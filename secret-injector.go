//
//
package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"
	log "github.com/sirupsen/logrus"

	secinject "secretsinjector"
	"utils"
)
const (
		logPrefix = "secret-injector:"
)
var (
	Secrets map[string]string // key = environment secret name, value = vault secret name
)

//------------------------------------------------------------------------------
//
// initialize/set environment
//
func setIfNotSet(key, default_val string){
	if v := utils.GetEnvVariableByName(key); v == "" {
		log.Debugf("Env Var %s is missing", key)
		if v = viper.GetString(key); v == "" {
			os.Setenv(key, default_val)
		}else{
			os.Setenv(key, v)
		}
	}
}
// HC Vault init
func initHCVault(){
	viper.SetConfigName("config"); viper.AddConfigPath(".") ; viper.AddConfigPath("/"); viper.SetConfigType("json")
	if err := viper.ReadInConfig(); err != nil {
		log.Warning( fmt.Errorf("Fatal error config file: %s \n", err) )
	}
	setIfNotSet("VAULT_TOKEN_PATH", "/home/vault/.vault-token")
	setIfNotSet("VAULT_REAUTH", "true")
	setIfNotSet("VAULT_AUTH_MOUNT_PATH", "kubernetes")
	setIfNotSet("SERVICE_ACCOUNT_TOKEN_PATH", "kubernetes")
	setIfNotSet("SERVICE_ACCOUNT_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	setIfNotSet("VAULT_SKIP_VERIFY", "true")
	viper.AutomaticEnv()
}
// Injector init
func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	// setting debug mode
	debug := utils.GetEnvVariableByName("debug")
	if strings.EqualFold(debug, "true") { log.SetLevel(log.DebugLevel)	} else {	log.SetLevel(log.InfoLevel)	}
	log.SetFormatter(&log.TextFormatter{})

	// custom auth
	_ = os.Setenv("CUSTOM_AUTH_INJECT", "true")
	// init settings for HC Vault
	initHCVault()
	if utils.GetEnvVariableByName("VAULT_ROLE") == "" {
		log.Warningf("%s unable to read environment variable 'VAULT_ROLE'", logPrefix)
	}
	if utils.GetEnvVariableByName("SERVICEACCOUNT") == "" {
		log.Warningf("%s unable to read environment variable 'SERVICEACCOUNT'", logPrefix)
	}
	if utils.GetEnvVariableByName("VAULT_PATH") == "" {
		log.Warningf("%s unable to read environment variable 'VAULT_PATH'", logPrefix)
	}
	if hc := utils.GetEnvVariableByName("hashicorpvault") ; hc != "" {
		_ = os.Setenv("VAULT_ADDR", hc)
		log.Debugf("%s setting VAULT_ADDR to %s", logPrefix, hc)
	}else{
		log.Warningf("%s unable to read environment variable 'hashicorpvault'", logPrefix)
	}

}

//
// main function
//
func main() {
	//
	// HC Vault secrets
	//

	// new instance of HC vault client
	vlt, err := secinject.NewHashicorpVault()
	if err != nil {
			log.Fatal(err)
	}
	if err = vlt.PopulateSecrets(); err != nil  { // alright, lets pull 'em, out of There! Push, push! Push! Oh, no.. thats pull, pull..
		log.Fatal(err)
	}
	//log.Debugf("Captured env vars:\n\t %v \n\n", vlt.EnvVars.Secrets)
	//log.Debugf("Captured file vars:\n\t %v \n\n", vlt.FileVars)

	// set secrets as  env vars
	for k, v := range vlt.EnvVars.Secrets {
		_ = os.Setenv(k, v)
	}
	// generate secret files
	for k, v := range vlt.FileVars { // itterate through all files we came know of
		for _, s := range v.Secrets {	// each file may or may not have many many secrets.. who know...

			err := generateSecretsFile( k, "", s )
			if err != nil {
				log.Errorf("%s unable to generate secrets file:  %v", logPrefix, err.Error())
			}
		}
	}

	//
	// Azure KeyVault secrets
	//

	// init
	sv := secinject.NewAzureKVault() // oh lala we have new AZ vault! Shiny!
	// populate secrets from vault
	err = sv.PopulateSecret( pullSecret ) // err..  okay, Doc, pull em!
	if err != nil {
		log.Errorf("%s errors while populating the secrets:  %v", logPrefix, err.Error())
	}

	// apply secrets to Pod env
	for index, _ := range sv.EnvVarSecrets {
		_ = os.Setenv(sv.EnvVarSecrets[index].EnvVarName, sv.EnvVarSecrets[index].Secret)
	}
	for index, _ := range sv.FileSecrets {
		err := generateSecretsFile( sv.FileSecrets[index].FileMntPath, "", sv.FileSecrets[index].Secret )
		if err != nil {
			log.Errorf("%s unable to generate secrets file:  %v", logPrefix, err.Error())
		}
	}

	if len(os.Args) == 1 {
		log.Fatalf("%s no command is given, currently vault-env can't determine the entrypoint (command), please specify it explicitly", logPrefix)
	} else {
		binary, err := exec.LookPath(os.Args[1])
		if err != nil {
			log.Errorf("%s binary not found: %s", logPrefix, os.Args[1])
		}
		log.Infof("starting process %s %v", binary, os.Args[1:])
		err = syscall.Exec(binary, os.Args[1:], os.Environ())
		if err != nil {
			log.Errorf("%s failed to exec process '%s': %s", logPrefix, binary, err.Error())
			return
		}
	}
	log.Debugf("%s azure key vault env injector successfully injected env variables with secrets", logPrefix)
	log.Debugf("%s shutting down azure key vault env injector", logPrefix)
}


func pullSecret (vault, secName string) (string, error) {
	authorizer, err := kvauth.NewAuthorizerFromEnvironment()
	if err != nil {
		s := fmt.Sprintf("Can't initialize authorizer: %v", err.Error())
		return "", errors.New(s)
	}
	bc := keyvault.New()
	bc.Authorizer = authorizer
	secretResp, err := getSecret(bc, vault, secName)
	if err != nil {
		s := fmt.Sprintf("%v", err.Error())
		return "", errors.New(s)
	} else {
		return *secretResp.Value, nil
	}
}
//
// Low level function to get the secret from the vault based on its name
//
func getSecret(vaultClient keyvault.BaseClient, vaultname string, secname string) (result keyvault.SecretBundle, err error) {
	log.Debugf("%s Making a call to:  https://%s.vault.azure.net to retrieve value for KEY: %s\n", logPrefix, vaultname, secname)
	return vaultClient.GetSecret(context.Background(), "https://"+vaultname+".vault.azure.net", secname, "")
}

//
// Function  creates secrets file, writes secret to it and makes file read-only
//
func generateSecretsFile(mntPath, secName, secret string) error {
	var secretsFile string
	if secName != "" {
		secretsFile = mntPath + "/" + secName
	}else{
		secretsFile = mntPath
	}
	_, err := os.Create(secretsFile)
	if err != nil {
		s := fmt.Sprintf("Error creating the file %s: %v", secretsFile, err.Error())
		return errors.New(s)
	} else {
		log.Debugf("Creating secret file: %s", secretsFile)
		_, err := os.Stat(secretsFile)
		if err != nil {
			if os.IsNotExist(err) {
				s := fmt.Sprintf("File %s does not exist.", secretsFile)
				return errors.New(s)
			}
		} else {
			// write secret to secrtets file
			log.Debugf("Populating secrets file: %s", secretsFile)
			err := ioutil.WriteFile(secretsFile, []byte(secret), 0666)
			if err != nil {
				s := fmt.Sprintf("Can't write to the file: %v", err.Error())
				return errors.New(s)
			}
		}
		//make file read-only
		log.Debugf("Making secrets file: %s read-only", secretsFile)
		err = os.Chmod(secretsFile, 0444)
		if err != nil {
			s := fmt.Sprintf("Can't file's permission mask: %v", err.Error())
			return errors.New(s)
		}

	}
	return nil
}

//
// debug function
//
func logRequest() autorest.PrepareDecorator {
	return func(p autorest.Preparer) autorest.Preparer {
		return autorest.PreparerFunc(func(r *http.Request) (*http.Request, error) {
			r, err := p.Prepare(r)
			if err != nil {
				log.Debugln(err)
			}
			dump, _ := httputil.DumpRequestOut(r, true)
			log.Debugln(string(dump))
			return r, err
		})
	}
}

//
// debug function
//
func logResponse() autorest.RespondDecorator {
	return func(p autorest.Responder) autorest.Responder {
		return autorest.ResponderFunc(func(r *http.Response) error {
			err := p.Respond(r)
			if err != nil {
				log.Debugln(err)
			}
			dump, _ := httputil.DumpResponse(r, true)
			log.Debugln(string(dump))
			return err
		})
	}
}
