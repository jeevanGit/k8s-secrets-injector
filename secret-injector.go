//
//
package main

import (
	"errors"
	"fmt"
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"encoding/json"

	log "github.com/sirupsen/logrus"

	secinject "secretsinjector"
	"utils"
	"secretschain"
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
		log.Warningf("> environment variable %s is missing", key)
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

func main() {

	chain, err := secretschain.NewSecretChain() //
	if err != nil {
		log.Errorf("%s unable to generate secrets chain:  %v", logPrefix, err.Error())
	}

	// Azure KeyVault
	_, err = secinject.NewAzKVault(chain)
	if err != nil {
		log.Errorf("%s unable to generate secrets chain:  %v", logPrefix, err.Error())
	}

	// HC Vault
	hc, err := secinject.NewHashicorpVaultClient(chain)
	if err != nil {
		log.Errorf("%s unable to generate secrets chain:  %v", logPrefix, err.Error())
	}
	prettyJSON, _ := json.MarshalIndent(hc.Chain, "", "    ") ; fmt.Printf("%s\n", string(prettyJSON))

	// Now, set Env Vars with secrets and files
	// set secrets as  env vars
	for idx, _ := range chain.Secrets {
		if chain.Secrets[idx].EnvVar != "" {
			_ = os.Setenv(chain.Secrets[idx].EnvVar , chain.Secrets[idx].Secret)
		}
	}
	// generate secret files
	for idx, _ := range chain.Secrets { // iterate through all files we came know of
		if chain.Secrets[idx].FilePath != "" {
			err := generateSecretsFile(chain.Secrets[idx].FilePath + chain.Secrets[idx].Name, "", chain.Secrets[idx].Secret)
			if err != nil {
				log.Errorf("%s unable to generate secrets file:  %v", logPrefix, err.Error())
			}
		}
	}

	// ..and the final part to call the command
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
