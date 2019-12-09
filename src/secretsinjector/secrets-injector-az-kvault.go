// Package provides capabilities to retrieve secrets from AZ KeyVault
//
package secretsinjector

import (
	_ "encoding/json"
	"fmt"
	_ "strings"
	"errors"
	_ "os"
	"context"
	log "github.com/sirupsen/logrus"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"

	"utils"
	"secretschain"
)

// Az KeyVault struct
type AzKeyVaultClientStruct struct {
	Authorizer 			autorest.Authorizer
	VaultClient			keyvault.BaseClient
	Chain 				*secretschain.SecretChainStruct
}

// Create new HC vault client and populate the environment in it
func NewAzKVault(ch *secretschain.SecretChainStruct) (*AzKeyVaultClientStruct, error) {
	// i do wonder what is the name of the vault that i suppose to interact with, eh?
	nameKV := utils.GetEnvVariableByName( secretschain.AzureVaultVarName)
	if nameKV == "" { // dude! really?? check your vars..
		return nil, errors.New( fmt.Sprintf("Can't create new instancce of Azure KVault Client - the name of KVault can not be empty.") )
	}

	var err error
	v := &AzKeyVaultClientStruct{}
	if ch == nil {
		v.Chain, err = secretschain.NewSecretChain()	// let's spin up new secrets chain from the env..
	}else{
		v.Chain = ch
	}

	v.Authorizer, err = kvauth.NewAuthorizerFromEnvironment()  // knock knock.. who's there?
	if err != nil {
		// sod off mate - don't know yah
		return nil, errors.New( fmt.Sprintf("Can't initialize authorizer: %v", err.Error()) )
	}

	v.VaultClient = keyvault.New() // brand new! and shiny! keyVault Client! Hallelujah! Praise the Lord!
	v.VaultClient.Authorizer = v.Authorizer

	for idx, _ := range v.Chain.Secrets { // loop through all the secrets we fished out from the env.
		if v.Chain.Secrets[idx].Origin == secretschain.AzureVaultVarName { // filter out everything but Azure KeyVaul origins
			// Huston, we have Take Off!
			// here is where we're doing some damage and pulling secrets
			secretResp, err := getSecret( v.VaultClient, nameKV, v.Chain.Secrets[idx].Name )  // let's take this baby out for a walk..
			if err != nil {
				log.Errorf("unable to generate secrets chain:  %v", err.Error()) // what the.
			} else {
				v.Chain.Secrets[idx].Secret = *secretResp.Value  // miracles are real!
			}
		}
	}
	return v, nil
}

// Low level function to get the secret from Azure KeyVault based on its name
func getSecret(vaultClient keyvault.BaseClient, vaultname string, secname string) (result keyvault.SecretBundle, err error) {
	log.Debugf("Making a call to:  https://%s.vault.azure.net to retrieve value for KEY: %s\n", vaultname, secname)
	return vaultClient.GetSecret(context.Background(), "https://"+vaultname+".vault.azure.net", secname, "")
}

