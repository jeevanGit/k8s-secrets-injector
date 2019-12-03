// Package provides capabilities to retrieve secrets from AZ KeyVault
//
package secretsinjector

import (
	"encoding/json"
	"fmt"
	"strings"
	"errors"
	"os"
	log "github.com/sirupsen/logrus"
	_ "github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	"utils"
)
const (
	azureVaultVarName      = "AzureKeyVault"
	patternSecretName      = "secret_injector_secret_name_"
	patternSecretMountPath = "secret_injector_mount_path_"
	patternStoreSystem		 = "secret_store_system_"
)
//------------------------------------------------------------------------------
// Secret-Vault Env Variable struct
type SecretVaultEnvVariableStruct struct {
	SecName    	string `json: "SecName,omitempty"`
	VaultName  	string	`json: "VaultName,omitempty"` // reserved for future development
	EnvVarName 	string `json: "EnvVarName,omitempty"`
	Secret		string `json: "Secret,omitempty"`
	IsValid    	bool `json: "IsValid,omitempty"`
}
// Secret-Vault File struct
type SecretVaultFileVariableStruct struct {
	SecName    	string `json: "SecName,omitempty"`
	VaultName  	string `json: "VaultName,omitempty"` // reserved for future development
	FileMntPath string `json: "FileMntPath,omitempty"`
	Secret 		string `json: "Secret,omitempty"`
	IsValid    	bool `json: "IsValid,omitempty"`
}
// Secrets Injector struct
type AzureKVSecretsInjectorStruct struct {
	VaultNameDefault   	string `json: "VaultNameDefault,omitempty"`
	//VaultClient       	keyvault.BaseClient `json:"-"`
	EnvVarSecrets 		[]SecretVaultEnvVariableStruct `json: "EnvVarSecrets,omitempty"`
	FileSecrets 		[]SecretVaultFileVariableStruct `json: "FileSecrets,omitempty"`
}

//------------------------------------------------------------------------------
func (self AzureKVSecretsInjectorStruct) MarshalToJson() (string, error) {
	jstr, err := json.Marshal( self )
	if err != nil {
		return "", err
	} else {
		return string( jstr ), nil
	}
}
//------------------------------------------------------------------------------
func NewAzureKVault() (*AzureKVSecretsInjectorStruct) {
	self := &AzureKVSecretsInjectorStruct{}
	self.EnvVarSecrets = make([]SecretVaultEnvVariableStruct, 0)
	self.FileSecrets = make([]SecretVaultFileVariableStruct, 0)
	for _, pairEnvVar := range os.Environ() {
		self.setDefaultVault(pairEnvVar)
		self.initEnvVars(pairEnvVar)
		self.initFileVars(pairEnvVar)
	}
	return self
}
//------------------------------------------------------------------------------
func (self *AzureKVSecretsInjectorStruct) setDefaultVault (pair string) {

	envVarSplit := strings.Split(pair, "=")
	if envVarSplit[0] != "" && strings.TrimSpace( strings.ToLower(envVarSplit[0]) ) == strings.ToLower(azureVaultVarName) {
		self.VaultNameDefault = envVarSplit[1]
	}
}

//------------------------------------------------------------------------------
// Section deals with Env Variables Secrets
func (self *AzureKVSecretsInjectorStruct) initEnvVars(pair string) error {
	//v := &SecretVaultEnvVariableStruct{}
	v, err := (&SecretVaultEnvVariableStruct{}).parse(pair)
	if err == nil { self.addEnvVar(v) }
	return nil
}

func (self *SecretVaultEnvVariableStruct) parse(item string) (*SecretVaultEnvVariableStruct, error) {

	envVarSplit := strings.Split(item, "=")
	secNameSplit := strings.Split(envVarSplit[1], "@")

	if strings.HasSuffix( strings.ToLower(envVarSplit[1]), strings.ToLower("@" + azureVaultVarName) ) {
		return &SecretVaultEnvVariableStruct{
			SecName: secNameSplit[0],
			VaultName: secNameSplit[1],
			EnvVarName: envVarSplit[0],
			Secret: "",
			IsValid: false,
		}, nil
	}

	if len(secNameSplit) != 2 {
		return &SecretVaultEnvVariableStruct{}, errors.New("Does not match pattern")
	}else{
		return &SecretVaultEnvVariableStruct{
			SecName: secNameSplit[0],
			VaultName: secNameSplit[1],
			EnvVarName: envVarSplit[0],
			Secret: "",
			IsValid: false,
		}, nil
	}
	return &SecretVaultEnvVariableStruct{}, nil
}

func (self *AzureKVSecretsInjectorStruct) addEnvVar(item *SecretVaultEnvVariableStruct) []SecretVaultEnvVariableStruct {
	self.EnvVarSecrets = append(self.EnvVarSecrets, *item)
	return self.EnvVarSecrets
}

//------------------------------------------------------------------------------
// Section deals with reaching out to secrets store and populating secrets part of structs

// external function responsible for providing functionality of pulling secrets specific to the secrets store or vault
type getVaultSecretFunction func(vault, secName string) (string, error)

// populate the secrets based on the implementation of specific vault store (fn)
func (self AzureKVSecretsInjectorStruct)PopulateSecret(fn getVaultSecretFunction) error {

	for index, _ := range self.EnvVarSecrets {
		s, err := fn( self.VaultNameDefault, self.EnvVarSecrets[index].SecName )
		if err != nil {
			s := fmt.Sprintf("Could not get the secret %s, error: %s ", self.EnvVarSecrets[index].SecName , err.Error() )
			return errors.New(s)
		}
		self.EnvVarSecrets[index].Secret = s
	}
	for index, _ := range self.FileSecrets {
		s, err := fn( self.VaultNameDefault, self.FileSecrets[index].SecName )
		if err != nil {
			s := fmt.Sprintf("Could not get the secret %s, error: %s ", self.FileSecrets[index].SecName , err.Error() )
			return errors.New(s)
		}
		self.FileSecrets[index].Secret = s
	}
	return nil
}

//------------------------------------------------------------------------------
// Section deals with File based Secrets
func (self *AzureKVSecretsInjectorStruct) initFileVars(pair string) error {
	v, err := (&SecretVaultFileVariableStruct{}).parse(pair)
	if err == nil {
		self.addFileVar(v)
	}
	return nil
}

func (self *AzureKVSecretsInjectorStruct) addFileVar (item *SecretVaultFileVariableStruct) []SecretVaultFileVariableStruct {
	self.FileSecrets = append(self.FileSecrets, *item)
	return self.FileSecrets
}

func (self *SecretVaultFileVariableStruct) parse(item string) (*SecretVaultFileVariableStruct, error) {

	kv := strings.SplitN( item , "=" , 2 )
	if strings.HasPrefix( strings.ToLower(kv[0]), patternSecretName ) {             // SECRET_INJECTOR_SECRET_NAME_secret_mysql
		secVar := strings.TrimPrefix( strings.ToLower(kv[0]), patternSecretName )     // index e.g 1

		// look up corresponding Store System env var - it determines teh vault origin for the secret
		storeSystem := utils.GetEnvVariableByName( patternStoreSystem + secVar )
		if storeSystem == "" {   // finding SECRET_INJECTOR_MOUNT_PATH_secret_mysql
			s := fmt.Sprintf("Missing Store System env variable for secret %s: '%s' - can not determine Vault origin", secVar, patternStoreSystem + secVar )
			return nil, errors.New(s)
		}else{

			// if match then secret comes from AZ Vault
			if storeSystem == azureVaultVarName {
				// look up second corresponding env var with name "secret_injector_mount_path_" + secVar,
				//   to determine mount path
				mountPath := utils.GetEnvVariableByName( patternSecretMountPath + secVar )
				if mountPath == "" {   // finding SECRET_INJECTOR_MOUNT_PATH_
					s := fmt.Sprintf("Missing second set of env variables for secret %s: '%s'", secVar, patternSecretMountPath + secVar )
					return nil, errors.New(s)
				}
				var newKey string
				if strings.HasSuffix(mountPath, "/") {
					newKey = mountPath + secVar
				}else{
					newKey = mountPath + "/" + secVar
				}
				log.Debugf("Adding new entry for File Variables map: %s", newKey)
				return &SecretVaultFileVariableStruct{
					SecName: strings.ToLower(kv[1]),
					VaultName: "",
					FileMntPath: newKey,
					Secret: "",
					IsValid: false,
				}, nil
			} // else secret from HC Vault
		}

	}
/*
	envVarSplit := strings.Split(item, "=") ; envSecName := envVarSplit[1]
	// matching to pattern
	if envVarSplit[0] != "" && strings.Contains(strings.TrimSpace(strings.ToLower(envVarSplit[0])) , strings.ToLower(patternSecretName)) {
		envSecSubName := utils.StringBetween( strings.ToLower(item), strings.ToLower( patternSecretName ), "=" )
		mntPath := utils.GetEnvVariableByName( strings.ToLower( patternSecretMountPath + envSecSubName ) )
		// populate SecretVaultFileVariableStruct
		return SecretVaultFileVariableStruct{
			SecName: envSecName,
			VaultName: "",
			FileMntPath: mntPath,
			Secret: "",
			IsValid: false,
		}, nil
	}
*/
	return nil, errors.New( fmt.Sprintf("Could not parse variable: %s ",item ) )
}
