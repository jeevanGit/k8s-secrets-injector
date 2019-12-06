// Module hosts common components used across the package
//

package secretsinjector

import (
	"fmt"
	"strings"
	"errors"
  "os"
  _ "path"
	log "github.com/sirupsen/logrus"

  "utils"
)

var vaultOrigins          = [...]string {"hashicorpvault", "AzureKeyVault"}

const (

	  hcVaultVarName         = "hashicorpvault"
  	azureVaultVarName      = "AzureKeyVault"
  	patternSecretName      = "secret_injector_secret_name_"
  	patternSecretMountPath = "secret_injector_mount_path_"
  	patternStoreSystem		 = "secret_store_system_"
    vaultPathConst         = "VAULT_PATH"
)
// describes the structure of any Secret (vault-agnostic)
type SecretStruct struct {
  Name          string // actual secret's name
  Secret        string // actual secret value
  Path          string // secret's path within the vault
  Encoding      string // method of encoding secret value
  Origin        string // type of the vault
  EnvVar        string // if set secret needs to be populated as Env Var
  File          string // if set secret needs to be populated as File
}

// struct describes the chain of secrets
type SecretChainStruct struct {
  Secrets map[string]SecretStruct
}

//
func NewSecretChain() (*SecretChainStruct, error){
  scs := &SecretChainStruct{}
  scs.Secrets = make(map[string]SecretStruct)
  if err := scs.init(); err != nil {  // Histon - we have a problem
    return scs, errors.New( fmt.Sprintf("error: %s ", err.Error() ) )
  }
  return scs, nil
}
//
func (self *SecretChainStruct) init() error {

  for _, pair := range os.Environ() { // go through env vars one by one
    kv := strings.SplitN( pair , "=" , 2 )  // and try to identify the patters
    if kv[0] != "" && kv[1] != "" {
      s, err := self.parse(kv[0], kv[1])
      if err == nil { self.add(*s) }
    }
   }
  return nil
}
// function to parse env variable into SecretStruct
//  assuming the pattern already detected
func (self *SecretChainStruct) parse(key, val string) (*SecretStruct, error) {
  v := &SecretStruct{}

  // check if var ends with "@<something>". Use vaultOrigins as list of all possible "something"s
  if strings.Contains ( strings.ToLower(val), "@" ){  // env vars secrets..
    for _, item := range vaultOrigins {
      if strings.HasSuffix( strings.ToLower(val), "@" + item ) { // this is env variable secret
        log.Debugf("--> parsing %s - %s , and it matches with %s", key, val, "@" + item)
        v.Name = strings.TrimSuffix( strings.ToLower(val), "@" + item )
        v.Origin = item
        v.EnvVar = key
      }
    }
  }else{  // now.. file secrets..:) here come the bride..

    if strings.HasPrefix( key, patternSecretName ) {             // see if var name matches SECRET_INJECTOR_SECRET_NAME_<index>
      secIndex := strings.TrimPrefix( key, patternSecretName )   // <index>

      // look up corresponding Store System env var - it determines the origin vault for the secret
      v.Origin = utils.GetEnvVariableByName( patternStoreSystem + secIndex ) // see if var name matches SECRET_STORE_SYSTEM_<index>
      if v.Origin == "" {
        return v, errors.New( fmt.Sprintf("Missing Store System env variable for secret %s: '%s' - can not determine Vault origin. Skipping secret '%s'.", val, patternStoreSystem + secIndex, secIndex ) )

      }else{  // aha! lets capture where this baby is coming from..

        // look up second corresponding env var with name "secret_injector_mount_path_" + secIndex,
        //   to determine mount path for secret file
        v.Path = strings.TrimSuffix( utils.GetEnvVariableByName( patternSecretMountPath + v.Name ) , "/") + "/"
        if v.Path == "" {   // finding SECRET_INJECTOR_MOUNT_PATH_<index>
          return v, errors.New( fmt.Sprintf("Missing second set of env variables for secret %s: '%s'", v.Name, patternSecretMountPath + v.Name ) )
        }
        // Now, its Xmas time! Lets construct the name of the secret within the vault..
        // there are 2 parts to it
        // 1 - lookup VAULT_PATH to find path within the vault (it could be empty and thats cool..  totaly cool..)
        v.Name = utils.GetEnvVariableByName( vaultPathConst )   // Here's a little TODO: design how distinguish vault path across diff vaults (just in case of many vaults and potentialy diff types)
        // 2 - adding to path actual name of secret within vault
        v.Name = v.Name + val
      }

    }

  }
  return v, nil
}

// adding new secret into the chain with the key as "name-of-the-secret:origin-vault"
//  secrets may have the same names across the vaults
func (self *SecretChainStruct) add(s SecretStruct) {
  self.Secrets[s.Name + ":" + s.Origin] = s
}
