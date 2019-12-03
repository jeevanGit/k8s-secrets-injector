// Package provides capabilities to retrieve secrets from Hashicorp Vault
//

package secretsinjector

import (
	"encoding/json"
	"fmt"
	"strings"
	"errors"
  "os"
  "path"
	log "github.com/sirupsen/logrus"

  hcvault "hc_vault_k8s"
	kv "hc_vault_kv"
  "utils"
)

const (
	hcVaultVarName         = "hashicorpvault"
)

// map of File Var and Secret path
type FileVarStruct struct {
  Secrets map[string]string
}
// map of Env Var and Secret path
type EnvVarStruct struct {
  Secrets map[string]string
}
// Secrets Injector struct
type HCVaultSecretsInjectorStruct struct {
  Vault               *hcvault.HCVault
  VaultClients        map[string]*kv.VaultClient
  VaultToken          string
	EnvVars 		        EnvVarStruct // Map of secrets pairs
  FileVars            map[string]FileVarStruct  // map of File name to Map of secrets pairs
}
//
func NewHashicorpVault() (*HCVaultSecretsInjectorStruct, error) {
  var err error
  v := &HCVaultSecretsInjectorStruct{}
  v.Vault, err = hcvault.NewFromEnvironment()
	if err != nil {
    s := fmt.Sprintf("error: %s ", err.Error() )
    return v, errors.New(s)
	}
	v.VaultToken, err = v.Vault.Authenticate()
	if err != nil {
      s := fmt.Sprintf("error: %s ", err.Error() )
			return v, errors.New(s)
	}
  log.Debugf("successfully authenticated to vault")
	log.Debugf("new token: %s", v.VaultToken)
  // set the token
  v.Vault.UseToken(v.VaultToken)

  // init VaultClient
  v.VaultClients = make(map[string]*kv.VaultClient)
  v.EnvVars = EnvVarStruct{}
  v.EnvVars.Secrets = make(map[string]string)

  // populate EnvVars.Secrets with actial values from teh env
  for _, pair := range os.Environ() {
    kv := strings.SplitN( pair , "=" , 2 )
    // check if var ends with "@hashicorpvault"
    if strings.HasSuffix( strings.ToLower(kv[1]), "@" + hcVaultVarName ) {
      v.EnvVars.Secrets[kv[0]] = strings.TrimSuffix( strings.ToLower(kv[1]), "@" + hcVaultVarName )
    }
  }

  // populate FileVars.Secrets map with actial values from the env
  // Example:
  //    - name: SECRET_INJECTOR_SECRET_NAME_secret_mysql
  //      value: secret/${APP_NAME}/${NAMESPACE}/mysql@hashicorpvault
  //    - name: SECRET_INJECTOR_MOUNT_PATH_secret_mysql
  //      value: /etc/secrets
  //
  //  v.FileVars should have:  map[ "/etc/secrets":{ "secret_mysql" : "secret/${APP_NAME}/${NAMESPACE}/mysql" } ]
  //
  v.FileVars = make(map[string]FileVarStruct)
  for _, pair := range os.Environ() {
    kv := strings.SplitN( pair , "=" , 2 )
    // check if var ends with "@hashicorpvault"
    if strings.HasPrefix( strings.ToLower(kv[0]), patternSecretName ) {             // SECRET_INJECTOR_SECRET_NAME_secret_mysql
      secVar := strings.TrimPrefix( strings.ToLower(kv[0]), patternSecretName )     // secret_mysql
        fv := FileVarStruct{                                                     // temp FileVarStruct with "secret_mysql" and secret
          Secrets: map[string]string{
            secVar: strings.ToLower(kv[1]),
          },
        }

        // look up corresponding Store System env var - it determines teh vault origin for the secret
        storeSystem := utils.GetEnvVariableByName( patternStoreSystem + secVar )
        if storeSystem == "" {   // finding SECRET_INJECTOR_MOUNT_PATH_secret_mysql
          s := fmt.Sprintf("Missing Store System env variable for secret %s: '%s' - can not determine Vault origin", secVar, patternStoreSystem + secVar )
          return v, errors.New(s)
        }else{

          // if match then secret comes from HC Vault
          if storeSystem == hcVaultVarName {
            // look up second corresponding env var with name "secret_injector_mount_path_" + secVar,
            //   to determine mount path
            mountPath := utils.GetEnvVariableByName( patternSecretMountPath + secVar )
            if mountPath == "" {   // finding SECRET_INJECTOR_MOUNT_PATH_
              s := fmt.Sprintf("Missing second set of env variables for secret %s: '%s'", secVar, patternSecretMountPath + secVar )
              return v, errors.New(s)
            }
            var newKey string
            if strings.HasSuffix(mountPath, "/") {
              newKey = mountPath + secVar
            }else{
              newKey = mountPath + "/" + secVar
            }
            v.FileVars[newKey] = fv       // create new map entry "file path + secret name": {"secret name", "secret path in vault"}
            log.Debugf("Adding new entry for File Variables map: %s", newKey)

          } // else secret from Az KVault
        }

    }
  }

  return v, nil
}
//
func (self *HCVaultSecretsInjectorStruct) Prep() error {
  //
  // Env Vars
  //
  secrets := make(map[string]string)
	// prep cycle
	for k, v := range self.EnvVars.Secrets {
		mount := strings.SplitN( v , "/" , 2 )[0]
		// ensure kv.Client for mount
		if _, ok := self.VaultClients[mount]; !ok {
			secretClient, err := kv.NewVClient( self.Vault.Client(), mount+"/" )
			if err != nil {
        return err
			}
			self.VaultClients[mount] = secretClient
		}
		// v is a secret
		if !strings.HasSuffix(v, "/") {
			secrets[k] = v
			continue
		}
		// v is a path -> get all secrets from v
		keys, err := self.VaultClients[mount].List(v)
		if err != nil {
      return err
		}
		if keys == nil {
			continue
		}
		// TODO: check for secret == nil
		for _, k := range keys {
			secrets[k] = path.Join(v, k)
		}
	}
	self.EnvVars.Secrets = secrets

  return nil
}
// 
func (self *HCVaultSecretsInjectorStruct) PopulateSecrets() error {

  if err := self.Prep(); err != nil  {
		return err
	}

  for k, v := range self.EnvVars.Secrets {
		// get secret from vault
		s, err := self.VaultClients[strings.SplitN(v, "/", 2)[0]].Read(v)
		if err != nil {
			return err
		}
		if s == nil {
			log.Warningf("Secret '%s' not found in the vault.", v)
			continue
		}else{
			log.Debugf( "secret: %s has value: %s", v, s )
      if j, err := json.Marshal(s); err == nil {
        self.EnvVars.Secrets[k] = string( j )
      }
		}
		// convert data
    /*
		data := make(map[string][]byte)
		for k, v := range s {
			data[k] = []byte(v.(string))
			fmt.Printf("secret: %s", []byte(v.(string)))
		}
    */
	}

  for f, s := range self.FileVars {
    for k, v := range s.Secrets {
      log.Println("Attempt to read '", v, "' from vault")
  		s, err := self.VaultClients[strings.SplitN(v, "/", 2)[0]].Read(v)
  		if err != nil {
  			return err
  		}
  		if s == nil {
  			log.Warning("Secret", v, "not found in the vault.")
  			continue
  		}else{
  			log.Debugf( "secret: %s has value: %s", v, s )
        if j, err := json.Marshal(s); err == nil {
          self.FileVars[f].Secrets[k] = string( j )
        }
  		}
    }

  }

  return nil
}
