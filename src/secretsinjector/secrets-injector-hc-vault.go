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
  EnvVars 		        EnvVarStruct // Map of secrets pairs for environment variables
  // One file may have multiple secrets
  FileVars            map[string]FileVarStruct  // map of File name to Map of secret pairs (secret name - actual secret)
  //Vars  map[string]SecretStruct // map of secret name to struct SecretStruct
}

// Create new HC vault client and populate the environment in it
func NewHashicorpVault() (*HCVaultSecretsInjectorStruct, error) {
  var err error
  v := &HCVaultSecretsInjectorStruct{}
  v.Vault, err = hcvault.NewFromEnvironment()
	if err != nil {
    return v, errors.New( fmt.Sprintf("error: %s ", err.Error() ) )
	}
	v.VaultToken, err = v.Vault.Authenticate()
	if err != nil {
			return v, errors.New( fmt.Sprintf("error: %s ", err.Error() ) )
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
  for _, pair := range os.Environ() { // go through env vars one by one
    kv := strings.SplitN( pair , "=" , 2 )  // and try to identify the patters
    if strings.HasPrefix( strings.ToLower(kv[0]), patternSecretName ) {             // see if var name matches SECRET_INJECTOR_SECRET_NAME_<something>
      secVar := strings.TrimPrefix( strings.ToLower(kv[0]), patternSecretName )     // <something>
        fv := FileVarStruct{                                                     // temp FileVarStruct with <something> and secret
          Secrets: map[string]string{
            secVar: strings.ToLower(kv[1]),
          },
        }

        // look up corresponding Store System env var - it determines teh vault origin for the secret
        storeSystem := utils.GetEnvVariableByName( patternStoreSystem + secVar ) // see if var name matches SECRET_STORE_SYSTEM_<something>
        if storeSystem == "" {

          return v, errors.New( fmt.Sprintf("Missing Store System env variable for secret %s: '%s' - can not determine Vault origin. Skipping secret ''.", secVar, patternStoreSystem + secVar, secVar ) )

        }else{  // aha! baby is comming from HC!

          // if match then secret comes from HC Vault
          if storeSystem == hcVaultVarName {
            // look up second corresponding env var with name "secret_injector_mount_path_" + secVar,
            //   to determine mount path
            mountPath := utils.GetEnvVariableByName( patternSecretMountPath + secVar )
            if mountPath == "" {   // finding SECRET_INJECTOR_MOUNT_PATH_<something>
              s := fmt.Sprintf("Missing second set of env variables for secret %s: '%s'", secVar, patternSecretMountPath + secVar )
              return v, errors.New(s)
            }
            newKey := strings.TrimSuffix(mountPath, "/") + "/" + secVar
/*
            if strings.HasSuffix(mountPath, "/") {
              newKey = mountPath + secVar
            }else{
              newKey = mountPath + "/" + secVar
            } */
            v.FileVars[newKey] = fv       // create new map entry "file path + secret name": {"secret name", "secret path in vault"}
            log.Debugf("Adding new entry for File Variables map: %s", newKey)  // we've got new crew-mate!

          } // else secret from Az KVault
        }

    } // nope.. not mine..
  }

  return v, nil
}

// Prepare HC vault secrets environment and VaultClients
func (self *HCVaultSecretsInjectorStruct) Prep() error { // some cleaning and cleansing.. you know orthodox stuff..
  //
  // Env Vars
  //
  secrets := make(map[string]string)
	// prep cycle
	for k, v := range self.EnvVars.Secrets { // cleanning 'em one by one. get your towels monkeys!
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

// Pull secrets from the vault and populate self.EnvVars & self.FileVars
func (self *HCVaultSecretsInjectorStruct) PopulateSecrets() error {  //  at the end of the rainbow you Shall find..

  if err := self.Prep(); err != nil  {	return err  }

  for k, v := range self.EnvVars.Secrets { // environment secrets first - age before u know..
		// get secret from vault
		s, err := self.VaultClients[strings.SplitN(v, "/", 2)[0]].Read(v)
		if err != nil { return err }
		if s == nil {
			log.Warningf("Secret '%s' not found in the vault.", v)
			continue
		}else{
			log.Debugf( "secret: %s has value: %s", v, s )
      if j, err := json.Marshal(s); err == nil {
        self.EnvVars.Secrets[k] = string( j )
      }
		}

	}

  for f, s := range self.FileVars {
    for k, v := range s.Secrets {
      log.Debugf("Attempt to read '%s' from HC vault", v)
  		s, err := self.VaultClients[strings.SplitN(v, "/", 2)[0]].Read(v)
  		if err != nil { return err }
  		if s == nil {
  			log.Warningf("Secret '%s' not found in the vault.", v)
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
