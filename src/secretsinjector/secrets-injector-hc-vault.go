// Package provides capabilities to retrieve secrets from Hashicorp Vault
//

package secretsinjector

import (
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"path"
	"strings"

	hcvault "hc_vault_k8s"
	kv "hc_vault_kv"
)


// Secrets Injector struct
type HCVaultClientStruct struct {
  	Vault               *hcvault.HCVault
  	VaultClients        map[string]*kv.VaultClient
  	VaultToken          string

	Chain 				*SecretChainStruct // Chain of secrets populated from the env vars

	// this is is a deprecated part
  EnvVars 		        EnvVarStruct // Map of secrets pairs for environment variables
  // One file may have multiple secrets
  FileVars            map[string]FileVarStruct  // map of File name to Map of secret pairs (secret name - actual secret)
  //Vars  map[string]SecretStruct // map of secret name to struct SecretStruct
}

// Create new HC vault client and populate the environment in it
func NewHashicorpVaultClient() (*HCVaultClientStruct, error) {
  var err error
  v := &HCVaultClientStruct{}
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

	v.Chain, err = NewSecretChain()	// let's spin up the secrets chain from the env..

	// init VaultClient
  	v.VaultClients = make(map[string]*kv.VaultClient)
  	//v.EnvVars = EnvVarStruct{}
  	//v.EnvVars.Secrets = make(map[string]string)

  	err = v.Prep()
	if err != nil {
		return nil, err
	}

	for idx, _ := range v.Chain.Secrets { // loop through all the secrets we fished out from the env.
		if v.Chain.Secrets[idx].Origin == hcVaultVarName { // filter out everything but Hashicrp origins
			// Huston, we have Take Off!
			log.Debugf("The secrets struct: %s\n", v.Chain.Secrets[idx])

			// here is where we're doing some damage and pulling secrets
			m :=  v.Chain.Secrets[idx].Name
			mount := strings.SplitN( m, "/", 2)[0]
			log.Debugf("NewHashicorpVaultClient: mount: %s", mount)

			vc := v.VaultClients[mount]; log.Debugf("vc looks like this: %v", vc)
			s, err := vc.Read( m )
			if err != nil { return v, err }
			if s == nil {
				log.Warningf("Secret '%s' not found in the vault.", v)
				continue
			}else{
				log.Debugf( "secret: %s has value: %s", v, s )
				if j, err := json.Marshal(s); err == nil {
					v.Chain.Secrets[idx].Secret = string( j )
				}
			}

			//secretResp, err := getSecret( v.VaultClient, nameKV, v.Chain.Secrets[idx].Name )  // let's take this baby out for a walk..
			//if err != nil {
			//	log.Errorf("unable to generate secrets chain:  %v", err.Error()) // what the.
			//} else {
			//	v.Chain.Secrets[idx].Secret = *secretResp.Value  // miracles are real!
			//}
		}
	}


	return v, nil
}

// Prepare HC vault secrets environment and VaultClients
func (self *HCVaultClientStruct) Prep() error { // some cleaning and cleansing.. you know orthodox stuff..

	secrets := make(map[string]string)
	// prep cycle
	// for k, v := range self.EnvVars.Secrets {
	for idx, _ := range self.Chain.Secrets { // preparing vault clients one by one.
		if self.Chain.Secrets[idx].Origin == hcVaultVarName {
			k := self.Chain.Secrets[idx].Name
			v := self.Chain.Secrets[idx].VaultPath
			mount := strings.SplitN( k , "/" , 2 )[0]

			// ensure kv.Client for mount
			if _, ok := self.VaultClients[mount]; !ok {
				log.Debugf("Prep: init kv.NewVClient with mount point: %s", mount)
				secretClient, err := kv.NewVClient(self.Vault.Client(), mount+"/")
				if err != nil {
					return err
				}
				self.VaultClients[mount] = secretClient
			}
			// v is a secret
			if !strings.HasSuffix(v, "/") {
				secrets[k] = v
				self.Chain.Secrets[idx].Secret = v
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
		//self.EnvVars.Secrets = secrets
	}

	return nil
}


// Pull secrets from the vault and populate self.EnvVars & self.FileVars
func (self *HCVaultClientStruct) PopulateSecrets() error {  //  at the end of the rainbow you Shall find..

	//if err := self.Prep(); err != nil  {	return err  }

	//for k, v := range self.EnvVars.Secrets { // environment secrets first - age before u know..
	for idx, _ := range self.Chain.Secrets {
		k := self.Chain.Secrets[idx].Name
		v := self.Chain.Secrets[idx].VaultPath

		mount := strings.SplitN( v , "/" , 2 )[0]
		// ensure kv.Client for mount
		if _, ok := self.VaultClients[mount]; !ok {
			secretClient, err := kv.NewVClient( self.Vault.Client(), mount+"/" )
			if err != nil {
				return err
			}
			self.VaultClients[mount] = secretClient
		}

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
	return nil
}