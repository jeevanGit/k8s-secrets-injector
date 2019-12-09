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
}

// Create new HC vault client and populate the environment in it
func NewHashicorpVaultClient(ch *SecretChainStruct) (*HCVaultClientStruct, error) {

	var err error
  	v := &HCVaultClientStruct{}
	v.VaultClients = make(map[string]*kv.VaultClient) // init map of VaultClient's
	if ch == nil {
		v.Chain, err = NewSecretChain()		// let's spin up the secrets Chain and init it with the env..
	}else{
		v.Chain = ch
	}

  	// This is where we create new HC vault instance
  	v.Vault, err = hcvault.NewFromEnvironment()
	if err != nil {
    return v, errors.New( fmt.Sprintf("error: %s ", err.Error() ) )
	}
	// .. authentication part, based on env vars from prev step
	if v.VaultToken, err = v.Vault.Authenticate(); err != nil {
			return v, errors.New( fmt.Sprintf("error: %s ", err.Error() ) )
	}
	// set the token
	v.Vault.UseToken(v.VaultToken)
  	log.Infof("successfully authenticated to vault with new token: %s", v.VaultToken)

  	// do some prep warm-ups
	if err = v.Prep(); err != nil {
		return nil, err // ops.. Huston, we have problem..
	}

	// this is main part
	for idx, _ := range v.Chain.Secrets { // loop through all the secrets we fished out from the env.
		if v.Chain.Secrets[idx].Origin == hcVaultVarName { // filter out everything but Hashicrp origins
			log.Debugf("Chain secrets with the index of %d looks like: %v", idx, v.Chain.Secrets[idx])
			// Huston, we have Take Off!
			// here is where we're doing some damage and pulling secrets
			m := v.Chain.Secrets[idx].VaultPath + v.Chain.Secrets[idx].Name
			mount := strings.SplitN( m, "/", 2)[0]
			s, err := v.VaultClients[mount].Read( m )
			if err != nil {
				return v, err
			}
			if s == nil {
				log.Warningf("Secret '%s' not found in the vault.", v)
				continue // moving on to the next secret in chain
			}else{ // secret is found and its good
				log.Debugf( "secret: %s has value: %s", v.Chain.Secrets[idx].Name, s )
				if j, err := json.Marshal(s); err == nil {
					v.Chain.Secrets[idx].Secret = string( j )
				}
			}
		}
	}
	return v, nil
}

// Prepare HC vault secrets environment and VaultClients
func (self *HCVaultClientStruct) Prep() error { // some cleaning and cleansing.. you know orthodox stuff..

	secrets := make(map[string]string)
	// prep cycle
	for idx, _ := range self.Chain.Secrets { // preparing vault clients one by one.
		if self.Chain.Secrets[idx].Origin == hcVaultVarName {
			//k := self.Chain.Secrets[idx].Name
			//v := self.Chain.Secrets[idx].VaultPath

			mount := strings.SplitN( self.Chain.Secrets[idx].VaultPath + self.Chain.Secrets[idx].Name , "/" , 2 )[0]

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
			if !strings.HasSuffix( self.Chain.Secrets[idx].VaultPath, "/" ) {
				secrets[self.Chain.Secrets[idx].Name] = self.Chain.Secrets[idx].VaultPath
				self.Chain.Secrets[idx].Secret = self.Chain.Secrets[idx].VaultPath
				continue
			}
			// v is a path -> get all secrets from v
			keys, err := self.VaultClients[mount].List( self.Chain.Secrets[idx].VaultPath )
			if err != nil {
				return err
			}
			if keys == nil {
				continue	// moving on to the next
			}
			// TODO: check for secret == nil
			for _, key := range keys {
				self.Chain.Secrets[idx].Secret = path.Join(self.Chain.Secrets[idx].VaultPath, key)
			}
		}
		//self.EnvVars.Secrets = secrets
	}

	return nil
}
