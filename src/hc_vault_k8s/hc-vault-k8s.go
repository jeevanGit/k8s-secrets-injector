// Package k8s provides authentication with Vault on Kubernetes
//
// Authentication is done with the Kubernetes Auth Method by Vault.
//

package hc_vault_k8s

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"utils"
)

// Constants
const (
	AuthMountPath           = "auth/kubernetes" // default vault auth mount path
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// VaultLogicalWriter interface for testing
type vaultLogicalWriter interface {
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}
var vaultLogical = func(c *api.Client) vaultLogicalWriter {
	return c.Logical()
}

// Vault represents the configuration to get a valid Vault token
type HCVault struct {
	Role                    string
	TokenPath               string
	ReAuth                  bool
	TTL                     int
	AuthMountPath           string
	ServiceAccountTokenPath string
	AllowFail               bool
	client                  *api.Client
}

// Client returns a Vault *api.Client
func (v *HCVault) Client() *api.Client {
	return v.client
}

// Authenticate with vault
func (v *HCVault) Authenticate() (string, error) {
	var empty string
	// read jwt of serviceaccount
	content, err := ioutil.ReadFile(v.ServiceAccountTokenPath)
	if err != nil {
		return empty, errors.Wrap(err, "failed to read jwt token")
	}
	jwt := string(bytes.TrimSpace(content))
	log.Debugf("using jwt to login: %s", jwt)
	log.Debugf("using Role to login: %s", v.Role)
	log.Debugf("using Address to login: %s", v.client.Address())

	// authenticate
	data := make(map[string]interface{})
	data["role"] = v.Role
	data["jwt"] = jwt

	c := vaultLogical(v.client)
	s, err := c.Write( path.Join( utils.FixAuthMountPath(v.AuthMountPath), "login" ), data )
	if err != nil {
		return empty, errors.Wrapf(err, "login failed with role from environment variable VAULT_ROLE: %q", v.Role)
	}else{
		log.Debugf("Successful login with role: %s", v.Role)
	}

	if len(s.Warnings) > 0 {
		return empty, fmt.Errorf("login failed with: %s", strings.Join(s.Warnings, " - "))
	}else{
		log.Debugf("No warnings.")
	}
	return s.Auth.ClientToken, nil
}

// NewFromEnvironment returns a initialized Vault type for authentication
func NewFromEnvironment() (*HCVault, error) {
	v := &HCVault{}
	v.Role = os.Getenv("VAULT_ROLE")
	v.TokenPath = os.Getenv("VAULT_TOKEN_PATH")
	if v.TokenPath == "" {
		return nil, fmt.Errorf("missing VAULT_TOKEN_PATH")
	}
	if s := os.Getenv("VAULT_REAUTH"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, errors.Wrap(err, "1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False are valid values for ALLOW_FAIL")
		}
		v.ReAuth = b
	}
	if s := os.Getenv("VAULT_TTL"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, errors.Wrapf(err, "%s is not a valid duration for VAULT_TTL", s)
		}
		v.TTL = int(d.Seconds())
	}
	v.AuthMountPath = utils.FixAuthMountPath(AuthMountPath) // use default
	if p := os.Getenv("VAULT_AUTH_MOUNT_PATH"); p != "" {
		v.AuthMountPath = utils.FixAuthMountPath(p) // if set, use value from environment
	}
	v.ServiceAccountTokenPath = os.Getenv("SERVICE_ACCOUNT_TOKEN_PATH")
	if v.ServiceAccountTokenPath == "" {
		v.ServiceAccountTokenPath = ServiceAccountTokenPath
	}
	if s := os.Getenv("ALLOW_FAIL"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, errors.Wrap(err, "1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False are valid values for ALLOW_FAIL")
		}
		v.AllowFail = b
	}
	// create vault client
	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return nil, errors.Wrap(err, "failed to read environment for vault")
	}
	var err error
	v.client, err = api.NewClient(vaultConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create vault client")
	}
	return v, nil
}


// StoreToken in VaultTokenPath
func (v *HCVault) StoreToken(token string) error {
	if err := ioutil.WriteFile(v.TokenPath, []byte(token), 0644); err != nil {
		return errors.Wrap(err, "failed to store token")
	}
	return nil
}

// LoadToken from VaultTokenPath
func (v *HCVault) LoadToken() (string, error) {
	content, err := ioutil.ReadFile(v.TokenPath)
	if err != nil {
		return "", errors.Wrap(err, "failed to load token")
	}
	if len(content) == 0 {
		return "", fmt.Errorf("found empty token")
	}
	return string(content), nil
}

// UseToken directly for requests with Vault
func (v *HCVault) UseToken(token string) {
	v.client.SetToken(token)
}

// GetToken tries to load the vault token from VaultTokenPath
// if token is not available, invalid or not renewable
// and VaultReAuth is true, try to re-authenticate
func (v *HCVault) GetToken() (string, error) {
	var empty string
	token, err := v.LoadToken()
	if err != nil {
		if v.ReAuth {
			return v.Authenticate()
		}
		return empty, errors.Wrapf(err, "failed to load token form: %s", v.TokenPath)
	}
	v.client.SetToken(token)
	if _, err = v.client.Auth().Token().RenewSelf(v.TTL); err != nil {
		if v.ReAuth {
			return v.Authenticate()
		}
		return empty, errors.Wrap(err, "failed to renew token")
	}
	return token, nil
}

// NewRenewer returns a *api.Renewer to renew the vault token regularly
func (v *HCVault) NewRenewer(token string) (*api.Renewer, error) {
	v.client.SetToken(token)
	// renew the token to get a secret usable for renewer
	secret, err := v.client.Auth().Token().RenewSelf(v.TTL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to renew-self token")
	}
	renewer, err := v.client.NewRenewer(&api.RenewerInput{Secret: secret})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token renewer")
	}
	return renewer, nil
}
