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
)

// Constants
const (
	AuthMountPath           = "auth/kubernetes"
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// VaultLogicalWriter interface for testing
type vaultLogicalWriter interface {
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

// vaultLogical will be overwritten by tests
var vaultLogical = func(c *api.Client) vaultLogicalWriter {
	return c.Logical()
}

// Vault represents the configuration to get a valid Vault token
type Vault struct {
	Role                    string
	TokenPath               string
	ReAuth                  bool
	TTL                     int
	AuthMountPath           string
	ServiceAccountTokenPath string
	AllowFail               bool
	client                  *api.Client
}

// FixAuthMountPath add the auth prefix
// kubernetes      -> auth/kubernetes
// auth/kubernetes -> auth/kubernetes
// presumes a valid path
func FixAuthMountPath(p string) string {
	pp := strings.Split(strings.TrimLeft(p, "/"), "/")
	if pp[0] == "auth" {
		return path.Join(pp...) // already correct
	}
	return path.Join(append([]string{"auth"}, pp...)...)
}
