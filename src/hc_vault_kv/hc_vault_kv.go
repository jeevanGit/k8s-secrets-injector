// Package kv provides version agnostic methods for read, write and list of secrets from @hashicorp Vault's KV secret engines

package hc_vault_kv

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Constants
const (
	ReadPrefix  = "data"
	WritePrefix = ReadPrefix
	ListPrefix  = "metadata"
)

// Client represents a KV client
type Client struct {
	client  *api.Client
	Version int
}

// FixPath inserts the API prefix for v1 style path
// secret/foo      -> secret/data/foo
// secret/data/foo -> secret/data/foo
// presumes a valid path
func FixPath(p, prefix string) string {
	pp := strings.Split(p, "/")
	if pp[1] == prefix {
		return p // already v2 style path
	}
	return path.Join(append(pp[:1], append([]string{prefix}, pp[1:]...)...)...)
}
