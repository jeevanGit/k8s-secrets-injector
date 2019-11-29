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
