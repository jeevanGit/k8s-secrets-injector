// Package utils containes utility type of functions


package utils

import (

	"path"
  "strings"

)

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
