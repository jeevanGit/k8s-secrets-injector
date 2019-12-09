// Package utils containes utility type of functions
package utils

import (
	"github.com/Azure/go-autorest/autorest"
	"net/http"
	"net/http/httputil"
	"path"
  	"strings"
	"os"
	log "github.com/sirupsen/logrus"
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

// Utility function designed to extract substring between 2 strings
func StringBetween(value string, a string, b string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, a)
	if posFirst == -1 {
		return ""
	}
	posLast := strings.Index(value, b)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(a)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}

// Function retrieves environment variable value based on its name
func GetEnvVariableByName(variableName string) string {
	environ := os.Environ()
	for _, pair := range environ {
		if strings.Contains(pair, "=") {
			if split := strings.Split(pair, "="); strings.EqualFold( strings.ToLower(strings.TrimSpace(variableName)), strings.ToLower(strings.TrimSpace(split[0])) ) {
					return split[1]
				}
		}
	}
	return ""
}


//
// debug function
//
func logRequest() autorest.PrepareDecorator {
	return func(p autorest.Preparer) autorest.Preparer {
		return autorest.PreparerFunc(func(r *http.Request) (*http.Request, error) {
			r, err := p.Prepare(r)
			if err != nil {
				log.Debugln(err)
			}
			dump, _ := httputil.DumpRequestOut(r, true)
			log.Debugln(string(dump))
			return r, err
		})
	}
}

//
// debug function
//
func logResponse() autorest.RespondDecorator {
	return func(p autorest.Responder) autorest.Responder {
		return autorest.ResponderFunc(func(r *http.Response) error {
			err := p.Respond(r)
			if err != nil {
				log.Debugln(err)
			}
			dump, _ := httputil.DumpResponse(r, true)
			log.Debugln(string(dump))
			return err
		})
	}
}

