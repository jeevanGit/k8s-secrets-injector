# Kubernetes Secrets Injector

Repo hosts Kubernetes Secrets Injector init-container to retrieve secrets/keys from Hashicorp Vault and populate them in form of environment variables as well as secrets files for your application/container.


## Overview

This project offer the component for handling Azure KeyVault and Hashicorp Vault Secrets in Kubernetes:

* Hashicorp Vault Vault Secrets Injector
* Azure KeyVault Vault Secrets Injector


The **Hashicorp Vault and Azure KeyVault Secrets Injector** (Secrets Injector for short) is a Kubernetes Mutating Webhook that transparently injects Hashicorp Vault secrets as environment variables into programs running in containers, without touching disk or in any other way expose the actual secret content outside the program.

The motivation behind this project was:

1. Avoid a direct program dependency on Vault for getting secrets, and adhere to the 12 Factor App principle for configuration (https://12factor.net/config)
2. Make it simple, secure and low risk to transfer Vault secrets into Kubernetes as native Kubernetes secrets.
3. Securely and transparently be able to inject Vault secrets as files and environment variables to applications, without having to use native Kubernetes secrets.

Use the Secrets Injector if:

* any of the [risks documented with Secrets in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) is not acceptable
* there are concerns about storing and exposing base64 encoded HC Vault secrets as Kubernetes `Secret` resources
* preventing Kubernetes users to gain access to HC Vault secret content is important
* the application running in the container support getting secrets as environment variables and as a files
* secret environment variable values should not be revealed to Kubernetes resources like Pod specs, stored on disks, visible in logs or exposed in any way other than in-memory for the application

## Retrieving secrets from Hashicorp Vault: How it works

The Secrets Injector will start processing containers containing one or more environment placeholders like below:

```
env:
- name: hashicorpvault
  value: <name of HashicorpVault>
- name: VAULT_PATH
  value: <root path to secrets listed below>

- name: <name of environment variable>
  value: <name of Secret>@hashicorpvault

- name: <name of another environment variable>
  value: <name of another Secret>@hashicorpvault

...
```

It will start by injecting a init-container into the Pod. This init-container copies over the `secret-injector` executable to a share volume between the init-container and the original container. It then changes either the CMD or ENTRYPOINT, depending on which was used by the original container, to use the `secret-injector` executable instead, and pass on the "old" command as parameters to this new executable. The init-container will then complete and the original container will start.

When the original container starts it will execute the `secret-injector` command which will download any Hashicorp Vault secrets, identified by the environment placeholders above. The remaining step is for `secret-injector` to execute the original command and params, pass on the updated environment variables with real secret values. This way all secrets gets injected transparently in-memory during container startup, and not reveal any secret content to the container spec, disk or logs.

### Kubernetes Auth Method

The recommanded way for the authentication is the Kubernetes auth method. There for you need a service account for the communication between Vault and the Secrets Injector. If you installed the operator via Helm this service account is created for you. The name of the created service account is secrets-operator. Use the following commands to set the environment variables for the activation of the Kubernetes auth method:

```
export SECRETS_OPERATOR_NAMESPACE=$(kubectl get sa secrets-operator -o jsonpath="{.metadata.namespace}")
export VAULT_SECRET_NAME=$(kubectl get sa secrets-operator -o jsonpath="{.secrets[*]['name']}")
export SA_JWT_TOKEN=$(kubectl get secret $VAULT_SECRET_NAME -o jsonpath="{.data.token}" | base64 --decode; echo)
export SA_CA_CRT=$(kubectl get secret $VAULT_SECRET_NAME -o jsonpath="{.data['ca\.crt']}" | base64 --decode; echo)
export K8S_HOST=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
```

```
# Verfify the environment variables
env | grep -E 'SECRETS_OPERATOR_NAMESPACE|VAULT_SECRET_NAME|SA_JWT_TOKEN|SA_CA_CRT|K8S_HOST'
```

Enable the Kubernetes auth method at the default path (auth/kubernetes) and finish the configuration of Vault:

```
vault auth enable kubernetes

# Tell Vault how to communicate with the Kubernetes cluster
vault write auth/kubernetes/config \
  token_reviewer_jwt="$SA_JWT_TOKEN" \
  kubernetes_host="$K8S_HOST" \
  kubernetes_ca_cert="$SA_CA_CRT"

# Create a role named, 'secrets-operator' to map Kubernetes Service Account to Vault policies and default token TTL
vault write auth/kubernetes/role/secrets-operator \
  bound_service_account_names="secrets-operator" \
  bound_service_account_namespaces="$SECRETS_OPERATOR_NAMESPACE" \
  policies=ecrets-operator \
  ttl=24h
```


## Retrieving secrets from Azure KeyVault: How it works



## Build Secrets Injector (use Azure environment)

Make sure you create `vars-az.mk` file and define `DOCKER_ORG`:

```
DOCKER_ORG?=<your acr name>.azurecr.io
```

Also, in `Makefile`, set variables `APP` and `RELEASE`

```
APP?=secret-injector
RELEASE?=v1alpha1
```

Then, login into the instance of ACR:

```
az acr login --name <your acr name>
```

To build the binaries run:

```
make build
```

This step compiles binary and places it under `./bin` directory.

Then, build image `secret-injector:v1alpha1` and push it to ACR instance:

```
export GOPATH=$GOPATH:$(pwd)
make push
```



## Credits

Credit goes to Banzai Cloud for coming up with the [original idea](https://banzaicloud.com/blog/inject-secrets-into-pods-vault/) of environment injection for their [bank-vaults](https://github.com/banzaicloud/bank-vaults) solution, which they use to inject Hashicorp Vault secrets into Pods.


---
