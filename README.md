# Kubernetes Secrets Injector

Repo hosts Kubernetes Secrets Injector init-container to retrieve secrets/keys from Hashicorp Vault and populate them in form of environment variables as well as secrets files for your application/container.


## Overview

This project offer the component for handling Hashicorp Vault Secrets in Kubernetes:

* Hashicorp Vault Vault Secrets Injector

The **Hashicorp Vault Vault Secrets Injector** (Secrets Injector for short) is a Kubernetes Mutating Webhook that transparently injects Hashicorp Vault secrets as environment variables into programs running in containers, without touching disk or in any other way expose the actual secret content outside the program.

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

## How it works

The Secrets Injector will start processing containers containing one or more environment placeholders like below:

```
env:
- name: vault_addr
  value: <name of HashicorpVault>
- name: <name of environment variable>
  value: <name of AzureKeyVaultSecret>@azurekeyvault

...
```

It will start by injecting a init-container into the Pod. This init-container copies over the `secret-injector` executable to a share volume between the init-container and the original container. It then changes either the CMD or ENTRYPOINT, depending on which was used by the original container, to use the `secret-injector` executable instead, and pass on the "old" command as parameters to this new executable. The init-container will then complete and the original container will start.

When the original container starts it will execute the `secret-injector` command which will download any Hashicorp Vault secrets, identified by the environment placeholders above. The remaining step is for `secret-injector` to execute the original command and params, pass on the updated environment variables with real secret values. This way all secrets gets injected transparently in-memory during container startup, and not reveal any secret content to the container spec, disk or logs.


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
