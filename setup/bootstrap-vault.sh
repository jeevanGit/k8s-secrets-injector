#!/bin/bash

set -e

if [ $# -eq 0 ]; then
    echo "usage: ${0} profile"
    exit 1
fi
if [ ! -r $1 ]; then
    echo "ERROR: failed to read profile \"$1\""
    exit 1
fi

source $1

kubectl config use-context ${CLUSTER}

# setup rbac
envsubst < rbac.yaml | kubectl --namespace=${NAMESPACE} apply -f -

# Set VAULT_SA_NAME to the service account you created earlier
#export VAULT_SA_NAME=$(kubectl get sa vault-auth -o jsonpath="{.secrets[*]['name']}")
export VAULT_SA_NAME=$(kubectl get sa $SERVICEACCOUNT -o jsonpath="{.secrets[*].name}")
# Set SA_JWT_TOKEN value to the service account JWT used to access the TokenReview API
export SA_JWT_TOKEN=$(kubectl get secret $VAULT_SA_NAME -o jsonpath="{.data.token}" | base64 --decode; echo)
# Set SA_CA_CRT to the PEM encoded CA cert used to talk to Kubernetes API
export SA_CA_CRT=$(kubectl get secret $VAULT_SA_NAME -o jsonpath="{.data['ca\.crt']}" | base64 --decode; echo)
# Set K8S_HOST to minikube kubernetes API address
export K8S_HOST=$(kubectl config view --minify | grep server | cut -f 2- -d ":" | tr -d " ")

# Enable the Kubernetes auth method
vault auth enable kubernetes

# Configure Vault to talk to our Kubernetes host with the cluster's CA and the
# correct token reviewer JWT token
vault write auth/kubernetes/config \
  kubernetes_host="${K8S_HOST}" \
  kubernetes_ca_cert="${SA_CA_CRT}" \
  token_reviewer_jwt="${SA_JWT_TOKEN}"

# setup policies
vault policy write $VAULT_ROLE secrets-read-policy.hcl

# Create a role named, 'example' to map Kubernetes Service Account to
#  Vault policies and default token TTL
vault write auth/kubernetes/role/${VAULT_ROLE} bound_service_account_names=$SERVICEACCOUNT bound_service_account_namespaces=$NAMESPACE policies=$VAULT_ROLE ttl=240h

# test data for application ${APP_NAME} and namespace=${NAMESPACE}
vault kv put secret/${APP_NAME}/${NAMESPACE}/mysql username="appuser" password=$(echo 'suP3r$e(Ret#' | base64)

# Create a config map to store the vault address
kubectl create configmap vault \
      --namespace $NAMESPACE \
      --from-literal "vault_addr=$VAULT_ADDR"

# setup test deployments
envsubst < ../test/test-deployment.yaml| kubectl --namespace=${NAMESPACE} apply -f -





# eof
