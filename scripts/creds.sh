#!/usr/bin/env bash

CREDS=$(aws configure export-credentials)
namespace="dvorah"
# Replace with your ECR registry address
accountID="123456789123"
PASSWORD=$(aws ecr get-login-password --region us-east-1)

if [ -n "$CREDS" ]; then
  echo "Credentials found"
else
  echo "No credentials found"
  exit 1
fi

if [ -n "$PASSWORD" ]; then
  echo "Password found"
else 
  echo "No password found"
  exit 1
fi

kubectl create secret generic aws-credentials \
  --from-literal=AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId') \
  --from-literal=AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey') \
  --from-literal=AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.SessionToken') \
  -n $namespace \
  --dry-run=client -o yaml > secret-aws.yaml

kubectl create secret docker-registry pullsecret --docker-server=${accountID}.dkr.ecr.us-east-1.amazonaws.com \
    --docker-username=AWS \
    --docker-password=$PASSWORD \
    --docker-email=no-reply@firebolt.io \
    --namespace=${namespace} \
    --dry-run=client -o yaml > secret-docker.yaml

openssl req -newkey rsa:2048 -nodes -keyout tls.key -x509 -days 365 -out tls.crt -subj "/CN=dvorah.dvorah.svc" -addext "subjectAltName=DNS:dvorah.dvorah.svc,DNS:dvorah.dvorah.svc.local,DNS:dvorah.dvorah.svc.cluster.local"
kubectl create secret tls dvorah-certificates --cert=tls.crt --key=tls.key -n ${namespace} --dry-run=client -o yaml > secret-dvorah.yaml

kubectl apply -f secret-dvorah.yaml -n ${namespace}
kubectl apply -f secret-aws.yaml -n ${namespace}
kubectl apply -f secret-docker.yaml -n ${namespace}

cat <<EOF > values.kind.yaml
certificate:
  enabled: false

validatingWebhook:
  enabled: false

serviceMonitor:
  enabled: false

env:
  enabled: false
  kind:
    enabled: true

cosign:
  publicKey: |
      -----BEGIN PUBLIC KEY-----
      <add public key here>
      -----END PUBLIC KEY-----
EOF