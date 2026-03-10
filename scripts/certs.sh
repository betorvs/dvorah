#!/usr/bin/env bash

CN=dvorah
NS=dvorah
key=tls.key
cert=tls.crt

if [ ! -f "$key" ]; then
    if [ ! -f "$cert" ]; then
        openssl req -newkey rsa:2048 -nodes -keyout $key -x509 -days 365 -out $cert -subj "/CN=$CN.$NS.svc" -addext "subjectAltName=DNS:$CN.$NS.svc,DNS:$CN.$NS.svc.local,DNS:$CN.$NS.svc.cluster.local"
    fi
fi
if [ ! -f "secret-adm.yaml" ]; then
    kubectl create secret tls dvorah-certificates --cert=$cert --key=$key -n ${NS} --dry-run=client -o yaml > dvorah-certificates.yaml
fi