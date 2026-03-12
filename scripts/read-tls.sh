#!/usr/bin/env bash

kubectl get secret -n dvorah dvorah-certificates -o jsonpath='{.data.tls\.crt}'