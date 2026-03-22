# The Royal Jelly

## config.yaml

GCP and keyless in policies with a global fallback option.

```yaml
globalMode: "deny"
globalProvider: "open-registry"
globalRegistries: 
  - "index.docker.io/betorvs"
globalPublicKey: |
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXBC/tG86ZkNXCMSODNnqWSv94czb
  QwYxG2qpcX90HRs3amRFfKMFcKWDNf3AmFmGRVySxvZYZ6ZR7WqYRTMm5Q==
  -----END PUBLIC KEY-----

policies:
  - name: "Google Artifact Registry - Production"
    pattern: "gcr.io/my-company/*"
    provider: "google"
    publicKey: |
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE... (GCP Specific Key)
      -----END PUBLIC KEY-----
    mode: "deny"
  - name: "keyless example"
    pattern: "ghcr.io/betorvs/dvorah:*"
    provider: "open-registry"
    registries:
      - "ghcr.io/betorvs/dvorah"
    mode: "deny"
    identity_regex: "^https://github.com/betorvs/dvorah/.github/workflows/release.yaml@refs/(heads/main|tags/v.*)$"
    issuer: "https://token.actions.githubusercontent.com"
```

## Generating docker-registry secret

```bash
kubectl create secret docker-registry -n dvorah dvorah-auth --dry-run=client --docker-server=https://index.docker.io/v1/ --docker-username=USERNAME --docker-password=PASSWORD -o yaml > dvorah-secret.yaml
```

Review it and apply
```bash
kubectl apply -n dvorah -f dvorah-secret.yaml
```


## Developing and testing it locally

### Prerequisites

```bash
# Install required tools
task dependencies-install-mac
```

### Deploying to Kubernetes

```bash
# 1. Create development environment
task dev-create

# 2. Deploy dvorah admission controller
task dvorah-deploy

# 3. Verify deployment
kubectl get pods -n dvorah
```

### Configuration

Important flags.

#### Key Configuration Options
- `-log-level`: Set logging level (`info` or `debug`)
- `-policy-config=config.yaml`: YAML config file for admission policy rules.
- `-mode`: [DEPRECATED] Set to `deny` (block unsigned images) or `audit` (log only)
- `-registry`: [DEPRECATED] Specify allowed ECR registries (comma-separated)
- `-public-key`: [DEPRECATED] Path to Cosign public key for signature verification

## Testing

```bash
# Test dvorah with cosign review
task dvorah-test-cosign
```

### Monitoring

```bash
# Check metrics
kubectl port-forward -n dvorah service/dvorah 8080:8080
curl http://localhost:8080/metrics
```
