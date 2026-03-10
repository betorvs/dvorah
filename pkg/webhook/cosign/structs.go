package cosign

import (
	"context"
	"crypto"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	ProviderAWS          = "aws"
	ProviderGoogle       = "google"
	ProviderOpenRegistry = "open-registry"
)

// add expiration data of token
// add token itself also
// also the publickey,
type VerifierConfig struct {
	PublicKeyPath     string
	PublicKey         signature.Verifier
	HashAlgorithm     crypto.Hash
	Provider          string
	InCluster         bool
	Registries        []string
	TrustedRegistries []string
	RegistryClient    RegistryClient
	Logger            *slog.Logger
}

type Verifier struct {
	config VerifierConfig
}

type RegistryClient interface {
	GetRemoteOption(ctx context.Context) (remote.Option, error)
}
