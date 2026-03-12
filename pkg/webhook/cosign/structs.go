package cosign

import (
	"context"
	"log/slog"

	"github.com/betorvs/dvorah/pkg/config"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Verifier struct {
	Config    *config.DvorahConfig
	Providers map[string]RegistryClient
	Logger    *slog.Logger
}

type RegistryClient interface {
	GetRemoteOption(ctx context.Context) (remote.Option, error)
}
