package cosign

import (
	"context"
	"log/slog"

	"github.com/betorvs/dvorah/pkg/config"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	digestSHA       string = "sha256"
	trustedRootJSON string = "trusted_root.json"
)

type Verifier struct {
	Config    *config.DvorahConfig
	Providers map[string]RegistryClient
	Logger    *slog.Logger
}

type RegistryClient interface {
	GetRemoteOption(ctx context.Context) (remote.Option, error)
}

type DockerPayload struct {
	Critical Critical `json:"critical"`
	Optional any      `json:"optional"`
}
type Identity struct {
	DockerReference string `json:"docker-reference"`
}
type Image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}
type Critical struct {
	Identity Identity `json:"identity"`
	Image    Image    `json:"image"`
	Type     string   `json:"type"`
}

type NewBundlePayload struct {
	Payload     string       `json:"payload"`
	PayloadType string       `json:"payloadType"`
	Signatures  []Signatures `json:"signatures"`
}
type Signatures struct {
	Sig string `json:"sig"`
}

type NewBundleNestedPayload struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
}

type Subject struct {
	Digest      map[string]string `json:"digest"`
	Annotations map[string]string `json:"annotations"`
}
