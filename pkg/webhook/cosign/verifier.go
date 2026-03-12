package cosign

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/betorvs/dvorah/pkg/config"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Return a new verifier
func NewVerifier(ctx context.Context, dvorahCfg *config.DvorahConfig, logger *slog.Logger) (*Verifier, error) {
	v := &Verifier{
		Config:    dvorahCfg,
		Logger:    logger,
		Providers: make(map[string]RegistryClient),
	}

	// Inicializa os braços (providers) injetando o config se necessário
	providers, err := newProviders(ctx, dvorahCfg, logger)
	if err != nil {
		return nil, err
	}
	v.Providers = providers

	return v, nil
}

func newProviders(ctx context.Context, c *config.DvorahConfig, logger *slog.Logger) (map[string]RegistryClient, error) {
	logger.Info("loading providers")
	providers := make(map[string]RegistryClient)

	loader := func(provider string, inCluster bool, registries []string) error {
		switch provider {
		case config.ProviderAWS:
			logger.Debug("loading aws provider")
			// AWS_ECR_REGION is used for the ECR client
			// it should match with the region of the ECR registry
			// our case it is us-east-1
			region, ok := os.LookupEnv("AWS_ECR_REGION")
			if !ok {
				region = "us-east-1"
			}
			ecrClient, err := NewECRClient(ctx, logger, region, inCluster, registries)
			if err != nil {
				return fmt.Errorf("failed to create ECR client: %w", err)
			}
			providers[config.ProviderAWS] = ecrClient
		case config.ProviderGoogle:
			logger.Debug("loading google provider")
			googleClient, err := NewGoogleClient(ctx, logger, inCluster)
			if err != nil {
				return fmt.Errorf("failed to create Google client: %w", err)
			}
			providers[config.ProviderGoogle] = googleClient
		case config.ProviderOpenRegistry:
			logger.Debug("loading open-registry provider")
			openRegistryClient, err := NewOpenRegistryClient(ctx, logger, inCluster, registries)
			if err != nil {
				return fmt.Errorf("failed to create Open Registry client: %w", err)
			}
			providers[config.ProviderOpenRegistry] = openRegistryClient
		}
		return nil
	}

	for _, v := range c.Policies {
		err := loader(v.Provider, v.InCluster, v.Registries)
		if err != nil {
			return nil, err
		}
	}
	if len(providers) == 0 {
		logger.Debug("no providers loaded, checking global")
		err := loader(c.GlobalProvider, c.InCluster, c.GetAllowedRegistries())
		if err != nil {
			return nil, err
		}
	}

	return providers, nil
}

func (v *Verifier) VerifySignature(image string) (bool, string, string, error) {

	ctx := context.Background()
	v.Logger.Debug("Starting signature verification for image", "image", image)

	// Parse the image reference
	imageRef, err := name.ParseReference(image)
	if err != nil {
		return false, "", v.Config.GlobalMode, fmt.Errorf("parsing reference: %w", err)
	}
	v.Logger.Debug("Parsed reference", "image", imageRef.String())

	name, provider, pubKey, mode := v.Config.GetPolicyForImage(imageRef.String(), v.Logger)
	v.Logger.Debug("return from GetPolicyForImage", "name", name, "provider", provider, "key", pubKey, "mode", mode)
	// remote options
	opts := []remote.Option{}

	switch provider {
	case config.ProviderAWS:
		awsOpts, err := v.Providers[config.ProviderAWS].GetRemoteOption(ctx)
		if err != nil {
			return false, "", mode, fmt.Errorf("failed to get ECR remote option: %w", err)
		}
		opts = append(opts, awsOpts)
	case config.ProviderGoogle:
		googleOpts, err := v.Providers[config.ProviderGoogle].GetRemoteOption(ctx)
		if err != nil {
			return false, "", mode, fmt.Errorf("failed to get Google remote option: %w", err)
		}
		opts = append(opts, googleOpts)
	case config.ProviderOpenRegistry:
		openRegistryOpts, err := v.Providers[config.ProviderOpenRegistry].GetRemoteOption(ctx)
		if err != nil {
			return false, "", mode, fmt.Errorf("failed to get Open Registry remote option: %w", err)
		}
		opts = append(opts, openRegistryOpts)
	default:
		return false, "", mode, fmt.Errorf("invalid provider: %s", provider)
	}

	publicKeyVerifier, err := v.getVerifier(pubKey)
	if err != nil {
		return false, "", mode, err
	}

	checkOpts := &cosign.CheckOpts{
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		IgnoreTlog:         true,
		Offline:            true,
		SigVerifier:        publicKeyVerifier,
		RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
	}

	// Cosign takes over the rest...
	v.Logger.Debug("Starting Cosign signature verification...")

	// pass digest directly to avoid a second remote lookup
	sigs, err := validSignatures(ctx, imageRef, checkOpts)
	if err != nil {
		v.Logger.Error("Failed to verify signature", "error", err, "image", imageRef.String(), "digest", imageRef.Identifier())
		return false, "", mode, fmt.Errorf("failed to verify signature: %w", err)
	}

	// resolve ref to a digest for logging purposis
	digest, err := ociremote.ResolveDigest(imageRef, checkOpts.RegistryClientOpts...)
	if err != nil {
		v.Logger.Error("Cannot get remote digest", "error", err, "image", imageRef.String())
		return false, "", mode, fmt.Errorf("cannot get remote digest: %w", err)
	}

	if len(sigs) > 0 {
		v.Logger.Debug("Signature verification successful for image", "image", imageRef.String(), "digest", digest.Identifier())
		v.Logger.Debug("Found valid signature(s)", "count", len(sigs))
		payload, err := sigs[0].Payload()
		if err != nil {
			v.Logger.Error("Failed to get first signature payload", "error", err, "image", imageRef.String(), "digest", digest.Identifier())
			return false, "", mode, fmt.Errorf("failed to get first signature payload: %w", err)
		}
		var payloadJSON map[string]interface{}
		if err := json.Unmarshal(payload, &payloadJSON); err != nil {
			v.Logger.Error("Failed to parse first signature payload", "error", err, "image", imageRef.String(), "digest", digest.Identifier())
			return false, "", mode, fmt.Errorf("failed to parse first signature payload: %w", err)
		}

		dockerManifestDigest := payloadJSON["critical"].(map[string]interface{})["image"].(map[string]interface{})["docker-manifest-digest"].(string)
		v.Logger.Debug("Manifest digest from first signature", "docker-manifest-digest", dockerManifestDigest, "image", imageRef.String(), "digest", digest.Identifier())
		return true, dockerManifestDigest, mode, nil
	}

	v.Logger.Info("No valid signatures found for image", "image", imageRef.String(), "digest", digest.Identifier())
	return false, "", mode, nil
}

func (v *Verifier) getVerifier(publicKeyData string) (signature.Verifier, error) {
	if publicKeyData == "" {
		return nil, fmt.Errorf("public key data is empty")
	}

	// Check if string starts with - or /
	if strings.HasPrefix(strings.TrimSpace(publicKeyData), "-----BEGIN PUBLIC KEY-----") {
		pk, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(publicKeyData))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}
		return signature.LoadVerifier(pk, crypto.SHA256)
	}

	return loadPublicKey(publicKeyData)
}

func validSignatures(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, checkOpts)
	return sigs, err
}

func loadPublicKey(path string) (signature.Verifier, error) {
	pubKey, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}

	pk, err := cryptoutils.UnmarshalPEMToPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	verifier, err := signature.LoadVerifier(pk, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier from public key: %v", err)
	}

	return verifier, nil
}
