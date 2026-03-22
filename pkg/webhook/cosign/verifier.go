package cosign

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/betorvs/dvorah/pkg/config"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/tuf"
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

	policy := v.Config.GetPolicyForImage(imageRef.String(), v.Logger)
	v.Logger.Debug("return from GetPolicyForImage", "name", policy.Name, "provider", policy.Provider, "key", policy.PublicKey, "mode", policy.Mode)
	// remote options

	checkOpts, err := v.getCheckOpts(ctx, policy)
	if err != nil {
		return false, "", policy.Mode, err
	}

	// Cosign takes over the rest...
	v.Logger.Debug("Starting Cosign signature verification...")

	checkOpts.NewBundleFormat = true
	newBundles, _, err := cosign.GetBundles(ctx, imageRef, checkOpts.RegistryClientOpts)
	if len(newBundles) == 0 || err != nil {
		checkOpts.NewBundleFormat = false
	}
	// v.Logger.Debug("bundle format", "found", checkOpts.NewBundleFormat, "bundle", newBundles)

	sigs := []oci.Signature{}
	// pass digest directly to avoid a second remote lookup
	if policy.PublicKey != "" {
		sig, err := validSignatures(ctx, imageRef, checkOpts)
		if err != nil {
			v.Logger.Error("Failed to verify signature", "error", err, "image", imageRef.String(), "digest", imageRef.Identifier())
			return false, "", policy.Mode, fmt.Errorf("failed to verify signature: %w", err)
		}
		sigs = append(sigs, sig...)
	} else if checkOpts.NewBundleFormat {
		v.Logger.Debug("checking attestations")
		sig, err := validAttestations(ctx, imageRef, checkOpts)
		if err != nil {
			v.Logger.Error("Failed to verify signature", "error", err, "image", imageRef.String(), "digest", imageRef.Identifier())
			return false, "", policy.Mode, fmt.Errorf("failed to verify signature: %w", err)
		}
		sigs = append(sigs, sig...)
	}

	// resolve ref to a digest for logging purposis
	digest, err := ociremote.ResolveDigest(imageRef, checkOpts.RegistryClientOpts...)
	if err != nil {
		v.Logger.Error("Cannot get remote digest", "error", err, "image", imageRef.String())
		return false, "", policy.Mode, fmt.Errorf("cannot get remote digest: %w", err)
	}

	if len(sigs) > 0 {
		v.Logger.Debug("Signature verification successful for image", "image", imageRef.String(), "digest", digest.Identifier())
		v.Logger.Debug("Found valid signature(s)", "count", len(sigs))
		payload, err := sigs[0].Payload()
		if err != nil {
			v.Logger.Error("Failed to get first signature payload", "error", err, "image", imageRef.String(), "digest", digest.Identifier())
			return false, "", policy.Mode, fmt.Errorf("failed to get first signature payload: %w", err)
		}
		dig, err := v.decodePayload(payload, checkOpts.NewBundleFormat)
		if err != nil {
			v.Logger.Error("error parsing payload", "error", err)
		}
		if checkOpts.NewBundleFormat {
			v.Logger.Debug("Manifest digest from first signature", "identity-digest", dig, "image", imageRef.String(), "digest", digest.Identifier())
		} else {
			v.Logger.Debug("Manifest digest from first signature", "docker-manifest-digest", dig, "image", imageRef.String(), "digest", digest.Identifier())
		}

		return true, dig, policy.Mode, nil
	}

	v.Logger.Info("No valid signatures found for image", "image", imageRef.String(), "digest", digest.Identifier())
	return false, "", policy.Mode, nil
}

func (v *Verifier) getVerifier(policy config.RegistryPolicy) (signature.Verifier, error) {
	if policy.PublicKey != "" {
		// Check if string starts with - or /
		if strings.HasPrefix(strings.TrimSpace(policy.PublicKey), "-----BEGIN PUBLIC KEY-----") {
			pk, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(policy.PublicKey))
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %v", err)
			}
			return signature.LoadVerifier(pk, crypto.SHA256)
		}
		return loadPublicKey(policy.PublicKey)
	}
	return nil, nil

}

func (v *Verifier) getProviderForImage(ctx context.Context, provider string) (remote.Option, error) {
	// Lógica de detecção baseada em padrões de URL
	switch provider {
	case config.ProviderAWS:
		awsOpts, err := v.Providers[config.ProviderAWS].GetRemoteOption(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get ECR remote option: %w", err)
		}
		return awsOpts, nil
	case config.ProviderGoogle:
		googleOpts, err := v.Providers[config.ProviderGoogle].GetRemoteOption(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get Google remote option: %w", err)
		}
		return googleOpts, nil
	case config.ProviderOpenRegistry:
		// Caso não seja um provider cloud específico, usa o padrão (DockerHub/OCI genérico)
		openRegistryOpts, err := v.Providers[config.ProviderOpenRegistry].GetRemoteOption(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get Open Registry remote option: %w", err)
		}
		return openRegistryOpts, nil

	default:
		return nil, fmt.Errorf("invalid provider: %s", provider)
	}
}

func (v *Verifier) getCheckOpts(ctx context.Context, policy config.RegistryPolicy) (*cosign.CheckOpts, error) {

	opts := []remote.Option{}

	opt, err := v.getProviderForImage(ctx, policy.Provider)
	if err != nil {
		return nil, err
	}
	if f, ok := os.LookupEnv("DOCKER_CONFIG"); ok && policy.Provider == config.ProviderOpenRegistry {
		v.Logger.Debug("docker_config environment variable found loading for open-provider", "content", f)
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}
	opts = append(opts, opt)

	if policy.PublicKey != "" {

		publicKeyVerifier, err := v.getVerifier(policy)
		if err != nil {
			return nil, err
		}

		checkOpts := &cosign.CheckOpts{
			ClaimVerifier:      cosign.SimpleClaimVerifier,
			IgnoreTlog:         true,
			Offline:            true,
			SigVerifier:        publicKeyVerifier,
			RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
		}

		return checkOpts, nil
	} else if policy.Identity != "" || policy.IdentityRegex != "" {
		v.Logger.Debug("using identity in checkopts")
		if err := tuf.Initialize(ctx, tuf.DefaultRemoteRoot, nil); err != nil {
			return nil, err
		}
		tr, err := getTrustedRMaterial(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get trusted material: %w", err)
		}
		fulcioRoots, fulcioIntermediates, err := getCerts()
		if err != nil {
			return nil, fmt.Errorf("getting root and intermediate certificates: %v", err)
		}
		rekorClient, rekorPubKeys, ctlogPubKey, err := getRekorClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting Rekor client and public keys:  %w", err)
		}

		identityCounter := 0
		identity := cosign.Identity{}
		if policy.Identity != "" {
			identity.Subject = policy.Identity
			identityCounter++
		}
		if policy.Issuer != "" {
			identity.Issuer = policy.Issuer
			identityCounter++
		}
		if policy.IdentityRegex != "" {
			identity.SubjectRegExp = policy.IdentityRegex
			identityCounter++
		}
		if policy.IssuerRegex != "" {
			identity.IssuerRegExp = policy.IssuerRegex
			identityCounter++
		}

		if identityCounter <= 1 {
			return nil, fmt.Errorf("identity should be at least 2 fields: identity, issuer, identity_regex or issuer_regex")
		}

		checkOpts := &cosign.CheckOpts{
			ClaimVerifier:      cosign.IntotoSubjectClaimVerifier,
			IgnoreTlog:         false,
			Offline:            false,
			SigVerifier:        nil,
			TrustedMaterial:    tr,
			RootCerts:          fulcioRoots,
			IntermediateCerts:  fulcioIntermediates,
			RekorClient:        rekorClient,
			RekorPubKeys:       rekorPubKeys,
			CTLogPubKeys:       ctlogPubKey,
			Identities:         []cosign.Identity{identity},
			RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
		}
		return checkOpts, nil
	}

	return nil, fmt.Errorf("option not implemented")
}

func (v *Verifier) decodePayload(p []byte, newBundle bool) (string, error) {
	if newBundle {
		var payload NewBundlePayload
		err := json.Unmarshal(p, &payload)
		if err != nil {
			return "", err
		}
		decodedBytes, err := base64.StdEncoding.DecodeString(string(payload.Payload))
		if err != nil {
			return "", err
		}
		var nested NewBundleNestedPayload
		err = json.Unmarshal(decodedBytes, &nested)
		if err != nil {
			return "", err
		}
		if len(nested.Subject) > 0 {
			return fmt.Sprintf("%s:%s", digestSHA, nested.Subject[0].Digest[digestSHA]), nil
		}
	}
	var payload DockerPayload
	err := json.Unmarshal(p, &payload)
	if err != nil {
		return "", err
	}

	return payload.Critical.Image.DockerManifestDigest, nil
}

func validSignatures(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, checkOpts)
	return sigs, err
}

func validAttestations(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	sigs, _, err := cosign.VerifyImageAttestations(ctx, ref, checkOpts)
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

func getCerts() (*x509.CertPool, *x509.CertPool, error) {
	roots, err := fulcioroots.Get()
	if err != nil {
		return nil, nil, err
	}
	intermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		return nil, nil, err
	}
	return roots, intermediates, nil
}

func getTrustedRMaterial(ctx context.Context) (*root.TrustedRoot, error) {
	tufClient, err := tuf.NewFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	targetBytes, err := tufClient.GetTarget(trustedRootJSON)
	if err != nil {
		return nil, err
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(targetBytes)
	if err != nil {
		return nil, err
	}
	return trustedRoot, nil
}

func getRekorClient(ctx context.Context) (*client.Rekor, *cosign.TrustedTransparencyLogPubKeys, *cosign.TrustedTransparencyLogPubKeys, error) {
	rekorPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	ctlogPubKey, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return nil, rekorPubKeys, ctlogPubKey, nil
}
