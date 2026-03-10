package cosign

import (
	"context"
	"log/slog"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	kc "github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// GoogleClient is a client for the Google API
type GoogleClient struct {
	InCluster bool
	Client    authn.Authenticator
	Keychain  authn.Keychain
}

func NewGoogleClient(ctx context.Context, logger *slog.Logger, inCluster bool) (*GoogleClient, error) {
	logger.Info("Loading Google configuration", "inCluster", inCluster)
	client := GoogleClient{
		InCluster: inCluster,
	}

	if inCluster {
		namespace, ok := os.LookupEnv("POD_NAMESPACE")
		if !ok {
			namespace = "default"
		}
		serviceAccount, ok := os.LookupEnv("POD_SERVICE_ACCOUNT")
		if !ok {
			serviceAccount = "default"
		}
		kChain, err := newClientInCluster(ctx, namespace, serviceAccount)
		if err != nil {
			return nil, err
		}
		client.Keychain = kChain
		return &client, nil
	}

	localClient, err := newClientLocal(ctx)
	if err != nil {
		return nil, err
	}
	client.Client = localClient
	return &client, nil
}

func (g *GoogleClient) GetRemoteOption(ctx context.Context) (remote.Option, error) {
	if g.InCluster {
		return remote.WithAuthFromKeychain(g.Keychain), nil
	}
	return remote.WithAuth(g.Client), nil
}

func newClientLocal(ctx context.Context) (authn.Authenticator, error) {
	auth, err := google.NewGcloudAuthenticator(ctx) // shells out to `gcloud` for an access token
	if err != nil {
		return nil, err
	}
	return auth, nil
}

func newClientInCluster(ctx context.Context, namespace, serviceAccount string) (authn.Keychain, error) {
	// k8schain discovers: ImagePullSecrets + cloud-specific helpers
	// (GCR/Artifact Registry, ECR, ACR) when running in-cluster.
	// On GKE/EKS this “just works”.
	// Ref: k8schain README.
	k8sKeychain, err := kc.NewInCluster(ctx, kc.Options{
		Namespace:          namespace,
		ServiceAccountName: serviceAccount,
	})
	if err != nil {
		return nil, err
	}

	return k8sKeychain, nil
}
