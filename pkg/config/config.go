package config

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

const (
	ModeAudit            = "audit"
	ModeDeny             = "deny"
	ProviderAWS          = "aws"
	ProviderGoogle       = "google"
	ProviderOpenRegistry = "open-registry"
)

type RegistryPolicy struct {
	Name          string   `yaml:"name"`                 // Ex: "aws"
	Pattern       string   `yaml:"pattern"`              // Ex: "*.dkr.ecr.us-east-1.amazonaws.com"
	PublicKey     string   `yaml:"publicKey,omitempty"`  // Public Key
	Provider      string   `yaml:"provider"`             // provider to connect
	Mode          string   `yaml:"mode"`                 // "deny" ou "audit"
	InCluster     bool     `yaml:"incluster"`            // in cluster bool
	Registries    []string `yaml:"registries,omitempty"` // allowed registries
	Identity      string   `yaml:"identity,omitempty"`
	IdentityRegex string   `yaml:"identity_regex,omitempty"`
	Issuer        string   `yaml:"issuer,omitempty"`
	IssuerRegex   string   `yaml:"issuer_regex,omitempty"`
}

type DvorahConfig struct {
	GlobalMode       string           `yaml:"globalMode"`
	GlobalPublicKey  string           `yaml:"globalPublicKey"`
	GlobalProvider   string           `yaml:"globalProvider"`
	GlobalRegistries []string         `yaml:"globalRegistries,omitempty"` // allowed registry list: it makes Dvorah fails fast in case a unknown registry in kubernetes
	Policies         []RegistryPolicy `yaml:"policies"`
	InCluster        bool             `yaml:"inCluster"`
	mu               sync.RWMutex
}

// New returns a DvorahConfig instance
func New(inCluster bool, policyFile string) *DvorahConfig {
	return &DvorahConfig{
		InCluster: inCluster,
	}
}

// Reload reads config.yaml configuration file
func (c *DvorahConfig) Reload(filePath string) error {
	pathClean := filepath.Clean(filePath)
	data, err := os.ReadFile(pathClean)
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err)
	}

	// Criamos uma estrutura temporária para validar o YAML antes de aplicar
	var newCfg DvorahConfig
	if err := yaml.Unmarshal(data, &newCfg); err != nil {
		return fmt.Errorf("could not unmarshal config: %w", err)
	}

	// Lock para escrita: impede leituras enquanto atualizamos os dados
	c.mu.Lock()
	defer c.mu.Unlock()

	if !validateMode(newCfg.GlobalMode) {
		return fmt.Errorf("globel mode invalid")
	}
	if !validateProvider(newCfg.GlobalProvider) {
		return fmt.Errorf("unsupported global provider %s", newCfg.GlobalProvider)
	}

	for _, v := range newCfg.Policies {
		if !validateMode(v.Mode) {
			return fmt.Errorf("invalid mode in policy %s ", v.Name)
		}
		if !validateProvider(v.Provider) {
			return fmt.Errorf("unsupported provider %s on %s", v.Provider, v.Name)
		}
	}

	if len(newCfg.GlobalRegistries) < 1 {
		return fmt.Errorf("invalid number of allowed registries")
	}

	c.GlobalMode = newCfg.GlobalMode
	c.GlobalPublicKey = newCfg.GlobalPublicKey
	c.GlobalProvider = newCfg.GlobalProvider
	c.GlobalRegistries = newCfg.GlobalRegistries
	c.Policies = newCfg.Policies

	return nil
}

// SetGlobal is used to create default global configuration from flags
func (c *DvorahConfig) SetGlobal(mode, publicKey, provider string, registries []string) error {
	if !validateMode(mode) {
		return fmt.Errorf("globel mode invalid")
	}
	if !validateProvider(provider) {
		return fmt.Errorf("unsupported global provider %s", provider)
	}
	if len(registries) < 1 {
		return fmt.Errorf("invalid number of allowed registries")
	}
	if publicKey == "" {
		return fmt.Errorf("invalid public key")
	}

	c.GlobalMode = mode
	c.GlobalPublicKey = publicKey
	c.GlobalProvider = provider
	c.GlobalRegistries = registries

	return nil
}

// GetPOlicyForImage returns RegistryPolicy
// Default: flags
// Override: if finds a config file
// Granularity: If the image matches a specific policy, use that policy's key; otherwise, use the flag's global-public-key.
func (c *DvorahConfig) GetPolicyForImage(imageURL string, logger *slog.Logger) RegistryPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, p := range c.Policies {
		if matchPattern(p.Pattern, imageURL, logger) {
			return p
		}
	}

	return RegistryPolicy{
		Name:       "global",
		Provider:   c.GlobalProvider,
		PublicKey:  c.GlobalPublicKey,
		Registries: c.GlobalRegistries,
	}
}

// GetAllowedRegistries returns a slice of registries
func (c *DvorahConfig) GetAllowedRegistries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	registries := []string{}
	for _, v := range c.Policies {
		registries = append(registries, v.Registries...)
	}
	registries = append(registries, c.GlobalRegistries...)
	return registries
}

func (c *DvorahConfig) GetGlobalMode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.GlobalMode
}

// MatchPattern checks if that image registry matches with some configs
// Exmaples: 'gcr.io/my-project/*' ou 'docker.io/library/alpine:*'
func matchPattern(pattern, imageURL string, logger *slog.Logger) bool {
	pattern = strings.TrimSpace(pattern)
	imageURL = strings.TrimSpace(imageURL)

	logger.Debug("matchpattern", "pattern", pattern, "image", imageURL)

	if pattern == "*" || pattern == "" {
		return true
	}

	if pattern == imageURL {
		return true
	}

	// 4. Glob Matching using path.Match
	matched, err := path.Match(pattern, imageURL)
	if err != nil {
		logger.Error("matchpattern", "error", err)
		return false
	}

	return matched
}

func validateMode(m string) bool {
	if m != ModeAudit && m != ModeDeny {
		return false
	}
	return true
}

func validateProvider(p string) bool {
	if p != ProviderAWS && p != ProviderGoogle && p != ProviderOpenRegistry {
		return false
	}
	return true
}
