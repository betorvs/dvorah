package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/betorvs/dvorah/pkg/config"
	"github.com/betorvs/dvorah/pkg/otelutils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/betorvs/dvorah/pkg/webhook/admission"
	"github.com/betorvs/dvorah/pkg/webhook/cosign"
	"github.com/betorvs/dvorah/pkg/webhook/metrics"
)

const (
	LogLevelInfo  = "info"
	LogLevelDebug = "debug"
)

var (
	Version = "dev"
)

func main() {
	// logger
	var appLogLevel = new(slog.LevelVar)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: appLogLevel}))
	slog.SetDefault(logger)
	port := flag.Int("port", 8443, "Port to listen on")
	admPort := flag.Int("adm-port", 8080, "Port to listen on for administrative requests")
	certFile := flag.String("cert", "/certs/tls.crt", "File containing the x509 Certificate for HTTPS")
	keyFile := flag.String("key", "/certs/tls.key", "File containing the x509 private key for HTTPS")
	publicKeyPath := flag.String("public-key", "/cosign/cosign.pub", "[DEPRECATED] Path to the public key file")
	provider := flag.String("provider", config.ProviderOpenRegistry, "[DEPRECATED] Provider for the registry: 'aws' or 'google' or 'open-registry'. Lower case is required.")
	inCluster := flag.Bool("in-cluster", false, "Whether the Dvorah is in-cluster")
	mode := flag.String("mode", config.ModeDeny, "[DEPRECATED] Dvorah admission controller operation mode: 'deny' or 'audit'")
	registry := flag.String("registry", "index.docker.io/betorvs", "[DEPRECATED] Comma-separated list of allowed registries")
	policyConfig := flag.String("policy-config", "", "Path to a JSON/YAML file with granular registry policies")
	logLevel := flag.String("log-level", "info", "log level: info or debug")

	digestCacheSize := flag.Int("digest-cache-size", 1000, "Size of the image digest cache")
	digestCacheTTL := flag.Int("digest-cache-ttl", 12, "Time-to-live for the image digest cache in hours")
	tagCacheSize := flag.Int("tag-cache-size", 1000, "Size of the image tag cache")
	tagCacheTTL := flag.Int("tag-cache-ttl", 12, "Time-to-live for the image tag cache in hours")
	ownerCacheSize := flag.Int("owner-cache-size", 1000, "Size of the owner reference cache")
	ownerCacheTTL := flag.Int("owner-cache-ttl", 12, "Time-to-live for the owner reference cache in hours")
	useTagCache := flag.Bool("use-tag-cache", true, "Enable caching by image tags in addition to digests")

	dvorahDeploymentName := flag.String("deployment-name", "dvorah", "dvorah default deployment name in kubernetes")
	dvorahDeploymentNamespace := flag.String("deployment-namespace", "dvorah", "dvorah default deployment name in kubernetes")
	dvorahValidation := flag.Bool("dvorah-validation", true, "this flag always permit dvorah deployemnts in kubernetes. Disable it in production environments!")

	flag.Parse()
	switch *logLevel {
	case LogLevelDebug:
		appLogLevel.Set(slog.LevelDebug)
	default:
		appLogLevel.Set(slog.LevelInfo)
	}
	logger.Info("Starting up", "log-level", *logLevel, "version", Version)
	//
	cfg := config.New(*inCluster, *policyConfig)
	if *policyConfig != "" {
		if err := cfg.Reload(*policyConfig); err != nil {
			logger.Error("Initial config load failed", "error", err)
			os.Exit(1)
		}
	} else {
		registries := strings.Split(*registry, ",")
		// Trim spaces from each registry
		for i := range registries {
			registries[i] = strings.TrimSpace(registries[i])
		}
		err := cfg.SetGlobal(*mode, *publicKeyPath, *provider, registries)
		if err != nil {
			logger.Error("using flags with error", "error", err)
			os.Exit(1)
		}
		logger.Debug("using flags instead policy config")
		logger.Info("Using public key", "path", *publicKeyPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("Starting dvorah admission controller") // , "mode", *mode)

	verifier, err := cosign.NewVerifier(ctx, cfg, logger)
	if err != nil {
		logger.Error("Failed to create verifier", "error", err)
		os.Exit(1)
	}

	logger.Debug("allowed", "registries", cfg.GetAllowedRegistries())

	if v, ok := os.LookupEnv("DVORAH_NAMESPACE"); ok {
		*dvorahDeploymentNamespace = v
	}

	logger.Debug("always skip dvorah validation", "enable", *dvorahValidation, "deployment_name", *dvorahDeploymentName, "namespace", *dvorahDeploymentNamespace)

	validator := admission.NewValidator(verifier, cfg.GetAllowedRegistries(),
		admission.CacheConfig{
			DigestSize: *digestCacheSize,
			DigestTTL:  time.Duration(*digestCacheTTL) * time.Hour,
			TagSize:    *tagCacheSize,
			TagTTL:     time.Duration(*tagCacheTTL) * time.Hour,
			OwnerSize:  *ownerCacheSize,
			OwnerTTL:   time.Duration(*ownerCacheTTL) * time.Hour,
		},
		*useTagCache, *dvorahValidation, *dvorahDeploymentName, *dvorahDeploymentNamespace, logger)

	// setupOTelSDK: enableTraces, enableLogs bool values
	otelShutdown, err := otelutils.SetupOTelSDK(ctx)
	if err != nil {
		logger.Error("Error setting up OpenTelemetry SDK", "error", err.Error())
		os.Exit(1)
	}

	defer func() {
		err = errors.Join(err, otelShutdown(ctx))
	}()

	if err := metrics.InitMetrics(ctx); err != nil {
		logger.Error("Error initializing cache metrics", "error", err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", validator.ValidateAdmission)

	logger.Info("Starting dvorah admission controller server", "port", *port)

	handler := otelhttp.NewHandler(mux, "/")
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%v", *port),
		Handler: handler,
	}

	admMux := http.NewServeMux()
	admMux.Handle("/metrics", promhttp.Handler())
	admMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("OK\n"))
		if err != nil {
			logger.Error("Error writing response", "error", err)
		}
	})
	admServer := &http.Server{
		Addr:    fmt.Sprintf(":%v", *admPort),
		Handler: admMux,
	}
	go func() {
		if err := admServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start administrative server", "error", err)
		}
	}()

	go func() {
		if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server", "error", err)
		}
	}()

	if *policyConfig != "" {
		go func() {
			if err := cfg.WatchConfig(ctx, *policyConfig, logger); err != nil {
				logger.Error("Watcher exited", "error", err)
			}
		}()
	}

	<-ctx.Done()
	logger.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	}
	if err := admServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Administrative server forced to shutdown", "error", err)
	}

	logger.Info("Server shutdown complete")
}
