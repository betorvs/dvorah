package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

// WatchConfig reads config.yaml file in the filesystem
func (c *DvorahConfig) WatchConfig(ctx context.Context, filePath string, logger *slog.Logger) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() {
		err := watcher.Close()
		if err != nil {
			logger.Error("error closing watcher", "error", err)
		}
	}()

	// O Kubernetes atualiza via symlink, monitorar o diretório pai é mais resiliente
	dir := filepath.Dir(filePath)
	if err := watcher.Add(dir); err != nil {
		return err
	}

	logger.Info("Watching policy configuration at", "file", filePath)

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopping policy watcher...")
			return ctx.Err()

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			// O K8s sinaliza mudanças criando/removendo symlinks (..data)
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				if filepath.Base(event.Name) == filepath.Base(filePath) || strings.Contains(event.Name, "..data") {
					logger.Info("Policy file change detected. Reloading...")
					if err := c.Reload(filePath); err != nil {
						logger.Error("Failed to reload config", "error", err)
					}
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			logger.Error("Watcher error", "error", err)
		}
	}
}
