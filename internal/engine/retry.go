package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"proxy-dispatcher/internal/config"
)

// RetryHandler wraps a rotator pick with configurable retry-on-failure.
type RetryHandler struct {
	maxAttempts int
	backoff     time.Duration
	enabled     bool
	logger      *slog.Logger
}

// NewRetryHandler builds a RetryHandler from config.
func NewRetryHandler(cfg config.RetryConfig, logger *slog.Logger) *RetryHandler {
	ma := cfg.MaxAttempts
	if ma <= 0 {
		ma = 1
	}
	return &RetryHandler{
		maxAttempts: ma,
		backoff:     time.Duration(cfg.BackoffMs) * time.Millisecond,
		enabled:     cfg.Enabled,
		logger:      logger,
	}
}

// WithRetry runs action with rotator-supplied proxies, retrying on error.
// Proxies that fail are excluded from subsequent attempts.
func (rh *RetryHandler) WithRetry(ctx context.Context, rotator Rotator, clientIP string, action func(proxy *config.ProxyEntry) error) (*config.ProxyEntry, error) {
	if !rh.enabled {
		p, err := rotator.Next(clientIP)
		if err != nil {
			return nil, err
		}
		return p, action(p)
	}
	exclude := make(map[string]bool)
	var lastErr error
	for attempt := 1; attempt <= rh.maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var proxy *config.ProxyEntry
		var err error
		for i := 0; i < 3; i++ {
			proxy, err = rotator.Next(clientIP)
			if err != nil {
				return nil, err
			}
			key := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
			if !exclude[key] {
				break
			}
		}
		err = action(proxy)
		if err == nil {
			return proxy, nil
		}
		lastErr = err
		key := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
		exclude[key] = true
		if rh.logger != nil {
			rh.logger.Debug("retry attempt failed", "attempt", attempt, "proxy", key, "error", err)
		}
		if attempt < rh.maxAttempts && rh.backoff > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(rh.backoff):
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("all retry attempts failed")
	}
	return nil, fmt.Errorf("retry exhausted: %w", lastErr)
}
