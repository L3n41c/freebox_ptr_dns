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

	"github.com/L3n41c/freebox_ptr_dns/internal/config"
	"github.com/L3n41c/freebox_ptr_dns/internal/dns"
	"github.com/L3n41c/freebox_ptr_dns/internal/freebox"
	"github.com/L3n41c/freebox_ptr_dns/internal/hosts"
	"golang.org/x/sync/errgroup"
)

func main() {
	configPath := flag.String("config", "/etc/freebox-ptr-dns/config.toml", "path to the TOML config file")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(*logLevel),
	})))

	if err := run(*configPath); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(exitCode(err))
	}
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func exitCode(err error) int {
	switch {
	case errors.Is(err, freebox.ErrInvalidAppToken):
		return 2
	case errors.Is(err, freebox.ErrAuthorizationDenied),
		errors.Is(err, freebox.ErrAuthorizationTimedOut):
		return 3
	default:
		return 1
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	httpClient := &http.Client{
		Timeout: cfg.Poller.HTTPTimeout,
		Transport: &http.Transport{
			MaxIdleConns:    2,
			IdleConnTimeout: 90 * time.Second,
		},
	}

	scheme := "https://"
	if cfg.Freebox.InsecureHTTP {
		scheme = "http://"
		slog.Warn("using HTTP for Freebox API: app_token and session tokens travel in cleartext on the LAN")
	}
	client := freebox.NewClient(freebox.ClientOptions{
		BaseURL:    scheme + cfg.Freebox.APIDomain,
		AppID:      cfg.Freebox.AppID,
		AppName:    cfg.Freebox.AppName,
		AppVersion: cfg.Freebox.AppVersion,
		DeviceName: cfg.Freebox.DeviceName,
		HTTPClient: httpClient,
	})

	token, err := freebox.LoadToken(cfg.Freebox.TokenPath)
	if errors.Is(err, os.ErrNotExist) {
		slog.Info("no app_token found, starting enrollment", "path", cfg.Freebox.TokenPath)
		freebox.OnPrompt = promptOnFreebox
		newToken, regErr := client.Register(ctx, 2*time.Second, 5*time.Minute)
		if regErr != nil {
			return fmt.Errorf("enrollment: %w", regErr)
		}
		if saveErr := freebox.SaveToken(cfg.Freebox.TokenPath, newToken); saveErr != nil {
			return fmt.Errorf("save token: %w", saveErr)
		}
		slog.Info("app_token saved", "path", cfg.Freebox.TokenPath)
		token = newToken
	} else if err != nil {
		return fmt.Errorf("load token: %w", err)
	}
	client.SetAppToken(token)

	cache := hosts.NewCache()
	handler := dns.NewHandler(cache, uint32(cfg.DNS.TTLSeconds), cfg.DNS.AllowedNetworks)
	server := dns.NewServer(cfg.DNS.Listen, handler)

	poller := hosts.NewPoller(client, cache, cfg.DNS.LocalDomain, cfg.Poller.Interval)
	poller.OnRefreshSuccess = handler.MarkReady

	// Refresh once before opening the DNS port so we never serve authoritative
	// NXDOMAIN built on empty data. Failure here is non-fatal — the handler
	// will return SERVFAIL until the poller succeeds.
	if err := poller.Refresh(ctx); err != nil {
		if errors.Is(err, freebox.ErrInvalidAppToken) {
			return err
		}
		slog.Warn("initial refresh failed; DNS will return SERVFAIL until next refresh succeeds", "err", err)
	} else {
		handler.MarkReady()
		slog.Info("hosts refreshed", "n", cache.Len())
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return poller.Run(ctx)
	})
	g.Go(func() error {
		slog.Info("DNS server listening", "addr", cfg.DNS.Listen)
		return server.ListenAndServe(ctx)
	})
	return g.Wait()
}

func promptOnFreebox(appName string) {
	banner := strings.Repeat("=", 66)
	msg := fmt.Sprintf("Approve %q on your Freebox front panel "+
		"(use the arrow keys + checkmark).", appName)
	slog.Warn("ACTION REQUIRED")
	for _, line := range []string{banner, msg, banner} {
		fmt.Fprintln(os.Stderr, line)
	}
}
