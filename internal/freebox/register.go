// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Register runs the full authorization flow:
//  1. POST login/authorize/ to obtain an app_token + track_id.
//  2. Poll GET login/authorize/{track_id} until the user grants
//     (or denies / times out) on the Freebox front panel.
//
// On success returns the new app_token. The caller is responsible for
// persisting it and calling SetAppToken on the client.
func (c *Client) Register(ctx context.Context, pollInterval, timeout time.Duration) (string, error) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	var auth authorizeResult
	if err := c.doPlain(ctx, "POST", "login/authorize/", authorizeRequest{
		AppID:      c.appID,
		AppName:    c.appName,
		AppVersion: c.appVersion,
		DeviceName: c.deviceName,
	}, &auth); err != nil {
		return "", fmt.Errorf("authorize: %w", err)
	}

	OnPrompt(c.appName)

	// Use a separate context for the authorization timeout so that parent context
	// cancellation (e.g., test timeout) can be distinguished from authorization timeout.
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		status, err := c.authorizeStatus(timeoutCtx, auth.TrackID)
		if err != nil {
			// Parent context was canceled (e.g., caller's deadline) - propagate that error first
			// to preserve caller's error semantics.
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			// Our timeout context expired during authorizeStatus request.
			if errors.Is(err, context.DeadlineExceeded) {
				return "", ErrAuthorizationTimedOut
			}
			return "", fmt.Errorf("track authorization: %w", err)
		}
		switch status {
		case "granted":
			return auth.AppToken, nil
		case "pending":
		case "denied":
			return "", ErrAuthorizationDenied
		case "timeout":
			return "", ErrAuthorizationTimedOut
		case "unknown":
			return "", errors.New("freebox: track unknown")
		default:
			return "", fmt.Errorf("freebox: unexpected status %q", status)
		}

		select {
		case <-timeoutCtx.Done():
			// Parent context was canceled first - propagate caller's error.
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			// Our authorization timeout expired.
			return "", ErrAuthorizationTimedOut
		case <-ticker.C:
		}
	}
}

func (c *Client) authorizeStatus(ctx context.Context, trackID int) (string, error) {
	var out authorizeStatusResult
	err := c.doPlain(ctx, "GET", fmt.Sprintf("login/authorize/%d", trackID), nil, &out)
	if err != nil {
		return "", err
	}
	return out.Status, nil
}

// OnPrompt is called once at the start of Register to notify the operator
// that they must approve the app on the Freebox front panel. Default is a
// no-op; main.go installs a slog-based printer, tests override it.
var OnPrompt = func(appName string) {}
