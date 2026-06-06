// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// sessionLifetime is how long we trust a fresh session token without forcing
// a refresh. The Freebox documents ~30 min; we keep a safety margin.
const sessionLifetime = 20 * time.Minute

// sessionToken returns a valid session token, refreshing transparently if the
// cached one is expired or missing. Thread-safe.
func (c *Client) sessionToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != "" && time.Now().Before(c.sessionExp) {
		return c.session, nil
	}

	if c.appToken == "" {
		return "", errors.New("freebox: no app_token; run enrollment first")
	}

	if err := c.refreshLocked(ctx); err != nil {
		return "", err
	}

	return c.session, nil
}

func (c *Client) invalidateSession() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.session = ""
	c.sessionExp = time.Time{}
}

// refreshLocked must be called with c.mu held.
func (c *Client) refreshLocked(ctx context.Context) error {
	var login loginResult
	if err := c.doPlain(ctx, "GET", "login/", nil, &login); err != nil {
		return fmt.Errorf("get challenge: %w", err)
	}

	pwd := hmacSHA1Hex(c.appToken, login.Challenge)

	var sess sessionResult
	if err := c.doPlain(ctx, "POST", "login/session/", sessionRequest{
		AppID:    c.appID,
		Password: pwd,
	}, &sess); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Code == "invalid_token" {
			return fmt.Errorf("%w: %s", ErrInvalidAppToken, apiErr.Msg)
		}
		return fmt.Errorf("open session: %w", err)
	}

	c.session = sess.SessionToken
	c.sessionExp = time.Now().Add(sessionLifetime)
	return nil
}

func hmacSHA1Hex(key, msg string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
