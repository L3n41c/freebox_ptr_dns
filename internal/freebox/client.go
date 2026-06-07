// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrInvalidAppToken signals that the app_token is no longer accepted by the
// Freebox. The caller must restart the enrollment flow (the user revoked the
// authorization or the Freebox forgot it).
var ErrInvalidAppToken = errors.New("freebox: app_token invalid")

// ErrAuthorizationDenied signals the user rejected the app on the front panel.
var ErrAuthorizationDenied = errors.New("freebox: authorization denied")

// ErrAuthorizationTimedOut signals the user did not respond in time.
var ErrAuthorizationTimedOut = errors.New("freebox: authorization timed out")

type ClientOptions struct {
	AppID       string
	AppName     string
	AppVersion  string
	DeviceName  string
	AppToken    string        // empty when registering
	HTTPTimeout time.Duration // HTTP client timeout; defaults to 10s
}

type Client struct {
	baseURL    *url.URL // e.g. "https://example.fbxos.fr:3615/api/v4/"
	appID      string
	appName    string
	appVersion string
	deviceName string
	appToken   string
	httpClient *http.Client

	mu         sync.Mutex
	session    string
	sessionExp time.Time
}

// NewClient creates a new Freebox API client by discovering the Freebox on the
// local network using mDNS. It automatically retrieves the API domain, base URL,
// and version from the Freebox's mDNS service announcement.
// The client uses Freebox-specific CA certificates to validate HTTPS connections.
// HTTPS is always used; if the Freebox does not advertise HTTPS support, an error is returned.
func NewClient(ctx context.Context, opt ClientOptions) (*Client, error) {
	// Discover Freebox API information using mDNS
	disc, err := Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("freebox discovery: %w", err)
	}

	// HTTPS is mandatory for security (tokens are sent over the connection)
	if !disc.HTTPSAvailable {
		return nil, errors.New("freebox: HTTPS is not available on the Freebox")
	}

	// Build the base URL: always use HTTPS
	// e.g., "https://example.fbxos.fr:3615/api/v4/"
	u := &url.URL{
		Scheme: "https",
		Host:   disc.APIDomain,
	}
	if disc.HTTPSPort != 0 {
		u.Host += ":" + strconv.Itoa(disc.HTTPSPort)
	}

	// Extract major version (e.g., "4.0" -> "4")
	majorVer, _, _ := strings.Cut(disc.APIVersion, ".")
	// Construct the full base URL using JoinPath
	u = u.JoinPath(disc.APIBaseURL, "v"+majorVer)

	// newClient will create the HTTP client with Freebox CA certificates and configured timeout
	return newClient(u, opt), nil
}

// newClient is the internal constructor that creates a Client with explicit
// API endpoint parameters. Used by NewClient and tests.
func newClient(baseURL *url.URL, opt ClientOptions) *Client {
	// Create HTTP client with Freebox CA certificates and configured timeout
	timeout := opt.HTTPTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.RootCAs = certPool

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return &Client{
		baseURL:    baseURL,
		appID:      opt.AppID,
		appName:    opt.AppName,
		appVersion: opt.AppVersion,
		deviceName: opt.DeviceName,
		appToken:   opt.AppToken,
		httpClient: httpClient,
	}
}

// SetAppToken updates the app_token used for session authentication. Useful
// just after a successful Register().
func (c *Client) SetAppToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.appToken = token
	c.session = ""
	c.sessionExp = time.Time{}
}

// doPlain executes an unauthenticated request and parses the envelope.
func (c *Client) doPlain(ctx context.Context, method, path string, body any, out any) error {
	req, err := c.buildRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	return parseEnvelope(resp, out)
}

// doAuth executes an authenticated request, automatically refreshing the
// session token once on `auth_required`.
func (c *Client) doAuth(ctx context.Context, method, path string, body any, out any) error {
	for attempt := 0; ; attempt++ {
		token, err := c.sessionToken(ctx)
		if err != nil {
			return err
		}

		req, err := c.buildRequest(ctx, method, path, body)
		if err != nil {
			return err
		}
		req.Header.Set("X-Fbx-App-Auth", token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}

		err = parseEnvelope(resp, out)
		resp.Body.Close() //nolint:errcheck
		var apiErr *APIError
		if attempt == 0 && errors.As(err, &apiErr) && apiErr.Code == "auth_required" {
			c.invalidateSession()
			continue
		}

		return err
	}
}

func (c *Client) buildRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	// baseURL already contains scheme + host + port + api_base_url + version +
	// trailing slash, e.g., "https://example.fbxos.fr:3615/api/v4/"
	fullURL := c.baseURL.JoinPath(path).String()

	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return req, nil
}

// APIError carries the Freebox-side error code and message.
type APIError struct {
	Code string
	Msg  string
}

func (e *APIError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("freebox API error: %s (%s)", e.Code, e.Msg)
	}
	return fmt.Sprintf("freebox API error: %s", e.Code)
}

// maxBodySize caps the response body we are willing to read from the Freebox.
// 1 MiB is far above anything the API legitimately returns and prevents a
// rogue or proxied server from exhausting memory.
const maxBodySize = 1 << 20

func parseEnvelope(resp *http.Response, out any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		var env envelope
		if json.Unmarshal(body, &env) == nil && env.ErrorCode != "" {
			return &APIError{Code: env.ErrorCode, Msg: env.Msg}
		}
		// Do not echo the raw body: it may contain tokens on the /login/* paths.
		return fmt.Errorf("http %d (body redacted)", resp.StatusCode)
	}

	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if !env.Success {
		return &APIError{Code: env.ErrorCode, Msg: env.Msg}
	}

	if out == nil || len(env.Result) == 0 {
		return nil
	}

	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("decode result: %w", err)
	}

	return nil
}
