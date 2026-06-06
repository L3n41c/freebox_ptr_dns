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
	AppID        string
	AppName      string
	AppVersion   string
	DeviceName   string
	AppToken     string       // empty when registering
	HTTPClient   *http.Client // optional; defaults to a sensible client
	InsecureHTTP bool         // opt-in: send tokens over plain HTTP
}

type Client struct {
	fullBaseURL string // e.g. "https://example.fbxos.fr:3615/api/v4/"
	appID       string
	appName     string
	appVersion  string
	deviceName  string
	appToken    string
	httpClient  *http.Client

	mu         sync.Mutex
	session    string
	sessionExp time.Time
}

// normalizeAPIBaseURL ensures the base URL starts and ends with a forward slash
// to avoid malformed URLs like ".../apiv4/".
func normalizeAPIBaseURL(baseURL string) string {
	if !strings.HasPrefix(baseURL, "/") {
		baseURL = "/" + baseURL
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL + "/"
	}
	return baseURL
}

// NewClient creates a new Freebox API client by discovering the Freebox on the
// local network using mDNS. It automatically retrieves the API domain, base URL,
// and version from the Freebox's mDNS service announcement.
// The client uses Freebox-specific CA certificates to validate HTTPS connections.
func NewClient(ctx context.Context, opt ClientOptions) (*Client, error) {
	// Discover Freebox API information using mDNS
	disc, err := Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("freebox discovery: %w", err)
	}

	// Respect the https_available flag from mDNS
	// If HTTPS is unavailable and user didn't opt into InsecureHTTP, fail fast
	if !disc.HTTPSAvailable && !opt.InsecureHTTP {
		return nil, errors.New("freebox: HTTPS is not available on the Freebox and InsecureHTTP is not enabled")
	}

	// Build the full base URL: scheme + host + port + api_base_url + version
	// e.g., "https://example.fbxos.fr:3615/api/v4/"
	scheme := "https"
	port := disc.HTTPSPort
	if opt.InsecureHTTP {
		scheme = "http"
		// In insecure mode, prefer standard HTTP port (80) over discovered HTTPS port
		// to avoid attempting HTTP on the HTTPS port (e.g., http://host:3615/)
		if port == 0 {
			port = 80
		}
		// If a specific https_port was advertised, don't use it for HTTP
		if port != 0 && port != 80 {
			port = 80
		}
	} else if port == 0 {
		port = 443
	}

	fullBaseURL := scheme + "://" + strings.TrimSuffix(disc.APIDomain, ".")
	if port != 0 && ((scheme == "https" && port != 443) || (scheme == "http" && port != 80)) {
		fullBaseURL += ":" + strconv.Itoa(port)
	}
	// Extract major version (e.g., "4.0" -> "4", "v4.0" -> "4")
	majorVer, _, _ := strings.Cut(disc.APIVersion, ".")
	majorVer = strings.TrimPrefix(majorVer, "v")
	// Normalize and construct the full base URL
	fullBaseURL += normalizeAPIBaseURL(disc.APIBaseURL) + "v" + majorVer + "/"

	// Create HTTP client with Freebox CA certificates
	// Clone everything to avoid mutating caller-provided client/transport
	var httpClient *http.Client
	if opt.HTTPClient != nil {
		// Clone the provided client to avoid mutation
		httpClient = &http.Client{
			Timeout:       opt.HTTPClient.Timeout,
			CheckRedirect: opt.HTTPClient.CheckRedirect,
			Jar:           opt.HTTPClient.Jar,
		}
		// Clone transport and apply Freebox CA for HTTPS, or just clone for HTTP
		if opt.HTTPClient.Transport != nil {
			if tr, ok := opt.HTTPClient.Transport.(*http.Transport); ok {
				transport := tr.Clone()
				if scheme == "https" {
					if transport.TLSClientConfig == nil {
						transport.TLSClientConfig = &tls.Config{}
					}
					transport.TLSClientConfig.RootCAs = certPool
				}
				httpClient.Transport = transport
			} else {
				return nil, errors.New("freebox: custom HTTP client has non-*http.Transport type; cannot configure TLS")
			}
		} else {
			// Clone default transport
			transport := http.DefaultTransport.(*http.Transport).Clone()
			if scheme == "https" {
				if transport.TLSClientConfig == nil {
					transport.TLSClientConfig = &tls.Config{}
				}
				transport.TLSClientConfig.RootCAs = certPool
			}
			httpClient.Transport = transport
		}
	} else {
		// Create new client with cloned default transport
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if scheme == "https" {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			}
			transport.TLSClientConfig.RootCAs = certPool
		}
		httpClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
	}

	return newClient(ClientParams{
		FullBaseURL: fullBaseURL,
		HTTPClient:  httpClient,
		ClientOptions: opt,
	}), nil
}

// ClientParams holds all parameters needed to create a Client, including the
// full base URL (scheme + host + port + api_base_url + version). Used internally
// and for testing.
type ClientParams struct {
	FullBaseURL string
	HTTPClient  *http.Client // optional; if nil, ClientOptions.HTTPClient is used
	ClientOptions
}

// newClient is the internal constructor that creates a Client with explicit
// API endpoint parameters. Used by NewClient and tests.
func newClient(params ClientParams) *Client {
	c := params.HTTPClient
	if c == nil {
		c = params.ClientOptions.HTTPClient
	}
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		fullBaseURL: params.FullBaseURL,
		appID:       params.AppID,
		appName:     params.AppName,
		appVersion:  params.AppVersion,
		deviceName:  params.DeviceName,
		appToken:    params.AppToken,
		httpClient:  c,
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
	// fullBaseURL already contains scheme + host + port + api_base_url + version +
	// trailing slash, e.g., "https://example.fbxos.fr:3615/api/v4/"
	fullURL := c.fullBaseURL + strings.TrimPrefix(path, "/")

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
