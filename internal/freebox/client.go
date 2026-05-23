package freebox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	BaseURL    string // e.g. "https://mafreebox.freebox.fr" (no trailing slash)
	AppID      string
	AppName    string
	AppVersion string
	DeviceName string
	AppToken   string       // empty when registering
	HTTPClient *http.Client // optional; defaults to a sensible client
}

type Client struct {
	opt        ClientOptions
	httpClient *http.Client

	mu         sync.Mutex
	session    string
	sessionExp time.Time
}

func NewClient(opt ClientOptions) *Client {
	c := opt.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{opt: opt, httpClient: c}
}

// SetAppToken updates the app_token used for session authentication. Useful
// just after a successful Register().
func (c *Client) SetAppToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opt.AppToken = token
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
	defer resp.Body.Close()
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
		resp.Body.Close()
		var apiErr *APIError
		if attempt == 0 && errors.As(err, &apiErr) && apiErr.Code == "auth_required" {
			c.invalidateSession()
			continue
		}
		return err
	}
}

func (c *Client) buildRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.opt.BaseURL+path, rdr)
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
