// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeServer is a tiny stand-in for the Freebox API used to drive tests.
type fakeServer struct {
	t      *testing.T
	server *httptest.Server

	mu         sync.Mutex
	challenge  string
	token      string // current valid session token
	appToken   string
	grants     atomic.Int32 // sessionRequest invocation count
	hostsResp  []LanHost
	ifaceResp  []LanInterface
	trackID    int
	trackState string // "pending", "granted", "denied", "timeout"
	trackDelay time.Duration
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()

	fs := &fakeServer{
		t:          t,
		challenge:  "challenge-A",
		token:      "session-token-1",
		appToken:   "app-token-secret",
		trackID:    42,
		trackState: "granted",
	}
	fs.server = httptest.NewServer(http.HandlerFunc(fs.handle))

	t.Cleanup(fs.server.Close)

	return fs
}

func (fs *fakeServer) get() (challenge, token, appToken, trackState string, hostsResp []LanHost, ifaceResp []LanInterface) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.challenge, fs.token, fs.appToken, fs.trackState, fs.hostsResp, fs.ifaceResp
}

func (fs *fakeServer) setTrackState(s string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.trackState = s
}

func (fs *fakeServer) setTrackDelay(d time.Duration) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.trackDelay = d
}

func (fs *fakeServer) setToken(s string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.token = s
}

func (fs *fakeServer) setHosts(h []LanHost) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.hostsResp = h
}

func (fs *fakeServer) setIfaces(i []LanInterface) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.ifaceResp = i
}

func (fs *fakeServer) getAppToken() string {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.appToken
}

func (fs *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	challenge, token, appToken, trackState, hostsResp, ifaceResp := fs.get()
	fs.mu.Lock()
	trackDelay := fs.trackDelay
	fs.mu.Unlock()

	switch {
	case r.Method == "POST" && r.URL.Path == "/api/v4/login/authorize/":
		var req authorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeOK(w, authorizeResult{AppToken: appToken, TrackID: fs.trackID})

	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v4/login/authorize/"):
		if trackDelay > 0 {
			select {
			case <-time.After(trackDelay):
			case <-r.Context().Done():
				return
			}
		}
		writeOK(w, authorizeStatusResult{Status: trackState})

	case r.Method == "GET" && r.URL.Path == "/api/v4/login/":
		writeOK(w, loginResult{Challenge: challenge})

	case r.Method == "POST" && r.URL.Path == "/api/v4/login/session/":
		fs.grants.Add(1)
		var req sessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mac := hmac.New(sha1.New, []byte(appToken))
		mac.Write([]byte(challenge))
		want := hex.EncodeToString(mac.Sum(nil))
		if req.Password != want {
			writeErr(w, "invalid_token", "bad password")
			return
		}
		writeOK(w, sessionResult{SessionToken: token})

	case r.Method == "GET" && r.URL.Path == "/api/v4/lan/browser/interfaces/":
		if r.Header.Get("X-Fbx-App-Auth") != token {
			writeErr(w, "auth_required", "session expired")
			return
		}
		writeOK(w, ifaceResp)

	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v4/lan/browser/"):
		if r.Header.Get("X-Fbx-App-Auth") != token {
			writeErr(w, "auth_required", "session expired")
			return
		}
		writeOK(w, hostsResp)

	default:
		http.Error(w, "not found: "+r.Method+" "+r.URL.Path, 404)
	}
}

func writeOK(w http.ResponseWriter, result any) {
	b, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Result: b})
}

func writeErr(w http.ResponseWriter, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200) // Freebox returns 200 + success=false
	_ = json.NewEncoder(w).Encode(envelope{Success: false, ErrorCode: code, Msg: msg})
}

// --- Register flow ----------------------------------------------------------

func TestRegister(t *testing.T) {
	tests := []struct {
		name       string
		trackState string
		wantErr    error
		wantToken  string
	}{
		{"happy path", "granted", nil, "app-token-secret"},
		{"denied", "denied", ErrAuthorizationDenied, ""},
		{"timeout", "timeout", ErrAuthorizationTimedOut, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newFakeServer(t)
			fs.setTrackState(tt.trackState)
			c := newTestClient(fs, "")

			tok, err := c.Register(t.Context(), 10*time.Millisecond, 5*time.Second)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, tok)
		})
	}
}

func TestRegister_PendingThenGranted(t *testing.T) {
	fs := newFakeServer(t)
	fs.setTrackState("pending")
	c := newTestClient(fs, "")

	go func() {
		time.Sleep(20 * time.Millisecond)
		fs.setTrackState("granted")
	}()

	tok, err := c.Register(t.Context(), 5*time.Millisecond, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, fs.getAppToken(), tok)
}

func TestRegister_LocalTimeoutWhilePending(t *testing.T) {
	fs := newFakeServer(t)
	fs.setTrackState("pending")
	c := newTestClient(fs, "")

	_, err := c.Register(t.Context(), 10*time.Millisecond, 25*time.Millisecond)
	require.ErrorIs(t, err, ErrAuthorizationTimedOut)
}

func TestRegister_LocalTimeoutDuringStatusRequest(t *testing.T) {
	fs := newFakeServer(t)
	fs.setTrackState("pending")
	fs.setTrackDelay(200 * time.Millisecond)
	c := newTestClient(fs, "")

	_, err := c.Register(t.Context(), 10*time.Millisecond, 25*time.Millisecond)
	require.ErrorIs(t, err, ErrAuthorizationTimedOut)
}

// --- Session refresh --------------------------------------------------------

func TestSession(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*testing.T, *fakeServer, *Client)
		wantToken      string
		wantGrantCount int32
	}{
		{
			name:          "refresh",
			wantToken:     "session-token-1",
			wantGrantCount: 1,
		},
		{
			name:  "cached",
			setup: func(t *testing.T, fs *fakeServer, c *Client) {
				for range 4 {
					_, err := c.sessionToken(t.Context())
					require.NoError(t, err)
				}
			},
			wantToken:     "session-token-1",
			wantGrantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newFakeServer(t)
			c := newTestClient(fs, fs.getAppToken())
			if tt.setup != nil {
				tt.setup(t, fs, c)
			}

			tok, err := c.sessionToken(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, tok)
			assert.Equal(t, tt.wantGrantCount, fs.grants.Load())
		})
	}
}

func TestSession_RefreshOnAuthRequired(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(fs, fs.getAppToken())

	_, err := c.ListInterfaces(t.Context())
	require.NoError(t, err)
	// Server rotates session token: previously stored client token now invalid.
	fs.setToken("session-token-2")
	_, err = c.ListInterfaces(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), fs.grants.Load())
}

// --- LAN --------------------------------------------------------------------

func TestListInterfaces(t *testing.T) {
	fs := newFakeServer(t)
	fs.setIfaces([]LanInterface{
		{Name: "pub", HostCount: 3},
		{Name: "ipv6", HostCount: 2},
	})
	c := newTestClient(fs, fs.getAppToken())

	ifaces, err := c.ListInterfaces(t.Context())
	require.NoError(t, err)
	assert.Len(t, ifaces, 2)
	assert.Equal(t, "pub", ifaces[0].Name)
	assert.Equal(t, "ipv6", ifaces[1].Name)
}

func TestListHosts(t *testing.T) {
	fs := newFakeServer(t)
	fs.setHosts([]LanHost{
		{
			ID:          "ether-aa:bb:cc:dd:ee:ff",
			PrimaryName: "laptop",
			Active:      true,
			Reachable:   true,
			L3Connectivities: []L3Conn{
				{Addr: "192.168.1.42", Af: "ipv4", Active: true, Reachable: true},
				{Addr: "fd00::1", Af: "ipv6", Active: true, Reachable: true},
			},
		},
	})
	c := newTestClient(fs, fs.getAppToken())

	hosts, err := c.ListHosts(t.Context(), "pub")
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	assert.Equal(t, "laptop", hosts[0].PrimaryName)
	assert.Len(t, hosts[0].L3Connectivities, 2)
}

// --- helpers ----------------------------------------------------------------

func newTestClient(fs *fakeServer, appToken string) *Client {
	return NewClient(ClientOptions{
		BaseURL:    fs.server.URL,
		AppID:      "test.app",
		AppName:    "Test App",
		AppVersion: "1.0",
		DeviceName: "host",
		AppToken:   appToken,
		HTTPClient: fs.server.Client(),
	})
}
