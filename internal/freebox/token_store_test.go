// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tightDir returns a sub-directory of t.TempDir() with 0700 permissions —
// the default t.TempDir() is 0770 on most systems, which the token store
// rightfully rejects.
func tightDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "secure")
	require.NoError(t, os.Mkdir(d, 0o700), "mkdir tight")
	return d
}

// --- Save/Load --------------------------------------------------------------

func TestTokenStore_SaveLoad(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantTok  string
		wantPerm os.FileMode
	}{
		{"basic", "secret-app-token", "secret-app-token", 0o600},
		{"with newline", "my-token\n", "my-token", 0o600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tightDir(t)
			p := filepath.Join(dir, "token")
			require.NoError(t, SaveToken(p, tt.content), "SaveToken should succeed")

			tok, err := LoadToken(p)
			require.NoError(t, err, "LoadToken should succeed")
			assert.Equal(t, tt.wantTok, tok)

			st, err := os.Stat(p)
			require.NoError(t, err, "Stat should succeed")
			assert.Equal(t, tt.wantPerm, st.Mode().Perm())
		})
	}
}



// --- Load errors ------------------------------------------------------------

func TestTokenStore_Load(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*testing.T, string)
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "loose file",
			setup: func(t *testing.T, p string) {
				require.NoError(t, os.WriteFile(p, []byte("t"), 0o644))
			},
			wantErr:    true,
			wantErrMsg: "permission",
		},
		{
			name:       "missing file",
			setup:      func(*testing.T, string) {},
			wantErr:    true,
			wantErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tightDir(t)
			p := filepath.Join(dir, "token")
			tt.setup(t, p)

			_, err := LoadToken(p)
			if tt.wantErr {
				require.Error(t, err, "LoadToken should fail")
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
				return
			} else {
				require.NoError(t, err, "LoadToken should succeed")
			}
		})
	}
}

func TestTokenStore_LoadMissingReturnsNotFound(t *testing.T) {
	_, err := LoadToken("/nonexistent/token")
	require.Error(t, err, "LoadToken should fail for missing file")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// --- Save errors ------------------------------------------------------------

func TestTokenStore_Save(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"empty token", "", true},
		{"valid token", "secret", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tightDir(t)
			p := filepath.Join(dir, "token")
			err := SaveToken(p, tt.token)
			if tt.wantErr {
				require.Error(t, err, "SaveToken should fail")
				return
			} else {
				require.NoError(t, err, "SaveToken should succeed")
			}
		})
	}
}

func TestTokenStore_SaveIsAtomic(t *testing.T) {
	// After SaveToken returns, no ".tmp" file should linger.
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	require.NoError(t, SaveToken(p, "secret"), "SaveToken should succeed")
	_, err := os.Stat(p + ".tmp")
	assert.True(t, os.IsNotExist(err), "temp file should not exist")
}

func TestTokenStore_SaveCleansUpLeftoverTmp(t *testing.T) {
	// A previous crash may leave "<path>.tmp" behind; the next SaveToken
	// must succeed by overwriting it.
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(p+".tmp", []byte("stale"), 0o600), "seed stale tmp")
	require.NoError(t, SaveToken(p, "fresh"), "SaveToken should succeed")

	tok, err := LoadToken(p)
	require.NoError(t, err, "LoadToken should succeed")
	assert.Equal(t, "fresh", tok)
}

// --- Parent dir / symlink ----------------------------------------------------

func TestTokenStore_RejectsLooseParentDir(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "loose")
	require.NoError(t, os.Mkdir(parent, 0o755), "mkdir should succeed")
	p := filepath.Join(parent, "token")

	err := SaveToken(p, "t")
	require.Error(t, err, "SaveToken should reject loose parent dir")
	assert.Contains(t, err.Error(), "parent")

	// Also at load time, even if the file is tight, a loose parent must reject.
	require.NoError(t, os.Chmod(parent, 0o700), "chmod should succeed")
	require.NoError(t, SaveToken(p, "t"), "SaveToken should succeed with tight parent")
	require.NoError(t, os.Chmod(parent, 0o755), "chmod back should succeed")
	_, err = LoadToken(p)
	require.Error(t, err, "LoadToken should reject loose parent dir")
}

func TestTokenStore_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	require.NoError(t, os.WriteFile(target, []byte("decoy\n"), 0o600), "write target should succeed")
	link := filepath.Join(dir, "token")
	require.NoError(t, os.Symlink(target, link), "symlink should succeed")

	_, err := LoadToken(link)
	require.Error(t, err, "LoadToken should refuse to follow a symlink")
	err = SaveToken(link, "t")
	require.Error(t, err, "SaveToken should refuse to follow a symlink")
}

// --- GetTokenPath ----------------------------------------------------------------

func TestGetTokenPath_ExplicitPath(t *testing.T) {
	path := "/explicit/path/token"
	result, err := GetTokenPath(path)
	require.NoError(t, err)
	assert.Equal(t, path, result)
}

func TestGetTokenPath_StateDirectory(t *testing.T) {
	// Set STATE_DIRECTORY environment variable
	statedir := "/var/lib/my-service"
	require.NoError(t, os.Setenv("STATE_DIRECTORY", statedir))
	defer func() {
		require.NoError(t, os.Unsetenv("STATE_DIRECTORY"))
	}()

	path, err := GetTokenPath("")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(statedir, "app_token"), path)
}

func TestGetTokenPath_Fallback(t *testing.T) {
	// Unset STATE_DIRECTORY
	require.NoError(t, os.Unsetenv("STATE_DIRECTORY"))

	path, err := GetTokenPath("")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(os.TempDir(), "freebox-ptr-dns", "app_token"), path)
}

func TestGetTokenPath_PrefsExplicitOverEnv(t *testing.T) {
	// Set STATE_DIRECTORY but also provide explicit path
	require.NoError(t, os.Setenv("STATE_DIRECTORY", "/var/lib/my-service"))
	defer func() {
		require.NoError(t, os.Unsetenv("STATE_DIRECTORY"))
	}()

	explicit := "/custom/path/token"
	path, err := GetTokenPath(explicit)
	require.NoError(t, err)
	assert.Equal(t, explicit, path)
}
