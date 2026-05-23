package freebox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tightDir returns a sub-directory of t.TempDir() with 0700 permissions —
// the default t.TempDir() is 0770 on most systems, which the token store
// rightfully rejects.
func tightDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "secure")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatalf("mkdir tight: %v", err)
	}
	return d
}

func TestTokenStore_SaveAndLoad(t *testing.T) {
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	if err := SaveToken(p, "secret-app-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	tok, err := LoadToken(p)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if tok != "secret-app-token" {
		t.Errorf("got %q", tok)
	}
}

func TestTokenStore_SavedFileIs0600(t *testing.T) {
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	if err := SaveToken(p, "t"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("perms = %o, want 600", st.Mode().Perm())
	}
}

func TestTokenStore_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "deep", "token")
	if err := SaveToken(p, "t"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	st, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if !st.IsDir() {
		t.Error("parent is not a dir")
	}
}

func TestTokenStore_LoadRejectsLooseFile(t *testing.T) {
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("t"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadToken(p)
	if err == nil {
		t.Fatal("expected error for too-permissive token file")
	}
	if !strings.Contains(err.Error(), "permission") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestTokenStore_LoadMissingReturnsNotFound(t *testing.T) {
	_, err := LoadToken("/nonexistent/token")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("want errors.Is(err, os.ErrNotExist), got %v", err)
	}
}

func TestTokenStore_LoadTrimsWhitespace(t *testing.T) {
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	// Some editors add trailing newline; we must accept it.
	if err := os.WriteFile(p, []byte("my-token\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	tok, err := LoadToken(p)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if tok != "my-token" {
		t.Errorf("got %q", tok)
	}
}

func TestTokenStore_SaveRefusesEmpty(t *testing.T) {
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	if err := SaveToken(p, ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestTokenStore_RejectsLooseParentDir(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "loose")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(parent, "token")
	err := SaveToken(p, "t")
	if err == nil {
		t.Fatal("expected SaveToken to reject loose parent dir")
	}
	if !strings.Contains(err.Error(), "parent") {
		t.Errorf("error should mention parent: %v", err)
	}

	// Also at load time, even if the file is tight, a loose parent must reject.
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := SaveToken(p, "t"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	if _, err := LoadToken(p); err == nil {
		t.Fatal("expected LoadToken to reject loose parent dir")
	}
}

func TestTokenStore_SaveIsAtomic(t *testing.T) {
	// After SaveToken returns, no ".tmp" file should linger.
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	if err := SaveToken(p, "secret"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file leaked: %v", err)
	}
}

func TestTokenStore_SaveCleansUpLeftoverTmp(t *testing.T) {
	// A previous crash may leave "<path>.tmp" behind; the next SaveToken
	// must succeed by overwriting it.
	dir := tightDir(t)
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p+".tmp", []byte("stale"), 0o600); err != nil {
		t.Fatalf("seed stale tmp: %v", err)
	}
	if err := SaveToken(p, "fresh"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	tok, err := LoadToken(p)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if tok != "fresh" {
		t.Errorf("got %q", tok)
	}
}

func TestTokenStore_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("decoy\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := LoadToken(link); err == nil {
		t.Fatal("LoadToken should refuse to follow a symlink")
	}
	if err := SaveToken(link, "t"); err == nil {
		t.Fatal("SaveToken should refuse to follow a symlink")
	}
}
