// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxTokenSize caps how much we read from a token file: more than enough for
// any real app_token, prevents reading an attacker-controlled large file.
const maxTokenSize = 4096

// SaveToken writes the app_token to path with 0600 permissions, creating
// parent directories as needed (0700). Refuses to overwrite an existing file
// and refuses to write under a directory whose permissions are looser than
// 0700 (group/world access to the parent would defeat the file mode).
//
// Writes are atomic: we stream into "<path>.tmp" then rename(2) it onto path.
// A crash mid-write therefore never leaves an empty or truncated app_token
// file behind, which would otherwise block re-enrollment (the next launch
// would fail to load and not enter the "missing → enroll" branch).
func SaveToken(path, token string) error {
	if token == "" {
		return errors.New("refusing to save empty token")
	}

	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	if err := checkParentDir(dir); err != nil {
		return err
	}

	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("token file %s already exists; remove it to re-enroll", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat token file: %w", err)
	}

	tmp := path + ".tmp"
	_ = os.Remove(tmp) // best effort: clean up after a previous crash

	// O_NOFOLLOW so a pre-existing symlink at tmp is not silently followed.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create token file: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.WriteString(token + "\n"); err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("write token: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("sync token: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close token: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename token: %w", err)
	}

	committed = true
	return nil
}

// LoadToken reads the app_token from path. Refuses to load if file
// permissions are looser than 0600 or the parent directory is group/world
// accessible. Uses fstat on the open file descriptor to avoid a TOCTOU race
// between the permission check and the read.
func LoadToken(path string) (string, error) {
	if err := checkParentDir(filepath.Dir(path)); err != nil {
		return "", err
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat token file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("token file %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %s has too-loose permission %o (want 0600)",
			path, st.Mode().Perm())
	}

	data, err := io.ReadAll(io.LimitReader(f, maxTokenSize))
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}

	return tok, nil
}

func checkParentDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat parent dir: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("token parent %s is not a directory", dir)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("token parent dir %s has too-loose permission %o (want 0700)",
			dir, st.Mode().Perm())
	}
	return nil
}
