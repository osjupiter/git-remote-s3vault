// Package cryptox wraps age encryption for bundle payloads.
//
// Bundles are always encrypted client-side before they reach the backend
// unless the user explicitly opts out. Both native age X25519 recipients
// and SSH (ed25519/RSA) recipients are supported.
package cryptox

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

// ParseRecipients turns recipient strings (age1... or ssh-...) into age
// recipients.
func ParseRecipients(specs []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		var (
			r   age.Recipient
			err error
		)
		switch {
		case strings.HasPrefix(s, "age1"):
			r, err = age.ParseX25519Recipient(s)
		case strings.HasPrefix(s, "ssh-"):
			r, err = agessh.ParseRecipient(s)
		default:
			err = fmt.Errorf("unrecognized recipient format")
		}
		if err != nil {
			return nil, fmt.Errorf("invalid age recipient %q: %w", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// LoadRecipientFiles reads recipient files (one recipient per line,
// '#' comments allowed) and appends them to specs.
func LoadRecipientFiles(paths []string) ([]string, error) {
	var specs []string
	for _, p := range paths {
		data, err := os.ReadFile(expandHome(p))
		if err != nil {
			return nil, fmt.Errorf("reading age recipients file: %w", err)
		}
		specs = append(specs, strings.Split(string(data), "\n")...)
	}
	return specs, nil
}

// LoadIdentityFiles parses age identity files. Files containing an OpenSSH
// private key are parsed as SSH identities.
func LoadIdentityFiles(paths []string) ([]age.Identity, error) {
	var ids []age.Identity
	for _, p := range paths {
		p = expandHome(p)
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading age identity file: %w", err)
		}
		if strings.Contains(string(data), "OPENSSH PRIVATE KEY") {
			id, err := agessh.ParseIdentity(data)
			if err != nil {
				return nil, fmt.Errorf("parsing SSH identity %s: %w", p, err)
			}
			ids = append(ids, id)
			continue
		}
		parsed, err := age.ParseIdentities(strings.NewReader(string(data)))
		if err != nil {
			return nil, fmt.Errorf("parsing age identity file %s: %w", p, err)
		}
		ids = append(ids, parsed...)
	}
	return ids, nil
}

// Encrypt copies src into dst, encrypting to the given recipients.
// The output is binary age format (not armored).
func Encrypt(dst io.Writer, src io.Reader, recipients []age.Recipient) error {
	if len(recipients) == 0 {
		return fmt.Errorf("no age recipients configured")
	}
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return fmt.Errorf("initializing age encryption: %w", err)
	}
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	return w.Close()
}

// Decrypt returns a reader yielding the plaintext of src. Armored input is
// detected transparently.
func Decrypt(src io.Reader, identities []age.Identity) (io.Reader, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("no age identities configured")
	}
	buffered := bufio.NewReader(src)
	if head, _ := buffered.Peek(len(armor.Header)); string(head) == armor.Header {
		return age.Decrypt(armor.NewReader(buffered), identities...)
	}
	return age.Decrypt(buffered, identities...)
}

// DefaultIdentityPath is where the helper looks for (and setup generates)
// the age identity when none is configured explicitly.
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "git-remote-r2", "identity.txt"), nil
}

// EnsureIdentityFile loads the identity file at path (the default location
// when path is empty), generating a fresh X25519 identity if the file does
// not exist. It returns the resolved path, whether it was created, and the
// X25519 public keys derivable from the file.
func EnsureIdentityFile(path string) (string, bool, []string, error) {
	if path == "" {
		var err error
		if path, err = DefaultIdentityPath(); err != nil {
			return "", false, nil, err
		}
	}

	if _, err := os.Stat(path); err == nil {
		ids, err := LoadIdentityFiles([]string{path})
		if err != nil {
			return path, false, nil, err
		}
		var recips []string
		for _, id := range ids {
			if x, ok := id.(*age.X25519Identity); ok {
				recips = append(recips, x.Recipient().String())
			}
		}
		return path, false, recips, nil
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return path, false, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return path, false, nil, err
	}
	content := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().Format(time.RFC3339), id.Recipient(), id)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return path, false, nil, err
	}
	return path, true, []string{id.Recipient().String()}, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}
