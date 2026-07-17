// Package credstore is the on-disk store for S3/R2 credentials at
// ~/.config/git-remote-r2/credentials.
//
// The file is plaintext with 0600 permissions — the same trust model as
// standard credential files. Because the recommended setup is one
// bucket-scoped API token per repository, entries are keyed by bucket
// first, with account- or endpoint-wide entries as fallback:
//
//	[account:abc123 bucket:my-repo]      # bucket-scoped token (recommended)
//	access_key_id = ...
//	secret_access_key = ...
//
//	[account:abc123]                     # account-wide fallback
//	...
//
//	[endpoint:http://127.0.0.1:9000]     # generic S3 backends
//	...
//
// Lookup order: account+bucket, endpoint+bucket, account, endpoint.
package credstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Credentials is one stored key pair.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// Path returns the credentials file location.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "git-remote-r2", "credentials"), nil
}

// SectionKey derives the storage key. bucket == "" means an account- or
// endpoint-wide entry; with a bucket the entry applies to that bucket only
// (matching the recommended one-token-per-bucket setup).
func SectionKey(accountID, endpoint, bucket string) (string, error) {
	var base string
	switch {
	case accountID != "":
		base = "account:" + accountID
	case endpoint != "":
		base = "endpoint:" + strings.TrimRight(endpoint, "/")
	}
	switch {
	case base != "" && bucket != "":
		return base + " bucket:" + bucket, nil
	case base != "":
		return base, nil
	case bucket != "":
		return "bucket:" + bucket, nil
	default:
		return "", fmt.Errorf("neither an account ID, an endpoint, nor a bucket is configured")
	}
}

// Lookup finds stored credentials, most specific entry first:
// account+bucket, endpoint+bucket, account, endpoint. A missing or
// unreadable file is treated as "no credentials".
func Lookup(accountID, endpoint, bucket string) (Credentials, bool) {
	path, err := Path()
	if err != nil {
		return Credentials{}, false
	}
	sections, err := parseFile(path)
	if err != nil {
		return Credentials{}, false
	}
	ep := strings.TrimRight(endpoint, "/")
	var keys []string
	if bucket != "" {
		if accountID != "" {
			keys = append(keys, "account:"+accountID+" bucket:"+bucket)
		}
		if ep != "" {
			keys = append(keys, "endpoint:"+ep+" bucket:"+bucket)
		}
		if accountID == "" && ep == "" {
			keys = append(keys, "bucket:"+bucket)
		}
	}
	if accountID != "" {
		keys = append(keys, "account:"+accountID)
	}
	if ep != "" {
		keys = append(keys, "endpoint:"+ep)
	}
	for _, k := range keys {
		if s, ok := sections.get(k); ok {
			c := Credentials{
				AccessKeyID:     s.values["access_key_id"],
				SecretAccessKey: s.values["secret_access_key"],
			}
			if c.AccessKeyID != "" && c.SecretAccessKey != "" {
				return c, true
			}
		}
	}
	return Credentials{}, false
}

// Save upserts credentials and writes the file with 0600 permissions,
// preserving unrelated entries. bucket == "" stores an account- or
// endpoint-wide entry. It returns the file path and the section name used.
func Save(accountID, endpoint, bucket string, c Credentials) (string, string, error) {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return "", "", fmt.Errorf("both an access key ID and a secret access key are required")
	}
	key, err := SectionKey(accountID, endpoint, bucket)
	if err != nil {
		return "", "", err
	}
	path, err := Path()
	if err != nil {
		return "", "", err
	}
	sections, err := parseFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	sections.set(key, map[string]string{
		"access_key_id":     c.AccessKeyID,
		"secret_access_key": c.SecretAccessKey,
	})

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	var b strings.Builder
	b.WriteString("# git-remote-r2 credentials. Keep permissions at 0600.\n")
	b.WriteString("# Tip: use R2 API tokens scoped to a single bucket (Object Read & Write).\n")
	for _, s := range sections.list {
		fmt.Fprintf(&b, "\n[%s]\n", s.name)
		for _, k := range []string{"access_key_id", "secret_access_key"} {
			if v, ok := s.values[k]; ok {
				fmt.Fprintf(&b, "%s = %s\n", k, v)
			}
		}
		for k, v := range s.values {
			if k != "access_key_id" && k != "secret_access_key" {
				fmt.Fprintf(&b, "%s = %s\n", k, v)
			}
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", "", err
	}
	// The file may pre-date this write with looser permissions.
	if err := os.Chmod(path, 0o600); err != nil {
		return "", "", err
	}
	return path, key, nil
}

type section struct {
	name   string
	values map[string]string
}

type sectionList struct {
	list []*section
}

func (l *sectionList) get(name string) (*section, bool) {
	for _, s := range l.list {
		if s.name == name {
			return s, true
		}
	}
	return nil, false
}

func (l *sectionList) set(name string, values map[string]string) {
	if s, ok := l.get(name); ok {
		s.values = values
		return
	}
	l.list = append(l.list, &section{name: name, values: values})
}

func parseFile(path string) (sectionList, error) {
	var out sectionList
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	var cur *section
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = &section{name: line[1 : len(line)-1], values: map[string]string{}}
			out.list = append(out.list, cur)
			continue
		}
		if cur == nil {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur.values[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out, nil
}
