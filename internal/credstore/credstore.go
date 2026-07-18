// Package credstore is the on-disk store for S3 credentials at
// ~/.config/git-remote-s3vault/credentials.
//
// The file is plaintext with 0600 permissions — the same trust model as
// standard credential files. The expected setup is one bucket-scoped API
// token per repository, so every entry is keyed by its bucket (qualified
// by endpoint to disambiguate identical bucket names across backends).
// There are no wide entries and no fallback:
//
//	[endpoint:https://x.r2.cloudflarestorage.com bucket:my-repo]
//	access_key_id = ...
//	secret_access_key = ...
//
//	[bucket:aws-bucket]   # AWS S3 (no explicit endpoint)
//	...
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
	return filepath.Join(dir, "git-remote-s3vault", "credentials"), nil
}

// SectionKey derives the storage key for a bucket, qualified by endpoint
// when one is configured (empty endpoint = AWS S3).
func SectionKey(endpoint, bucket string) (string, error) {
	if bucket == "" {
		return "", fmt.Errorf("a bucket is required (entries are always bucket-scoped)")
	}
	if endpoint != "" {
		return "endpoint:" + strings.TrimRight(endpoint, "/") + " bucket:" + bucket, nil
	}
	return "bucket:" + bucket, nil
}

// Lookup finds the stored credentials for exactly this bucket. There is
// no fallback; a missing or unreadable file is treated as "no
// credentials".
func Lookup(endpoint, bucket string) (Credentials, bool) {
	if bucket == "" {
		return Credentials{}, false
	}
	path, err := Path()
	if err != nil {
		return Credentials{}, false
	}
	sections, err := parseFile(path)
	if err != nil {
		return Credentials{}, false
	}
	key, err := SectionKey(endpoint, bucket)
	if err != nil {
		return Credentials{}, false
	}
	if s, ok := sections.get(key); ok {
		c := Credentials{
			AccessKeyID:     s.values["access_key_id"],
			SecretAccessKey: s.values["secret_access_key"],
		}
		if c.AccessKeyID != "" && c.SecretAccessKey != "" {
			return c, true
		}
	}
	return Credentials{}, false
}

// Save upserts this bucket's credentials and writes the file with 0600
// permissions, preserving unrelated entries. It returns the file path and
// the section name used.
func Save(endpoint, bucket string, c Credentials) (string, string, error) {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return "", "", fmt.Errorf("both an access key ID and a secret access key are required")
	}
	key, err := SectionKey(endpoint, bucket)
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
	b.WriteString("# git-remote-s3vault credentials. Keep permissions at 0600.\n")
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
