// Package config resolves all settings for the remote helper from the
// remote URL, git configuration, and environment variables.
//
// Precedence (highest first): environment variables, remote-scoped git
// config (remote.<name>.*), global git config (s3vault.*), built-in defaults.
package config

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/osjupiter/git-remote-s3vault/internal/credstore"
)

// EncryptionMode selects how repository data is protected.
type EncryptionMode string

const (
	// EncryptionAge is the default: full encryption, with age-based key
	// management.
	EncryptionAge EncryptionMode = "age"
	// EncryptionNone stores data readable by anyone with bucket access.
	// Must be opted into explicitly.
	EncryptionNone EncryptionMode = "none"
)

// Config holds everything the helper needs to talk to the backend.
type Config struct {
	RemoteName string
	RawURL     string

	Bucket string
	Prefix string // key prefix inside the bucket, no leading/trailing slash

	// Backend: any S3-compatible endpoint. Empty means AWS S3.
	Endpoint     string
	Region       string
	UsePathStyle bool

	// Credentials (env or the credential store; nothing else is consulted).
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	Encryption     EncryptionMode
	Recipients     []string // age recipient strings (age1... or ssh-...)
	RecipientFiles []string
	IdentityFiles  []string

	Verbosity int
}

// GitConfigReader reads git configuration values. Implemented by execGit so
// tests can substitute a fake.
type GitConfigReader interface {
	Get(key string) (string, bool)
	GetAll(key string) []string
}

type execGit struct{}

func (execGit) Get(key string) (string, bool) {
	out, err := exec.Command("git", "config", "--get", key).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func (execGit) GetAll(key string) []string {
	out, err := exec.Command("git", "config", "--get-all", key).Output()
	if err != nil {
		return nil
	}
	var vals []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			vals = append(vals, l)
		}
	}
	return vals
}

// CredentialLookup finds stored credentials for an endpoint/bucket pair.
// It exists as an injection point so the config package stays decoupled
// from the on-disk store (and testable without the filesystem).
type CredentialLookup func(endpoint, bucket string) (keyID, secret string, ok bool)

// Load resolves the full configuration for a remote, including saved
// credentials from ~/.config/git-remote-s3vault/credentials.
func Load(remoteName, rawURL string) (*Config, error) {
	return load(remoteName, rawURL, execGit{}, os.Getenv, func(endpoint, bucket string) (string, string, bool) {
		c, ok := credstore.Lookup(endpoint, bucket)
		return c.AccessKeyID, c.SecretAccessKey, ok
	})
}

func load(remoteName, rawURL string, git GitConfigReader, getenv func(string) string, creds CredentialLookup) (*Config, error) {
	c := &Config{RemoteName: remoteName, RawURL: rawURL, Encryption: EncryptionAge}

	if err := c.parseURL(rawURL); err != nil {
		return nil, err
	}

	// lookup returns the first non-empty value among env names, then
	// remote-scoped git config, then global s3vault.* git config.
	lookup := func(gitKey string, envNames ...string) string {
		for _, e := range envNames {
			if v := getenv(e); v != "" {
				return v
			}
		}
		if remoteName != "" && remoteName != rawURL {
			if v, ok := git.Get("remote." + remoteName + "." + gitKey); ok && v != "" {
				return v
			}
		}
		if v, ok := git.Get("s3vault." + gitKey); ok && v != "" {
			return v
		}
		return ""
	}
	lookupAll := func(gitKey, envName string) []string {
		if v := getenv(envName); v != "" {
			var out []string
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
			return out
		}
		if remoteName != "" && remoteName != rawURL {
			if vs := git.GetAll("remote." + remoteName + "." + gitKey); len(vs) > 0 {
				return vs
			}
		}
		return git.GetAll("s3vault." + gitKey)
	}

	c.Endpoint = lookup("endpoint", "GIT_REMOTE_S3VAULT_ENDPOINT", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL")
	c.Region = lookup("region", "GIT_REMOTE_S3VAULT_REGION", "AWS_REGION", "AWS_DEFAULT_REGION")
	if c.Region == "" {
		c.Region = "us-east-1"
	}

	c.AccessKeyID = getenv("AWS_ACCESS_KEY_ID")
	c.SecretAccessKey = getenv("AWS_SECRET_ACCESS_KEY")
	c.SessionToken = getenv("AWS_SESSION_TOKEN")
	// Saved credentials fill in when env vars (which win) are absent.
	if c.AccessKeyID == "" && creds != nil {
		if id, secret, ok := creds(c.Endpoint, c.Bucket); ok {
			c.AccessKeyID, c.SecretAccessKey = id, secret
		}
	}

	switch v := lookup("usepathstyle", "GIT_REMOTE_S3VAULT_PATH_STYLE"); v {
	case "true", "1", "yes", "on":
		c.UsePathStyle = true
	case "false", "0", "no", "off":
		c.UsePathStyle = false
	case "":
		// Path-style is required by MinIO and most self-hosted S3
		// implementations; virtual-hosted style is the norm for AWS and R2.
		c.UsePathStyle = c.Endpoint != "" &&
			!strings.Contains(c.Endpoint, "amazonaws.com") &&
			!strings.Contains(c.Endpoint, ".r2.cloudflarestorage.com")
	default:
		return nil, fmt.Errorf("invalid usepathstyle value %q", v)
	}

	switch v := lookup("encryption", "GIT_REMOTE_S3VAULT_ENCRYPTION"); v {
	case "", "age":
		c.Encryption = EncryptionAge
	case "none":
		c.Encryption = EncryptionNone
	default:
		return nil, fmt.Errorf("invalid encryption mode %q (want \"age\" or \"none\")", v)
	}

	c.Recipients = lookupAll("agerecipients", "GIT_REMOTE_S3VAULT_AGE_RECIPIENTS")
	c.RecipientFiles = lookupAll("agerecipientsfile", "GIT_REMOTE_S3VAULT_AGE_RECIPIENTS_FILE")
	c.IdentityFiles = lookupAll("ageidentityfile", "GIT_REMOTE_S3VAULT_AGE_IDENTITY_FILE")

	return c, nil
}

// ValidateURL reports whether raw is a usable remote URL for this helper.
func ValidateURL(raw string) error {
	var c Config
	return c.parseURL(raw)
}

// parseURL accepts s3vault://bucket/prefix (and s3://bucket/prefix for
// installations that symlink the binary as git-remote-s3).
func (c *Config) parseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid remote URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "s3vault", "s3":
	default:
		return fmt.Errorf("unsupported URL scheme %q (want s3vault:// or s3://)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("remote URL %q is missing a bucket name", raw)
	}
	c.Bucket = u.Host
	c.Prefix = strings.Trim(u.Path, "/")
	return nil
}
