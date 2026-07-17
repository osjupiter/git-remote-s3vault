// Package config resolves all settings for the remote helper from the
// remote URL, git configuration, and environment variables.
//
// Precedence (highest first): environment variables, remote-scoped git
// config (remote.<name>.*), global git config (r2.*), built-in defaults.
package config

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/osjupiter/git-remote-r2/internal/credstore"
)

// EncryptionMode selects how bundles are protected before upload.
type EncryptionMode string

const (
	// EncryptionAge encrypts bundles with age before upload (default).
	EncryptionAge EncryptionMode = "age"
	// EncryptionNone uploads plaintext bundles. Must be opted into explicitly.
	EncryptionNone EncryptionMode = "none"
)

// Config holds everything the helper needs to talk to the backend.
type Config struct {
	RemoteName string
	RawURL     string

	Bucket string
	Prefix string // key prefix inside the bucket, no leading/trailing slash

	// Backend endpoint resolution.
	AccountID    string // Cloudflare account ID; derives the R2 endpoint
	Endpoint     string // explicit endpoint URL; wins over AccountID
	Region       string
	UsePathStyle bool

	// Static credentials override (falls back to the AWS default chain).
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

// CredentialLookup finds stored credentials for an account ID or endpoint.
// It exists as an injection point so the config package stays decoupled
// from the on-disk store (and testable without touching the filesystem).
type CredentialLookup func(accountID, endpoint string) (keyID, secret string, ok bool)

// Load resolves the full configuration for a remote, including saved
// credentials from ~/.config/git-remote-r2/credentials.
func Load(remoteName, rawURL string) (*Config, error) {
	return load(remoteName, rawURL, execGit{}, os.Getenv, func(account, endpoint string) (string, string, bool) {
		c, ok := credstore.Lookup(account, endpoint)
		return c.AccessKeyID, c.SecretAccessKey, ok
	})
}

func load(remoteName, rawURL string, git GitConfigReader, getenv func(string) string, creds CredentialLookup) (*Config, error) {
	c := &Config{RemoteName: remoteName, RawURL: rawURL, Encryption: EncryptionAge}

	if err := c.parseURL(rawURL); err != nil {
		return nil, err
	}

	// lookup returns the first non-empty value among env names, then
	// remote-scoped git config, then global r2.* git config.
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
		if v, ok := git.Get("r2." + gitKey); ok && v != "" {
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
		return git.GetAll("r2." + gitKey)
	}

	c.AccountID = lookup("accountid", "GIT_REMOTE_R2_ACCOUNT_ID", "R2_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID", "CF_ACCOUNT_ID")
	c.Endpoint = lookup("endpoint", "GIT_REMOTE_R2_ENDPOINT", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL")
	c.Region = lookup("region", "GIT_REMOTE_R2_REGION", "AWS_REGION", "AWS_DEFAULT_REGION")

	c.AccessKeyID = firstNonEmpty(getenv("R2_ACCESS_KEY_ID"), getenv("AWS_ACCESS_KEY_ID"))
	c.SecretAccessKey = firstNonEmpty(getenv("R2_SECRET_ACCESS_KEY"), getenv("AWS_SECRET_ACCESS_KEY"))
	c.SessionToken = getenv("AWS_SESSION_TOKEN")

	if c.Endpoint == "" && c.AccountID != "" {
		c.Endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", c.AccountID)
	}
	// Saved credentials fill the gap between env vars (which win) and the
	// AWS default chain (which storage falls back to when these are empty).
	if c.AccessKeyID == "" && creds != nil {
		if id, secret, ok := creds(c.AccountID, c.Endpoint); ok {
			c.AccessKeyID, c.SecretAccessKey = id, secret
		}
	}
	if c.Region == "" {
		if c.isR2() {
			c.Region = "auto"
		} else {
			c.Region = "us-east-1"
		}
	}

	switch v := lookup("usepathstyle", "GIT_REMOTE_R2_PATH_STYLE"); v {
	case "true", "1", "yes", "on":
		c.UsePathStyle = true
	case "false", "0", "no", "off":
		c.UsePathStyle = false
	case "":
		// Path-style is required by MinIO and most self-hosted S3
		// implementations; virtual-hosted style is the norm for R2 and AWS.
		c.UsePathStyle = c.Endpoint != "" && !c.isR2() && !strings.Contains(c.Endpoint, "amazonaws.com")
	default:
		return nil, fmt.Errorf("invalid usepathstyle value %q", v)
	}

	switch v := lookup("encryption", "GIT_REMOTE_R2_ENCRYPTION"); v {
	case "", "age":
		c.Encryption = EncryptionAge
	case "none":
		c.Encryption = EncryptionNone
	default:
		return nil, fmt.Errorf("invalid encryption mode %q (want \"age\" or \"none\")", v)
	}

	c.Recipients = lookupAll("agerecipients", "GIT_REMOTE_R2_AGE_RECIPIENTS")
	c.RecipientFiles = lookupAll("agerecipientsfile", "GIT_REMOTE_R2_AGE_RECIPIENTS_FILE")
	c.IdentityFiles = lookupAll("ageidentityfile", "GIT_REMOTE_R2_AGE_IDENTITY_FILE")

	return c, nil
}

// ValidateURL reports whether raw is a usable remote URL for this helper.
func ValidateURL(raw string) error {
	var c Config
	return c.parseURL(raw)
}

// parseURL accepts r2://bucket/prefix and s3://bucket/prefix.
func (c *Config) parseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid remote URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "r2", "s3":
	default:
		return fmt.Errorf("unsupported URL scheme %q (want r2:// or s3://)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("remote URL %q is missing a bucket name", raw)
	}
	c.Bucket = u.Host
	c.Prefix = strings.Trim(u.Path, "/")
	return nil
}

func (c *Config) isR2() bool {
	return strings.Contains(c.Endpoint, ".r2.cloudflarestorage.com")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
