package config

import "testing"

type fakeGit map[string][]string

func (f fakeGit) Get(key string) (string, bool) {
	vs := f[key]
	if len(vs) == 0 {
		return "", false
	}
	return vs[len(vs)-1], true
}

func (f fakeGit) GetAll(key string) []string { return f[key] }

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseURL(t *testing.T) {
	cases := []struct {
		url     string
		bucket  string
		prefix  string
		wantErr bool
	}{
		{"s3ee://my-bucket/team/repo", "my-bucket", "team/repo", false},
		{"s3ee://my-bucket", "my-bucket", "", false},
		{"s3ee://my-bucket/", "my-bucket", "", false},
		{"s3://other/deep/nested/path/", "other", "deep/nested/path", false},
		{"https://example.com/x", "", "", true},
		{"s3ee:///no-bucket", "", "", true},
	}
	for _, tc := range cases {
		c, err := load("origin", tc.url, fakeGit{}, env(nil), nil)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got %+v", tc.url, c)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.url, err)
			continue
		}
		if c.Bucket != tc.bucket || c.Prefix != tc.prefix {
			t.Errorf("%s: got bucket=%q prefix=%q, want %q %q", tc.url, c.Bucket, c.Prefix, tc.bucket, tc.prefix)
		}
	}
}

func TestEndpointAndPathStyleHeuristic(t *testing.T) {
	// Self-hosted endpoint → path style.
	c, err := load("origin", "s3://b/p", fakeGit{}, env(map[string]string{
		"AWS_ENDPOINT_URL": "http://127.0.0.1:9000",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "http://127.0.0.1:9000" {
		t.Errorf("endpoint = %q", c.Endpoint)
	}
	if !c.UsePathStyle {
		t.Error("self-hosted endpoint should default to path style")
	}

	// R2 and AWS endpoints → virtual-hosted style.
	for _, ep := range []string{"https://abc.r2.cloudflarestorage.com", "https://s3.eu-central-1.amazonaws.com", ""} {
		c, err := load("origin", "s3ee://b", fakeGit{}, env(map[string]string{
			"GIT_REMOTE_S3EE_ENDPOINT": ep,
		}), nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.UsePathStyle {
			t.Errorf("endpoint %q should not use path style", ep)
		}
	}

	// Default region.
	c, err = load("origin", "s3ee://b", fakeGit{}, env(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Region != "us-east-1" {
		t.Errorf("region = %q, want us-east-1", c.Region)
	}
}

func TestGitConfigPrecedence(t *testing.T) {
	git := fakeGit{
		"remote.origin.endpoint":   {"https://remote-scoped.example.com"},
		"s3ee.endpoint":            {"https://global.example.com"},
		"s3ee.agerecipients":       {"age1aaa", "age1bbb"},
		"remote.origin.encryption": {"none"},
	}
	c, err := load("origin", "s3ee://b", git, env(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "https://remote-scoped.example.com" {
		t.Errorf("endpoint = %q, want remote-scoped git config to win", c.Endpoint)
	}
	if len(c.Recipients) != 2 {
		t.Errorf("recipients = %v", c.Recipients)
	}
	if c.Encryption != EncryptionNone {
		t.Errorf("encryption = %q", c.Encryption)
	}

	// Env beats git config.
	c, err = load("origin", "s3ee://b", git, env(map[string]string{"GIT_REMOTE_S3EE_ENDPOINT": "https://from-env.example.com"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "https://from-env.example.com" {
		t.Errorf("endpoint = %q, want env to win", c.Endpoint)
	}
}

func TestSavedCredentialsResolution(t *testing.T) {
	stored := func(endpoint, bucket string) (string, string, bool) {
		if endpoint == "https://ep1.example.com" && bucket == "b" {
			return "stored-key", "stored-secret", true
		}
		return "", "", false
	}

	// Env is empty → saved credentials fill in.
	c, err := load("origin", "s3ee://b", fakeGit{}, env(map[string]string{
		"GIT_REMOTE_S3EE_ENDPOINT": "https://ep1.example.com",
	}), stored)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "stored-key" || c.SecretAccessKey != "stored-secret" {
		t.Errorf("saved credentials not used: %q/%q", c.AccessKeyID, c.SecretAccessKey)
	}

	// Env credentials win over the store.
	c, err = load("origin", "s3ee://b", fakeGit{}, env(map[string]string{
		"GIT_REMOTE_S3EE_ENDPOINT": "https://ep1.example.com",
		"AWS_ACCESS_KEY_ID":        "env-key",
		"AWS_SECRET_ACCESS_KEY":    "env-secret",
	}), stored)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "env-key" {
		t.Errorf("env should win over the store, got %q", c.AccessKeyID)
	}

	// No match in the store → left empty (storage.New then rejects the
	// connection with guidance; there is no AWS-chain fallback).
	c, err = load("origin", "s3ee://b", fakeGit{}, env(map[string]string{
		"GIT_REMOTE_S3EE_ENDPOINT": "https://unknown.example.com",
	}), stored)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "" {
		t.Errorf("expected empty credentials, got %q", c.AccessKeyID)
	}
}

func TestEncryptionDefaultsToAge(t *testing.T) {
	c, err := load("origin", "s3ee://b", fakeGit{}, env(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Encryption != EncryptionAge {
		t.Errorf("encryption = %q, want age by default", c.Encryption)
	}
	if _, err := load("origin", "s3ee://b", fakeGit{}, env(map[string]string{
		"GIT_REMOTE_S3EE_ENCRYPTION": "rot13",
	}), nil); err == nil {
		t.Error("invalid encryption mode should be rejected")
	}
}
