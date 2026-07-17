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
		{"r2://my-bucket/team/repo", "my-bucket", "team/repo", false},
		{"r2://my-bucket", "my-bucket", "", false},
		{"r2://my-bucket/", "my-bucket", "", false},
		{"s3://other/deep/nested/path/", "other", "deep/nested/path", false},
		{"https://example.com/x", "", "", true},
		{"r2:///no-bucket", "", "", true},
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

func TestR2EndpointDerivation(t *testing.T) {
	c, err := load("origin", "r2://b/p", fakeGit{}, env(map[string]string{
		"R2_ACCOUNT_ID": "abc123",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://abc123.r2.cloudflarestorage.com"; c.Endpoint != want {
		t.Errorf("endpoint = %q, want %q", c.Endpoint, want)
	}
	if c.Region != "auto" {
		t.Errorf("region = %q, want auto", c.Region)
	}
	if c.UsePathStyle {
		t.Error("R2 should not use path style by default")
	}
}

func TestExplicitEndpointWinsAndPathStyleHeuristic(t *testing.T) {
	c, err := load("origin", "s3://b/p", fakeGit{}, env(map[string]string{
		"R2_ACCOUNT_ID":    "abc123",
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
}

func TestGitConfigPrecedence(t *testing.T) {
	git := fakeGit{
		"remote.origin.accountid":  {"remote-scoped"},
		"r2.accountid":             {"global"},
		"r2.agerecipients":         {"age1aaa", "age1bbb"},
		"remote.origin.encryption": {"none"},
	}
	c, err := load("origin", "r2://b", git, env(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccountID != "remote-scoped" {
		t.Errorf("accountID = %q, want remote-scoped git config to win", c.AccountID)
	}
	if len(c.Recipients) != 2 {
		t.Errorf("recipients = %v", c.Recipients)
	}
	if c.Encryption != EncryptionNone {
		t.Errorf("encryption = %q", c.Encryption)
	}

	// Env beats git config.
	c, err = load("origin", "r2://b", git, env(map[string]string{"R2_ACCOUNT_ID": "from-env"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccountID != "from-env" {
		t.Errorf("accountID = %q, want env to win", c.AccountID)
	}
}

func TestSavedCredentialsResolution(t *testing.T) {
	stored := func(account, endpoint, bucket string) (string, string, bool) {
		if account == "acct1" {
			return "stored-key", "stored-secret", true
		}
		return "", "", false
	}

	// Env is empty → saved credentials fill in.
	c, err := load("origin", "r2://b", fakeGit{}, env(map[string]string{
		"R2_ACCOUNT_ID": "acct1",
	}), stored)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "stored-key" || c.SecretAccessKey != "stored-secret" {
		t.Errorf("saved credentials not used: %q/%q", c.AccessKeyID, c.SecretAccessKey)
	}

	// Env credentials win over the store.
	c, err = load("origin", "r2://b", fakeGit{}, env(map[string]string{
		"R2_ACCOUNT_ID":         "acct1",
		"AWS_ACCESS_KEY_ID":     "env-key",
		"AWS_SECRET_ACCESS_KEY": "env-secret",
	}), stored)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "env-key" {
		t.Errorf("env should win over the store, got %q", c.AccessKeyID)
	}

	// No match in the store → left empty for the AWS default chain.
	c, err = load("origin", "r2://b", fakeGit{}, env(map[string]string{
		"R2_ACCOUNT_ID": "unknown-acct",
	}), stored)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "" {
		t.Errorf("expected empty credentials, got %q", c.AccessKeyID)
	}
}

func TestEncryptionDefaultsToAge(t *testing.T) {
	c, err := load("origin", "r2://b", fakeGit{}, env(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Encryption != EncryptionAge {
		t.Errorf("encryption = %q, want age by default", c.Encryption)
	}
	if _, err := load("origin", "r2://b", fakeGit{}, env(map[string]string{
		"GIT_REMOTE_R2_ENCRYPTION": "rot13",
	}), nil); err == nil {
		t.Error("invalid encryption mode should be rejected")
	}
}
