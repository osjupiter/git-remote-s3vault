package credstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func TestSaveLookupRoundtrip(t *testing.T) {
	isolate(t)

	if _, ok := Lookup("acct1", "", ""); ok {
		t.Fatal("lookup on a missing file must miss")
	}

	path, section, err := Save("acct1", "https://acct1.r2.cloudflarestorage.com", "",
		Credentials{AccessKeyID: "AKIA1", SecretAccessKey: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if section != "account:acct1" {
		t.Errorf("section = %q, want the account to win over the endpoint", section)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("credentials file mode = %v, want 0600", st.Mode().Perm())
	}

	c, ok := Lookup("acct1", "", "")
	if !ok || c.AccessKeyID != "AKIA1" || c.SecretAccessKey != "s3cret" {
		t.Fatalf("lookup = %+v, %v", c, ok)
	}
	if _, ok := Lookup("other", "", ""); ok {
		t.Fatal("other accounts must not match")
	}
}

func TestEndpointKeyedEntries(t *testing.T) {
	isolate(t)
	if _, section, err := Save("", "http://127.0.0.1:9000/", "", Credentials{AccessKeyID: "minio", SecretAccessKey: "minio123"}); err != nil {
		t.Fatal(err)
	} else if section != "endpoint:http://127.0.0.1:9000" {
		t.Errorf("section = %q (trailing slash should be normalized)", section)
	}

	// Lookup with and without the trailing slash both hit.
	for _, ep := range []string{"http://127.0.0.1:9000", "http://127.0.0.1:9000/"} {
		if c, ok := Lookup("", ep, ""); !ok || c.AccessKeyID != "minio" {
			t.Errorf("lookup(%q) = %+v, %v", ep, c, ok)
		}
	}

	if _, _, err := Save("", "", "", Credentials{AccessKeyID: "x", SecretAccessKey: "y"}); err == nil {
		t.Error("saving without account or endpoint must fail")
	}
	if _, _, err := Save("a", "", "", Credentials{AccessKeyID: "x"}); err == nil {
		t.Error("saving without a secret must fail")
	}
}

func TestBucketScopedEntriesWinOverAccountWide(t *testing.T) {
	isolate(t)
	// Account-wide entry plus one bucket-scoped token per repo.
	if _, _, err := Save("acct1", "", "", Credentials{AccessKeyID: "wide", SecretAccessKey: "s"}); err != nil {
		t.Fatal(err)
	}
	_, section, err := Save("acct1", "", "repo-a", Credentials{AccessKeyID: "token-a", SecretAccessKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if section != "account:acct1 bucket:repo-a" {
		t.Errorf("section = %q", section)
	}

	// The bucket-scoped token wins for its bucket...
	if c, ok := Lookup("acct1", "", "repo-a"); !ok || c.AccessKeyID != "token-a" {
		t.Errorf("repo-a lookup = %+v, %v (want the bucket-scoped token)", c, ok)
	}
	// ...while other buckets fall back to the account-wide entry.
	if c, ok := Lookup("acct1", "", "repo-b"); !ok || c.AccessKeyID != "wide" {
		t.Errorf("repo-b lookup = %+v, %v (want the account-wide fallback)", c, ok)
	}

	// Endpoint-keyed bucket entries work the same way.
	if _, _, err := Save("", "http://127.0.0.1:9000", "repo-c", Credentials{AccessKeyID: "token-c", SecretAccessKey: "s"}); err != nil {
		t.Fatal(err)
	}
	if c, ok := Lookup("", "http://127.0.0.1:9000", "repo-c"); !ok || c.AccessKeyID != "token-c" {
		t.Errorf("repo-c lookup = %+v, %v", c, ok)
	}
}

func TestUpsertPreservesOtherSections(t *testing.T) {
	isolate(t)
	if _, _, err := Save("acct1", "", "", Credentials{AccessKeyID: "k1", SecretAccessKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Save("acct2", "", "", Credentials{AccessKeyID: "k2", SecretAccessKey: "s2"}); err != nil {
		t.Fatal(err)
	}
	// Rotate acct1's key.
	if _, _, err := Save("acct1", "", "", Credentials{AccessKeyID: "k1-new", SecretAccessKey: "s1-new"}); err != nil {
		t.Fatal(err)
	}

	c1, ok1 := Lookup("acct1", "", "")
	c2, ok2 := Lookup("acct2", "", "")
	if !ok1 || c1.AccessKeyID != "k1-new" {
		t.Errorf("acct1 = %+v, %v", c1, ok1)
	}
	if !ok2 || c2.AccessKeyID != "k2" {
		t.Errorf("acct2 must be preserved: %+v, %v", c2, ok2)
	}
}

func TestFixesLoosePermissions(t *testing.T) {
	dir := isolate(t)
	path := filepath.Join(dir, "git-remote-r2", "credentials")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("[account:a]\naccess_key_id = k\nsecret_access_key = s\n"), 0o644)

	if _, _, err := Save("b", "", "", Credentials{AccessKeyID: "k2", SecretAccessKey: "s2"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("Save should tighten permissions, got %v", st.Mode().Perm())
	}
	// Pre-existing content survived the rewrite.
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "account:a") {
		t.Errorf("existing section lost:\n%s", data)
	}
}
