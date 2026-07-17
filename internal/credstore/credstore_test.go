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

	if _, ok := Lookup("acct1", "", "repo1"); ok {
		t.Fatal("lookup on a missing file must miss")
	}

	path, section, err := Save("acct1", "https://acct1.r2.cloudflarestorage.com", "repo1",
		Credentials{AccessKeyID: "AKIA1", SecretAccessKey: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if section != "account:acct1 bucket:repo1" {
		t.Errorf("section = %q, want account-qualified bucket key", section)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("credentials file mode = %v, want 0600", st.Mode().Perm())
	}

	c, ok := Lookup("acct1", "", "repo1")
	if !ok || c.AccessKeyID != "AKIA1" || c.SecretAccessKey != "s3cret" {
		t.Fatalf("lookup = %+v, %v", c, ok)
	}
	if _, ok := Lookup("other", "", "repo1"); ok {
		t.Fatal("other accounts must not match")
	}
	if _, ok := Lookup("acct1", "", "other-bucket"); ok {
		t.Fatal("other buckets must not match")
	}
}

func TestNoFallbackToWiderEntries(t *testing.T) {
	dir := isolate(t)
	// A hand-written account-wide section is ignored: entries are strictly
	// per-bucket.
	path := filepath.Join(dir, "git-remote-r2", "credentials")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte(
		"[account:acct1]\naccess_key_id = wide\nsecret_access_key = s\n"+
			"[endpoint:http://127.0.0.1:9000]\naccess_key_id = wide2\nsecret_access_key = s\n"), 0o600)

	if c, ok := Lookup("acct1", "", "repo"); ok {
		t.Fatalf("account-wide entry must not match a bucket lookup: %+v", c)
	}
	if c, ok := Lookup("", "http://127.0.0.1:9000", "repo"); ok {
		t.Fatalf("endpoint-wide entry must not match a bucket lookup: %+v", c)
	}
}

func TestEndpointKeyedEntries(t *testing.T) {
	isolate(t)
	if _, section, err := Save("", "http://127.0.0.1:9000/", "test",
		Credentials{AccessKeyID: "minio", SecretAccessKey: "minio123"}); err != nil {
		t.Fatal(err)
	} else if section != "endpoint:http://127.0.0.1:9000 bucket:test" {
		t.Errorf("section = %q (trailing slash should be normalized)", section)
	}

	// Lookup with and without the trailing slash both hit.
	for _, ep := range []string{"http://127.0.0.1:9000", "http://127.0.0.1:9000/"} {
		if c, ok := Lookup("", ep, "test"); !ok || c.AccessKeyID != "minio" {
			t.Errorf("lookup(%q) = %+v, %v", ep, c, ok)
		}
	}

	if _, _, err := Save("acct", "", "", Credentials{AccessKeyID: "x", SecretAccessKey: "y"}); err == nil {
		t.Error("saving without a bucket must fail")
	}
	if _, _, err := Save("a", "", "b", Credentials{AccessKeyID: "x"}); err == nil {
		t.Error("saving without a secret must fail")
	}
}

func TestUpsertPreservesOtherSections(t *testing.T) {
	isolate(t)
	if _, _, err := Save("acct1", "", "repo-a", Credentials{AccessKeyID: "k1", SecretAccessKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Save("acct1", "", "repo-b", Credentials{AccessKeyID: "k2", SecretAccessKey: "s2"}); err != nil {
		t.Fatal(err)
	}
	// Rotate repo-a's token.
	if _, _, err := Save("acct1", "", "repo-a", Credentials{AccessKeyID: "k1-new", SecretAccessKey: "s1-new"}); err != nil {
		t.Fatal(err)
	}

	ca, oka := Lookup("acct1", "", "repo-a")
	cb, okb := Lookup("acct1", "", "repo-b")
	if !oka || ca.AccessKeyID != "k1-new" {
		t.Errorf("repo-a = %+v, %v", ca, oka)
	}
	if !okb || cb.AccessKeyID != "k2" {
		t.Errorf("repo-b must be preserved: %+v, %v", cb, okb)
	}
}

func TestFixesLoosePermissions(t *testing.T) {
	dir := isolate(t)
	path := filepath.Join(dir, "git-remote-r2", "credentials")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("[account:a bucket:x]\naccess_key_id = k\nsecret_access_key = s\n"), 0o644)

	if _, _, err := Save("b", "", "y", Credentials{AccessKeyID: "k2", SecretAccessKey: "s2"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("Save should tighten permissions, got %v", st.Mode().Perm())
	}
	// Pre-existing content survived the rewrite.
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "account:a bucket:x") {
		t.Errorf("existing section lost:\n%s", data)
	}
}
