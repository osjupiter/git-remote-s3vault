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

	if _, ok := Lookup("https://x.example.com", "repo1"); ok {
		t.Fatal("lookup on a missing file must miss")
	}

	path, section, err := Save("https://x.example.com", "repo1",
		Credentials{AccessKeyID: "AKIA1", SecretAccessKey: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if section != "endpoint:https://x.example.com bucket:repo1" {
		t.Errorf("section = %q", section)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("credentials file mode = %v, want 0600", st.Mode().Perm())
	}

	c, ok := Lookup("https://x.example.com", "repo1")
	if !ok || c.AccessKeyID != "AKIA1" || c.SecretAccessKey != "s3cret" {
		t.Fatalf("lookup = %+v, %v", c, ok)
	}
	if _, ok := Lookup("https://other.example.com", "repo1"); ok {
		t.Fatal("other endpoints must not match")
	}
	if _, ok := Lookup("https://x.example.com", "other-bucket"); ok {
		t.Fatal("other buckets must not match")
	}
}

func TestEndpointNormalizationAndAWSEntries(t *testing.T) {
	isolate(t)
	if _, section, err := Save("http://127.0.0.1:9000/", "test",
		Credentials{AccessKeyID: "minio", SecretAccessKey: "minio123"}); err != nil {
		t.Fatal(err)
	} else if section != "endpoint:http://127.0.0.1:9000 bucket:test" {
		t.Errorf("section = %q (trailing slash should be normalized)", section)
	}
	// Lookup with and without the trailing slash both hit.
	for _, ep := range []string{"http://127.0.0.1:9000", "http://127.0.0.1:9000/"} {
		if c, ok := Lookup(ep, "test"); !ok || c.AccessKeyID != "minio" {
			t.Errorf("lookup(%q) = %+v, %v", ep, c, ok)
		}
	}

	// AWS S3 (no endpoint) gets a bare bucket section.
	if _, section, err := Save("", "aws-bucket", Credentials{AccessKeyID: "k", SecretAccessKey: "s"}); err != nil {
		t.Fatal(err)
	} else if section != "bucket:aws-bucket" {
		t.Errorf("section = %q", section)
	}
	if c, ok := Lookup("", "aws-bucket"); !ok || c.AccessKeyID != "k" {
		t.Errorf("aws lookup = %+v, %v", c, ok)
	}

	if _, _, err := Save("https://e", "", Credentials{AccessKeyID: "x", SecretAccessKey: "y"}); err == nil {
		t.Error("saving without a bucket must fail")
	}
	if _, _, err := Save("https://e", "b", Credentials{AccessKeyID: "x"}); err == nil {
		t.Error("saving without a secret must fail")
	}
}

func TestNoCrossEntryFallback(t *testing.T) {
	dir := isolate(t)
	path := filepath.Join(dir, "git-remote-s3vault", "credentials")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte(
		"[endpoint:http://127.0.0.1:9000]\naccess_key_id = wide\nsecret_access_key = s\n"), 0o600)

	if c, ok := Lookup("http://127.0.0.1:9000", "repo"); ok {
		t.Fatalf("endpoint-wide entry must not match a bucket lookup: %+v", c)
	}
}

func TestUpsertPreservesOtherSections(t *testing.T) {
	isolate(t)
	ep := "https://x.example.com"
	if _, _, err := Save(ep, "repo-a", Credentials{AccessKeyID: "k1", SecretAccessKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Save(ep, "repo-b", Credentials{AccessKeyID: "k2", SecretAccessKey: "s2"}); err != nil {
		t.Fatal(err)
	}
	// Rotate repo-a's token.
	if _, _, err := Save(ep, "repo-a", Credentials{AccessKeyID: "k1-new", SecretAccessKey: "s1-new"}); err != nil {
		t.Fatal(err)
	}

	ca, oka := Lookup(ep, "repo-a")
	cb, okb := Lookup(ep, "repo-b")
	if !oka || ca.AccessKeyID != "k1-new" {
		t.Errorf("repo-a = %+v, %v", ca, oka)
	}
	if !okb || cb.AccessKeyID != "k2" {
		t.Errorf("repo-b must be preserved: %+v, %v", cb, okb)
	}
}

func TestFixesLoosePermissions(t *testing.T) {
	dir := isolate(t)
	path := filepath.Join(dir, "git-remote-s3vault", "credentials")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("[bucket:x]\naccess_key_id = k\nsecret_access_key = s\n"), 0o644)

	if _, _, err := Save("", "y", Credentials{AccessKeyID: "k2", SecretAccessKey: "s2"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("Save should tighten permissions, got %v", st.Mode().Perm())
	}
	// Pre-existing content survived the rewrite.
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "bucket:x") {
		t.Errorf("existing section lost:\n%s", data)
	}
}
