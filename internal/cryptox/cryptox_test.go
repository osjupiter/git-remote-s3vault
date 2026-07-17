package cryptox

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recips, err := ParseRecipients([]string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}

	plaintext := bytes.Repeat([]byte("git bundle payload "), 4096)
	var ciphertext bytes.Buffer
	if err := Encrypt(&ciphertext, bytes.NewReader(plaintext), recips); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext.Bytes(), []byte("git bundle payload")) {
		t.Fatal("ciphertext contains plaintext")
	}

	out, err := Decrypt(bytes.NewReader(ciphertext.Bytes()), []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestDecryptWithWrongIdentityFails(t *testing.T) {
	id1, _ := age.GenerateX25519Identity()
	id2, _ := age.GenerateX25519Identity()
	recips, _ := ParseRecipients([]string{id1.Recipient().String()})

	var ct bytes.Buffer
	if err := Encrypt(&ct, strings.NewReader("secret"), recips); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(bytes.NewReader(ct.Bytes()), []age.Identity{id2}); err == nil {
		t.Fatal("decryption with wrong identity should fail")
	}
}

func TestEncryptRequiresRecipients(t *testing.T) {
	if err := Encrypt(io.Discard, strings.NewReader("x"), nil); err == nil {
		t.Fatal("encrypt without recipients should fail")
	}
}

func TestParseRecipientsRejectsGarbage(t *testing.T) {
	if _, err := ParseRecipients([]string{"not-a-key"}); err == nil {
		t.Fatal("garbage recipient should be rejected")
	}
	// Comments and blanks are ignored.
	recips, err := ParseRecipients([]string{"# comment", "", "  "})
	if err != nil || len(recips) != 0 {
		t.Fatalf("recips=%v err=%v", recips, err)
	}
}

func TestLoadIdentityAndRecipientFiles(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()

	idFile := filepath.Join(dir, "identity.txt")
	os.WriteFile(idFile, []byte("# created by test\n"+id.String()+"\n"), 0o600)
	ids, err := LoadIdentityFiles([]string{idFile})
	if err != nil || len(ids) != 1 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}

	recFile := filepath.Join(dir, "recipients.txt")
	os.WriteFile(recFile, []byte("# team keys\n"+id.Recipient().String()+"\n"), 0o600)
	specs, err := LoadRecipientFiles([]string{recFile})
	if err != nil {
		t.Fatal(err)
	}
	recips, err := ParseRecipients(specs)
	if err != nil || len(recips) != 1 {
		t.Fatalf("recips=%v err=%v", recips, err)
	}
}
