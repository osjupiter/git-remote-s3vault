// Package keyring implements sops-style envelope encryption for a remote.
//
// Each repository gets its own data-encryption key (DEK): an age X25519
// keypair generated on first use. Bundles are encrypted only to the DEK's
// public key. The DEK's secret half is stored in the bucket, wrapped
// (age-encrypted) once per member public key:
//
//	<prefix>/.keys/repo.pub          DEK public key (plaintext, safe)
//	<prefix>/.keys/dek/<label>.age   DEK secret wrapped to one member key
//	<prefix>/.keys/dek/<label>.pub   that member's public key (for listing)
//
// Granting access = wrapping the DEK to one more public key: a single
// small upload, no re-encryption of history. Revoking a slot removes
// future unwrap ability for that key, but a party who already unwrapped
// the DEK can still read until the DEK is rotated.
package keyring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-s3ee/internal/cryptox"
	"github.com/osjupiter/git-remote-s3ee/internal/storage"
)

const (
	repoPubName = "repo.pub"
	dekDirName  = "dek"
	// KeysDir is the reserved prefix; the helper must never treat objects
	// under it as ref bundles.
	KeysDir = ".keys"
	// RecoveryLabel is the conventional slot label for the repository's
	// recovery key.
	RecoveryLabel = "recovery"
)

// Keyring accesses the key material of one remote.
type Keyring struct {
	store  storage.Storage
	prefix string
}

// New returns a Keyring rooted at the remote's key prefix.
func New(store storage.Storage, prefix string) *Keyring {
	return &Keyring{store: store, prefix: prefix}
}

func (k *Keyring) key(parts ...string) string {
	all := append([]string{k.prefix, KeysDir}, parts...)
	return strings.TrimPrefix(path.Join(all...), "/")
}

// Slot is one wrapped copy of the DEK.
type Slot struct {
	Label     string
	Recipient string // public key the DEK is wrapped to ("" if unrecorded)
}

// DefaultLabel derives a stable slot label from a recipient string.
func DefaultLabel(recipientSpec string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(recipientSpec)))
	return hex.EncodeToString(sum[:])[:12]
}

// RepoRecipient returns the repository's public key, if the keyring exists.
func (k *Keyring) RepoRecipient(ctx context.Context) (age.Recipient, bool, error) {
	rc, err := k.store.Get(ctx, k.key(repoPubName))
	if err != nil {
		return nil, false, nil // treat as absent; Init or first push will create it
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 4096))
	if err != nil {
		return nil, false, err
	}
	r, err := age.ParseX25519Recipient(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, false, fmt.Errorf("corrupt %s: %w", k.key(repoPubName), err)
	}
	return r, true, nil
}

// Init generates a fresh DEK, publishes its public key, and wraps its
// secret to every given recipient spec. Fails if a keyring already exists.
func (k *Keyring) Init(ctx context.Context, recipientSpecs []string) (*age.X25519Identity, error) {
	if len(recipientSpecs) == 0 {
		return nil, fmt.Errorf("at least one public key is required to initialize the repository key")
	}
	if _, exists, err := k.RepoRecipient(ctx); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("repository key already exists")
	}
	dek, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	if err := k.SetRepoKey(ctx, dek); err != nil {
		return nil, err
	}
	for _, spec := range recipientSpecs {
		if err := k.Grant(ctx, dek, spec, ""); err != nil {
			return nil, err
		}
	}
	return dek, nil
}

// SetRepoKey publishes (or replaces, during rotation) the repository's
// public key.
func (k *Keyring) SetRepoKey(ctx context.Context, dek *age.X25519Identity) error {
	pub := dek.Recipient().String() + "\n"
	return k.store.Put(ctx, k.key(repoPubName), strings.NewReader(pub), int64(len(pub)))
}

// Grant wraps the DEK to one more public key. label defaults to a
// fingerprint of the recipient. Idempotent for the same label.
func (k *Keyring) Grant(ctx context.Context, dek *age.X25519Identity, recipientSpec, label string) error {
	recips, err := cryptox.ParseRecipients([]string{recipientSpec})
	if err != nil {
		return err
	}
	if len(recips) != 1 {
		return fmt.Errorf("expected exactly one recipient, got %d", len(recips))
	}
	if label == "" {
		label = DefaultLabel(recipientSpec)
	}
	if strings.ContainsAny(label, "/ \t\n") {
		return fmt.Errorf("invalid slot label %q", label)
	}

	var wrapped bytes.Buffer
	if err := cryptox.Encrypt(&wrapped, strings.NewReader(dek.String()+"\n"), recips); err != nil {
		return fmt.Errorf("wrapping repository key: %w", err)
	}
	if err := k.store.Put(ctx, k.key(dekDirName, label+".age"),
		bytes.NewReader(wrapped.Bytes()), int64(wrapped.Len())); err != nil {
		return err
	}
	spec := strings.TrimSpace(recipientSpec) + "\n"
	return k.store.Put(ctx, k.key(dekDirName, label+".pub"), strings.NewReader(spec), int64(len(spec)))
}

// Slots lists who currently holds a wrapped copy of the DEK.
func (k *Keyring) Slots(ctx context.Context) ([]Slot, error) {
	objs, err := k.store.List(ctx, k.key(dekDirName)+"/")
	if err != nil {
		return nil, err
	}
	slots := map[string]*Slot{}
	var order []string
	for _, o := range objs {
		base := path.Base(o.Key)
		switch {
		case strings.HasSuffix(base, ".age"):
			label := strings.TrimSuffix(base, ".age")
			if slots[label] == nil {
				slots[label] = &Slot{Label: label}
				order = append(order, label)
			}
		case strings.HasSuffix(base, ".pub"):
			label := strings.TrimSuffix(base, ".pub")
			rc, err := k.store.Get(ctx, o.Key)
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(rc, 4096))
			rc.Close()
			if slots[label] == nil {
				slots[label] = &Slot{Label: label}
				order = append(order, label)
			}
			slots[label].Recipient = strings.TrimSpace(string(data))
		}
	}
	var out []Slot
	for _, l := range order {
		out = append(out, *slots[l])
	}
	return out, nil
}

// Unwrap recovers the DEK by trying the given identities against every
// wrapped slot. Returns (nil, false, nil) when no slot matches.
func (k *Keyring) Unwrap(ctx context.Context, ids []age.Identity) (*age.X25519Identity, bool, error) {
	if len(ids) == 0 {
		return nil, false, nil
	}
	objs, err := k.store.List(ctx, k.key(dekDirName)+"/")
	if err != nil {
		return nil, false, err
	}
	for _, o := range objs {
		if !strings.HasSuffix(o.Key, ".age") {
			continue
		}
		rc, err := k.store.Get(ctx, o.Key)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if err != nil {
			continue
		}
		r, err := age.Decrypt(bytes.NewReader(data), ids...)
		if err != nil {
			continue // wrapped to someone else's key
		}
		plaintext, err := io.ReadAll(r)
		if err != nil {
			continue
		}
		parsed, err := age.ParseIdentities(bytes.NewReader(plaintext))
		if err != nil {
			return nil, false, fmt.Errorf("corrupt wrapped key %s: %w", o.Key, err)
		}
		for _, id := range parsed {
			if x, ok := id.(*age.X25519Identity); ok {
				return x, true, nil
			}
		}
	}
	return nil, false, nil
}

// Access resolves the DEK for the given identities: by unwrapping a slot,
// or by noticing that one of the identities IS the DEK (post-recovery).
func (k *Keyring) Access(ctx context.Context, ids []age.Identity) (*age.X25519Identity, bool, error) {
	dek, ok, err := k.Unwrap(ctx, ids)
	if err != nil || ok {
		return dek, ok, err
	}
	r, exists, err := k.RepoRecipient(ctx)
	if err != nil || !exists {
		return nil, false, err
	}
	if xr, okR := r.(*age.X25519Recipient); okR {
		for _, id := range ids {
			if x, okX := id.(*age.X25519Identity); okX && x.Recipient().String() == xr.String() {
				return x, true, nil
			}
		}
	}
	return nil, false, nil
}

// Revoke deletes a slot by label or by recipient public key. Returns the
// removed slot. NOTE: true revocation also requires rotating the DEK.
func (k *Keyring) Revoke(ctx context.Context, labelOrRecipient string) (*Slot, error) {
	slots, err := k.Slots(ctx)
	if err != nil {
		return nil, err
	}
	needle := strings.TrimSpace(labelOrRecipient)
	for _, s := range slots {
		if s.Label != needle && s.Recipient != needle {
			continue
		}
		if err := k.store.Delete(ctx, k.key(dekDirName, s.Label+".age")); err != nil {
			return nil, err
		}
		if err := k.store.Delete(ctx, k.key(dekDirName, s.Label+".pub")); err != nil {
			return nil, err
		}
		return &s, nil
	}
	return nil, fmt.Errorf("no key slot matches %q", labelOrRecipient)
}
