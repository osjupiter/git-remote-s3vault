// Package snapshot implements the repository state record: one small
// object per data generation holding the complete ref table, HEAD, and
// the kopia object ID of the single all-refs bundle.
//
//	<prefix>/state-<gen>   age-encrypted JSON (plaintext in encryption=none
//	                       mode), updated with ETag compare-and-swap
//
// Because every push replaces the whole record atomically, multi-ref
// pushes are atomic and concurrent pushes lose cleanly (retryable 412)
// instead of racing per ref.
package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-s3vault/internal/cryptox"
	"github.com/osjupiter/git-remote-s3vault/internal/storage"
)

// State is one complete snapshot of the remote repository.
type State struct {
	Refs   map[string]string `json:"refs"`   // refname -> sha
	Head   string            `json:"head"`   // symbolic HEAD target ("" = unset)
	Bundle string            `json:"bundle"` // kopia object ID of the all-refs bundle
}

// ErrConcurrentUpdate is returned by Save when the state changed since it
// was loaded — someone else pushed. The caller fetches and retries.
var ErrConcurrentUpdate = errors.New("concurrent push detected: the remote changed since it was read")

// Key returns the storage key of a generation's state object.
func Key(prefix, gen string) string {
	return strings.TrimPrefix(path.Join(prefix, "state-"+gen), "/")
}

// Load reads the state for a generation. dek == nil means plaintext mode.
// A missing state object yields (nil, "", nil) — the remote is either
// empty or still in the pre-snapshot per-ref format.
func Load(ctx context.Context, st storage.Storage, prefix, gen string, dek *age.X25519Identity) (*State, string, error) {
	k := Key(prefix, gen)
	etag, err := st.ETag(ctx, k)
	if err != nil {
		return nil, "", err
	}
	if etag == "" {
		return nil, "", nil
	}
	rc, err := st.Get(ctx, k)
	if err != nil {
		return nil, "", fmt.Errorf("reading state: %w", err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, 16<<20))
	if err != nil {
		return nil, "", err
	}

	var jsonBytes []byte
	if dek != nil {
		plain, err := cryptox.Decrypt(bytes.NewReader(raw), []age.Identity{dek})
		if err != nil {
			return nil, "", fmt.Errorf("decrypting state (is your key granted access?): %w", err)
		}
		if jsonBytes, err = io.ReadAll(plain); err != nil {
			return nil, "", err
		}
	} else {
		jsonBytes = raw
	}

	var s State
	if err := json.Unmarshal(jsonBytes, &s); err != nil {
		return nil, "", fmt.Errorf("corrupt state object: %w", err)
	}
	if s.Refs == nil {
		s.Refs = map[string]string{}
	}
	return &s, etag, nil
}

// Save writes the state with a compare-and-swap against expectETag
// ("" = the state object must not exist yet). recipient encrypts the
// record (nil = plaintext mode). On backends without conditional writes
// it degrades to a plain write.
func Save(ctx context.Context, st storage.Storage, prefix, gen string, s *State, recipient age.Recipient, expectETag string) error {
	jsonBytes, err := json.Marshal(s)
	if err != nil {
		return err
	}
	payload := jsonBytes
	if recipient != nil {
		var enc bytes.Buffer
		if err := cryptox.Encrypt(&enc, bytes.NewReader(jsonBytes), []age.Recipient{recipient}); err != nil {
			return fmt.Errorf("encrypting state: %w", err)
		}
		payload = enc.Bytes()
	}

	k := Key(prefix, gen)
	err = st.PutIf(ctx, k, bytes.NewReader(payload), int64(len(payload)), expectETag)
	if errors.Is(err, storage.ErrPreconditionFailed) {
		return ErrConcurrentUpdate
	}
	if errors.Is(err, storage.ErrConditionalUnsupported) {
		return st.Put(ctx, k, bytes.NewReader(payload), int64(len(payload)))
	}
	return err
}

// Delete removes a generation's state object (rotation cleanup).
func Delete(ctx context.Context, st storage.Storage, prefix, gen string) error {
	return st.Delete(ctx, Key(prefix, gen))
}
