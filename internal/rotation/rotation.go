// Package rotation implements full key rotation: re-encrypting the entire
// remote under a brand-new DEK (and thus a brand-new kopia master key),
// blue/green style.
//
//	<prefix>/.keys/generation      pointer to the active data generation
//	<prefix>/data/                 generation A (current)
//	<prefix>/data2/                generation B (being built)
//	<prefix>/.keys/rotation-next.age  staged new DEK, wrapped to the OLD
//	                                  repository key — makes a crashed
//	                                  build resumable with the same DEK
//
// The phases are individually idempotent and the only atomic step is one
// small pointer write:
//
//	Build      copy every ref's bundle from the current generation into
//	           the next one (kopia dedup makes re-runs incremental);
//	           the remote stays fully usable on the current generation
//	RewrapKeys wrap the new DEK for every existing member slot and the
//	           recovery key, update repo.pub
//	Flip       write the generation pointer (the atomic switch)
//	Cleanup    delete the old generation's objects and the staged DEK
//
// Interrupting before Flip leaves the remote untouched; interrupting
// after Flip leaves it fully working on the new generation with only
// garbage to sweep, which the next rotation (or a re-run) removes.
package rotation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-s3vault/internal/config"
	"github.com/osjupiter/git-remote-s3vault/internal/cryptox"
	"github.com/osjupiter/git-remote-s3vault/internal/keyring"
	"github.com/osjupiter/git-remote-s3vault/internal/kopiax"
	"github.com/osjupiter/git-remote-s3vault/internal/storage"
)

const stagedDEKName = ".keys/rotation-next.age"

// Rotator drives one full rotation.
type Rotator struct {
	cfg   *config.Config
	store storage.Storage
	kr    *keyring.Keyring
	out   io.Writer

	dekOld *age.X25519Identity // nil in plaintext mode
	dekNew *age.X25519Identity // nil in plaintext mode

	CurGen  string
	NextGen string

	pointerETag string // generation pointer's ETag at start ("" = absent)
}

// New prepares a rotation: resolves generations and loads (or creates and
// stages) the next DEK so that an interrupted rotation resumes with the
// same key.
func New(ctx context.Context, cfg *config.Config, store storage.Storage, dekOld *age.X25519Identity, out io.Writer) (*Rotator, error) {
	r := &Rotator{
		cfg:    cfg,
		store:  store,
		kr:     keyring.New(store, cfg.Prefix),
		out:    out,
		dekOld: dekOld,
	}
	r.CurGen, r.pointerETag = kopiax.CurrentGenerationInfo(ctx, store, cfg.Prefix)
	r.NextGen = kopiax.NextGeneration(r.CurGen)

	if cfg.Encryption == config.EncryptionNone {
		return r, nil // plaintext: rotation degenerates to a repack
	}
	if dekOld == nil {
		return nil, fmt.Errorf("rotation requires the current repository key")
	}
	dekNew, err := r.loadOrStageNextDEK(ctx)
	if err != nil {
		return nil, err
	}
	r.dekNew = dekNew
	return r, nil
}

func (r *Rotator) key(name string) string {
	return strings.TrimPrefix(path.Join(r.cfg.Prefix, name), "/")
}

func (r *Rotator) logf(format string, args ...any) {
	fmt.Fprintf(r.out, format+"\n", args...)
}

// loadOrStageNextDEK reuses a previously staged next-DEK (resume case) or
// generates and stages a fresh one, wrapped to the OLD repository key so
// only current members can read it.
func (r *Rotator) loadOrStageNextDEK(ctx context.Context) (*age.X25519Identity, error) {
	if rc, err := r.store.Get(ctx, r.key(stagedDEKName)); err == nil {
		data, rerr := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if rerr == nil {
			if plain, derr := cryptox.Decrypt(bytes.NewReader(data), []age.Identity{r.dekOld}); derr == nil {
				text, _ := io.ReadAll(plain)
				if ids, perr := age.ParseIdentities(bytes.NewReader(text)); perr == nil {
					for _, id := range ids {
						if x, ok := id.(*age.X25519Identity); ok {
							r.logf("resuming rotation with the previously staged key")
							return x, nil
						}
					}
				}
			}
		}
		r.logf("warning: ignoring unreadable staged rotation key; starting fresh")
	}

	dekNew, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	var wrapped bytes.Buffer
	if err := cryptox.Encrypt(&wrapped, strings.NewReader(dekNew.String()+"\n"),
		[]age.Recipient{r.dekOld.Recipient()}); err != nil {
		return nil, fmt.Errorf("staging next key: %w", err)
	}
	if err := r.store.Put(ctx, r.key(stagedDEKName),
		bytes.NewReader(wrapped.Bytes()), int64(wrapped.Len())); err != nil {
		return nil, err
	}
	return dekNew, nil
}

func (r *Rotator) passwords() (oldPW, newPW string) {
	if r.cfg.Encryption == config.EncryptionNone {
		return kopiax.PlaintextPassword, kopiax.PlaintextPassword
	}
	return r.dekOld.String(), r.dekNew.String()
}

// SweepStaleGenerations removes leftovers of generations other than the
// active one AND the one being built (post-Flip crash debris).
func (r *Rotator) SweepStaleGenerations(ctx context.Context) error {
	objs, err := r.store.List(ctx, r.key("")+"/")
	if err != nil {
		return err
	}
	deleted := map[string]int{}
	for _, o := range objs {
		rel := strings.TrimPrefix(o.Key, r.key("")+"/")
		gen, _, found := strings.Cut(rel, "/")
		if !found || !strings.HasPrefix(gen, "data") || gen == r.CurGen || gen == r.NextGen {
			continue
		}
		if err := r.store.Delete(ctx, o.Key); err != nil {
			return fmt.Errorf("sweeping stale generation %s: %w", gen, err)
		}
		deleted[gen]++
	}
	for gen, n := range deleted {
		r.logf("swept stale generation %s (%d objects)", gen, n)
	}
	return nil
}

// Build copies every ref (and HEAD) from the current generation into the
// next one, re-encrypted under the new DEK. Re-runs are incremental
// thanks to kopia deduplication. Loops until the source refs are stable.
func (r *Rotator) Build(ctx context.Context) error {
	oldPW, newPW := r.passwords()
	src, err := kopiax.Open(ctx, r.cfg, oldPW, r.CurGen, false)
	if err != nil {
		return fmt.Errorf("opening current generation: %w", err)
	}
	defer src.Close(ctx)
	dst, err := kopiax.Open(ctx, r.cfg, newPW, r.NextGen, true)
	if err != nil {
		return fmt.Errorf("opening next generation: %w", err)
	}
	defer dst.Close(ctx)

	copied := map[string]string{} // refname -> sha copied so far
	for round := 1; ; round++ {
		refs, err := src.Refs(ctx)
		if err != nil {
			return err
		}
		changed := 0
		for name, ri := range refs {
			if copied[name] == ri.SHA {
				continue
			}
			rc, size, err := src.OpenBundle(ctx, ri.Object)
			if err != nil {
				return fmt.Errorf("reading %s from %s: %w", name, r.CurGen, err)
			}
			_, err = dst.PushRef(ctx, name, ri.SHA, rc, false)
			rc.Close()
			if err != nil {
				return fmt.Errorf("writing %s to %s: %w", name, r.NextGen, err)
			}
			r.logf("re-encrypted %s (%s)", name, humanSize(size))
			copied[name] = ri.SHA
			changed++
		}
		for name := range copied {
			if _, ok := refs[name]; !ok {
				if err := dst.DeleteRef(ctx, name); err != nil {
					return err
				}
				delete(copied, name)
				changed++
			}
		}
		if changed == 0 {
			break
		}
		if round >= 5 {
			return fmt.Errorf("refs keep changing while rotating — is someone pushing? retry later")
		}
	}

	head, err := src.Head(ctx)
	if err != nil {
		return err
	}
	if head != "" {
		if err := dst.SetHead(ctx, head); err != nil {
			return err
		}
	}
	return nil
}

// RewrapKeys wraps the new DEK for every existing slot (members and the
// recovery key) and publishes the new repository public key.
func (r *Rotator) RewrapKeys(ctx context.Context) error {
	if r.cfg.Encryption == config.EncryptionNone {
		return nil
	}
	slots, err := r.kr.Slots(ctx)
	if err != nil {
		return err
	}
	for _, s := range slots {
		if s.Recipient == "" {
			r.logf("warning: slot %q has no recorded public key; it loses access (re-grant if needed)", s.Label)
			continue
		}
		if err := r.kr.Grant(ctx, r.dekNew, s.Recipient, s.Label); err != nil {
			return fmt.Errorf("re-wrapping slot %q: %w", s.Label, err)
		}
	}
	if err := r.kr.SetRepoKey(ctx, r.dekNew); err != nil {
		return err
	}
	r.logf("re-wrapped the new key for %d slot(s)", len(slots))
	return nil
}

// Flip atomically switches the remote to the new generation. The write
// is a compare-and-swap against the pointer observed at start, so a
// concurrent rotation cannot be clobbered.
func (r *Rotator) Flip(ctx context.Context) error {
	err := kopiax.SetGeneration(ctx, r.store, r.cfg.Prefix, r.NextGen, r.pointerETag)
	if errors.Is(err, storage.ErrPreconditionFailed) {
		return fmt.Errorf("another rotation switched the generation while this one was running; aborting without changes (re-run to rotate again)")
	}
	if err != nil {
		return err
	}
	r.logf("switched active generation: %s → %s", r.CurGen, r.NextGen)
	return nil
}

// Cleanup deletes the old generation and the staged DEK.
func (r *Rotator) Cleanup(ctx context.Context) error {
	prefix := r.key(r.CurGen) + "/"
	objs, err := r.store.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, o := range objs {
		if err := r.store.Delete(ctx, o.Key); err != nil {
			return fmt.Errorf("deleting old generation: %w", err)
		}
	}
	if err := r.store.Delete(ctx, r.key(stagedDEKName)); err != nil {
		r.logf("warning: could not remove staged rotation key: %v", err)
	}
	r.logf("removed old generation %s (%d objects)", r.CurGen, len(objs))
	return nil
}

// Run executes a complete rotation.
func (r *Rotator) Run(ctx context.Context) error {
	if err := r.SweepStaleGenerations(ctx); err != nil {
		return err
	}
	if err := r.Build(ctx); err != nil {
		return err
	}
	if err := r.RewrapKeys(ctx); err != nil {
		return err
	}
	if err := r.Flip(ctx); err != nil {
		return err
	}
	return r.Cleanup(ctx)
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
