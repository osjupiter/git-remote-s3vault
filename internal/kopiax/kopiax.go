// Package kopiax wraps the kopia repository layer as the storage engine
// for the remote helper.
//
// kopia provides content-defined chunking with deduplication, encryption
// (AES-256-GCM / ChaCha20-Poly1305), packing of small contents into large
// blobs, local caching, and many storage backends. On top of it this
// package exposes exactly what a git remote needs:
//
//   - bundles are kopia objects (chunked, deduplicated, encrypted)
//   - refs and HEAD are kopia manifests (small labeled JSON records)
//
// The kopia repository password is the repository DEK managed by the
// keyring package (an age X25519 identity string — high-entropy and
// wrapped per member public key under .keys/). The kopia data lives under
// <prefix>/data/ so it never collides with the keyring objects.
package kopiax

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/blob/s3"
	"github.com/kopia/kopia/repo/content"
	"github.com/kopia/kopia/repo/format"
	"github.com/kopia/kopia/repo/manifest"
	"github.com/kopia/kopia/repo/object"

	"github.com/osjupiter/git-remote-s3ee/internal/config"
)

// ErrNotInitialized is returned when the remote has no kopia repository
// yet (a fresh remote before the first push).
var ErrNotInitialized = errors.New("remote repository not initialized")

// PlaintextPassword is the well-known password used when the user
// explicitly opts out of encryption (r2.encryption=none). It is NOT a
// secret and provides no confidentiality.
const PlaintextPassword = "git-remote-s3ee-plaintext-mode"

// NewBlobStorage builds the kopia blob storage for a remote. Tests swap
// this out for a filesystem-backed store.
var NewBlobStorage = func(ctx context.Context, cfg *config.Config) (blob.Storage, error) {
	opt := &s3.Options{
		BucketName:      cfg.Bucket,
		Prefix:          dataPrefix(cfg),
		AccessKeyID:     cfg.AccessKeyID,
		SecretAccessKey: cfg.SecretAccessKey,
		SessionToken:    cfg.SessionToken,
		Region:          cfg.Region,
	}
	if cfg.Endpoint != "" {
		u, err := url.Parse(cfg.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint %q: %w", cfg.Endpoint, err)
		}
		opt.Endpoint = u.Host
		opt.DoNotUseTLS = u.Scheme == "http"
	} else {
		opt.Endpoint = "s3.amazonaws.com"
	}
	return s3.New(ctx, opt, false)
}

func dataPrefix(cfg *config.Config) string {
	return strings.TrimPrefix(path.Join(cfg.Prefix, "data"), "/") + "/"
}

// Repo is an open kopia-backed remote repository.
type Repo struct {
	rep repo.Repository
}

// RefInfo is one remote ref.
type RefInfo struct {
	SHA    string
	Object string // kopia object ID of the ref's bundle
}

type refPayload struct {
	SHA    string `json:"sha"`
	Object string `json:"object"`
}

type headPayload struct {
	Target string `json:"target"`
}

func refLabels(name string) map[string]string {
	return map[string]string{"type": "gitref", "ref": name}
}

func headLabels() map[string]string {
	return map[string]string{"type": "githead"}
}

// Open connects to the remote's kopia repository. When create is true a
// missing repository is initialized; otherwise ErrNotInitialized is
// returned for fresh remotes.
func Open(ctx context.Context, cfg *config.Config, password string, create bool) (*Repo, error) {
	st, err := NewBlobStorage(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening blob storage: %w", err)
	}
	defer st.Close(ctx) //nolint:errcheck // read-side storage handle only

	if _, err := st.GetMetadata(ctx, "kopia.repository"); err != nil {
		if !errors.Is(err, blob.ErrBlobNotFound) {
			return nil, fmt.Errorf("checking repository: %w", err)
		}
		if !create {
			return nil, ErrNotInitialized
		}
		if err := repo.Initialize(ctx, st, &repo.NewRepositoryOptions{
			ObjectFormat: format.ObjectFormat{Splitter: "DYNAMIC-128K-BUZHASH"},
		}, password); err != nil {
			return nil, fmt.Errorf("initializing repository: %w", err)
		}
	}

	cacheDir, configFile, err := cachePaths(cfg)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	if err := repo.Connect(ctx, configFile, st, password, &repo.ConnectOptions{
		ClientOptions: repo.ClientOptions{Username: "git-remote-s3ee", Hostname: hostname},
		CachingOptions: content.CachingOptions{
			CacheDirectory:         filepath.Join(cacheDir, "cache"),
			ContentCacheSizeBytes:  512 << 20,
			MetadataCacheSizeBytes: 128 << 20,
		},
	}); err != nil {
		return nil, fmt.Errorf("connecting to repository: %w", err)
	}
	// The config file embeds the storage credentials; keep it private.
	if err := os.Chmod(configFile, 0o600); err != nil {
		return nil, err
	}

	rep, err := repo.Open(ctx, configFile, password, nil)
	if err != nil {
		return nil, fmt.Errorf("opening repository (wrong key? see `git-remote-s3ee key list`): %w", err)
	}
	return &Repo{rep: rep}, nil
}

// cachePaths returns the per-remote local cache directory and config file.
func cachePaths(cfg *config.Config) (string, string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", "", fmt.Errorf("resolving cache dir: %w", err)
	}
	sum := sha256.Sum256([]byte(cfg.Endpoint + "\x00" + cfg.Bucket + "\x00" + cfg.Prefix))
	dir := filepath.Join(base, "git-remote-s3ee", hex.EncodeToString(sum[:])[:16])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	return dir, filepath.Join(dir, "kopia.config"), nil
}

func (r *Repo) Close(ctx context.Context) error {
	return r.rep.Close(ctx)
}

// Refs returns all remote refs. When concurrent pushes have left multiple
// manifests for one ref, the newest wins.
func (r *Repo) Refs(ctx context.Context) (map[string]RefInfo, error) {
	entries, err := r.rep.FindManifests(ctx, map[string]string{"type": "gitref"})
	if err != nil {
		return nil, fmt.Errorf("listing refs: %w", err)
	}
	newest := map[string]*manifest.EntryMetadata{}
	for _, e := range entries {
		name := e.Labels["ref"]
		if name == "" {
			continue
		}
		if cur, ok := newest[name]; !ok || e.ModTime.After(cur.ModTime) {
			newest[name] = e
		}
	}
	refs := map[string]RefInfo{}
	for name, e := range newest {
		var p refPayload
		if _, err := r.rep.GetManifest(ctx, e.ID, &p); err != nil {
			return nil, fmt.Errorf("reading ref %s: %w", name, err)
		}
		refs[name] = RefInfo{SHA: p.SHA, Object: p.Object}
	}
	return refs, nil
}

// Head returns the remote HEAD target refname ("" if unset).
func (r *Repo) Head(ctx context.Context) (string, error) {
	entries, err := r.rep.FindManifests(ctx, headLabels())
	if err != nil {
		return "", err
	}
	var newest *manifest.EntryMetadata
	for _, e := range entries {
		if newest == nil || e.ModTime.After(newest.ModTime) {
			newest = e
		}
	}
	if newest == nil {
		return "", nil
	}
	var p headPayload
	if _, err := r.rep.GetManifest(ctx, newest.ID, &p); err != nil {
		return "", err
	}
	return p.Target, nil
}

// PushRef stores a bundle and points the ref at it, optionally also
// setting HEAD, in one write session. It returns the bundle's object ID.
func (r *Repo) PushRef(ctx context.Context, name, sha string, bundle io.Reader, setHead bool) (string, error) {
	var oidStr string
	err := repo.WriteSession(ctx, r.rep, repo.WriteSessionOptions{Purpose: "git-remote-s3ee push"},
		func(ctx context.Context, w repo.RepositoryWriter) error {
			ow := w.NewObjectWriter(ctx, object.WriterOptions{Description: "git bundle " + name})
			defer ow.Close() //nolint:errcheck // Result() surfaces errors
			if _, err := io.Copy(ow, bundle); err != nil {
				return fmt.Errorf("writing bundle: %w", err)
			}
			oid, err := ow.Result()
			if err != nil {
				return fmt.Errorf("finalizing bundle: %w", err)
			}
			oidStr = oid.String()
			if _, err := w.ReplaceManifests(ctx, refLabels(name), refPayload{SHA: sha, Object: oidStr}); err != nil {
				return fmt.Errorf("updating ref: %w", err)
			}
			if setHead {
				if _, err := w.ReplaceManifests(ctx, headLabels(), headPayload{Target: name}); err != nil {
					return fmt.Errorf("updating HEAD: %w", err)
				}
			}
			return nil
		})
	return oidStr, err
}

// DeleteRef removes a ref (the bundle contents remain until a future GC).
func (r *Repo) DeleteRef(ctx context.Context, name string) error {
	return r.deleteManifests(ctx, refLabels(name))
}

// DeleteHead removes the HEAD pointer.
func (r *Repo) DeleteHead(ctx context.Context) error {
	return r.deleteManifests(ctx, headLabels())
}

func (r *Repo) deleteManifests(ctx context.Context, labels map[string]string) error {
	entries, err := r.rep.FindManifests(ctx, labels)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	return repo.WriteSession(ctx, r.rep, repo.WriteSessionOptions{Purpose: "git-remote-s3ee delete"},
		func(ctx context.Context, w repo.RepositoryWriter) error {
			for _, e := range entries {
				if err := w.DeleteManifest(ctx, e.ID); err != nil {
					return err
				}
			}
			return nil
		})
}

// OpenBundle streams a stored bundle.
func (r *Repo) OpenBundle(ctx context.Context, objectID string) (io.ReadCloser, int64, error) {
	oid, err := object.ParseID(objectID)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid object ID %q: %w", objectID, err)
	}
	rd, err := r.rep.OpenObject(ctx, oid)
	if err != nil {
		return nil, 0, fmt.Errorf("opening bundle: %w", err)
	}
	return rd, rd.Length(), nil
}
