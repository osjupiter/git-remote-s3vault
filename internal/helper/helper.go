// Package helper implements the git remote-helper protocol
// (gitremote-helpers(7)) on top of an S3-compatible object store.
//
// Remote layout:
//
//	<prefix>/<refname>/<sha>.bundle.age  encrypted full bundle for a ref
//	<prefix>/<refname>/<sha>.bundle      plaintext bundle (encryption=none)
//	<prefix>/HEAD                        plaintext refname of the default branch
//
// Every push uploads a self-contained bundle of the ref's full history and
// then removes the previous bundle, so the newest object under a ref's
// directory is always sufficient on its own for cloning and fetching.
package helper

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-r2/internal/config"
	"github.com/osjupiter/git-remote-r2/internal/cryptox"
	"github.com/osjupiter/git-remote-r2/internal/gitutil"
	"github.com/osjupiter/git-remote-r2/internal/keyring"
	"github.com/osjupiter/git-remote-r2/internal/storage"
)

const (
	extEncrypted = ".bundle.age"
	extPlain     = ".bundle"
	headKeyName  = "HEAD"
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)

type remoteRef struct {
	sha string
	key string
}

// Helper drives one remote-helper session over stdin/stdout.
type Helper struct {
	cfg   *config.Config
	store storage.Storage
	git   gitutil.Git

	in   *bufio.Scanner
	out  *bufio.Writer
	errW io.Writer

	refs     map[string]remoteRef // refname -> current bundle, from the last list
	headRef  string
	forceAll bool
	verbose  int

	repoKey    age.Recipient  // the remote's DEK public key (push side)
	fetchIDs   []age.Identity // unwrapped DEK + personal identities (fetch side)
	identities []age.Identity
}

// New wires up a session. store may be nil, in which case it is built
// lazily from cfg on first use (so `capabilities` works without creds).
func New(cfg *config.Config, store storage.Storage, in io.Reader, out, errW io.Writer) *Helper {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	return &Helper{
		cfg:     cfg,
		store:   store,
		in:      sc,
		out:     bufio.NewWriter(out),
		errW:    errW,
		verbose: 1,
	}
}

// Run processes commands until EOF or an empty line outside a batch.
func (h *Helper) Run(ctx context.Context) error {
	for h.in.Scan() {
		line := strings.TrimRight(h.in.Text(), "\n")
		switch {
		case line == "":
			return h.out.Flush()
		case line == "capabilities":
			h.printf("option\nfetch\npush\n\n")
		case strings.HasPrefix(line, "option "):
			h.handleOption(strings.TrimPrefix(line, "option "))
		case line == "list", line == "list for-push":
			if err := h.cmdList(ctx); err != nil {
				return err
			}
		case strings.HasPrefix(line, "fetch "):
			if err := h.cmdFetchBatch(ctx, line); err != nil {
				return err
			}
		case strings.HasPrefix(line, "push "):
			if err := h.cmdPushBatch(ctx, line); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown remote-helper command %q", line)
		}
		if err := h.out.Flush(); err != nil {
			return err
		}
	}
	if err := h.in.Err(); err != nil {
		return err
	}
	return h.out.Flush()
}

func (h *Helper) printf(format string, args ...any) {
	fmt.Fprintf(h.out, format, args...)
}

func (h *Helper) logf(format string, args ...any) {
	if h.verbose >= 2 || os.Getenv("GIT_REMOTE_R2_DEBUG") != "" {
		fmt.Fprintf(h.errW, "git-remote-r2: "+format+"\n", args...)
	}
}

func (h *Helper) warnf(format string, args ...any) {
	fmt.Fprintf(h.errW, "git-remote-r2: warning: "+format+"\n", args...)
}

func (h *Helper) handleOption(opt string) {
	name, value, _ := strings.Cut(opt, " ")
	switch name {
	case "verbosity":
		fmt.Sscanf(value, "%d", &h.verbose)
		h.printf("ok\n")
	case "force":
		h.forceAll = value == "true"
		h.printf("ok\n")
	case "progress":
		h.printf("ok\n")
	default:
		h.printf("unsupported\n")
	}
}

func (h *Helper) ensureStore(ctx context.Context) error {
	if h.store != nil {
		return nil
	}
	s, err := storage.New(ctx, h.cfg)
	if err != nil {
		return err
	}
	h.store = s
	return nil
}

// key builds an object key under the configured prefix.
func (h *Helper) key(parts ...string) string {
	all := append([]string{h.cfg.Prefix}, parts...)
	return strings.TrimPrefix(path.Join(all...), "/")
}

func (h *Helper) ext() string {
	if h.cfg.Encryption == config.EncryptionNone {
		return extPlain
	}
	return extEncrypted
}

// loadRemoteRefs lists the bucket prefix and reconstructs the remote's refs.
func (h *Helper) loadRemoteRefs(ctx context.Context) error {
	if err := h.ensureStore(ctx); err != nil {
		return err
	}
	objs, err := h.store.List(ctx, h.key()+"/")
	if err != nil {
		if h.cfg.Prefix == "" {
			objs, err = h.store.List(ctx, "")
		}
		if err != nil {
			return err
		}
	}

	type candidate struct {
		storage.Object
		sha string
	}
	byRef := map[string][]candidate{}
	h.refs = map[string]remoteRef{}
	h.headRef = ""

	base := h.key()
	for _, o := range objs {
		rel := o.Key
		if base != "" {
			rel = strings.TrimPrefix(rel, base+"/")
		}
		if rel == headKeyName || rel == keyring.KeysDir ||
			strings.HasPrefix(rel, keyring.KeysDir+"/") {
			continue // HEAD and key material are not ref bundles
		}
		var ext string
		switch {
		case strings.HasSuffix(rel, extEncrypted):
			ext = extEncrypted
		case strings.HasSuffix(rel, extPlain):
			ext = extPlain
		default:
			continue
		}
		dir, file := path.Split(strings.TrimSuffix(rel, ext))
		refname := strings.TrimSuffix(dir, "/")
		if refname == "" || !shaRe.MatchString(file) {
			continue
		}
		byRef[refname] = append(byRef[refname], candidate{o, file})
	}

	for refname, cands := range byRef {
		sort.Slice(cands, func(i, j int) bool {
			return cands[i].LastModified.After(cands[j].LastModified)
		})
		if len(cands) > 1 {
			h.warnf("ref %s has %d bundles; using the newest (%s). Concurrent pushes may have raced.",
				refname, len(cands), cands[0].sha[:12])
		}
		h.refs[refname] = remoteRef{sha: cands[0].sha, key: cands[0].Key}
	}

	// Resolve the remote HEAD (symbolic ref for clone's default branch).
	if rc, err := h.store.Get(ctx, h.key(headKeyName)); err == nil {
		data, rerr := io.ReadAll(io.LimitReader(rc, 4096))
		rc.Close()
		if rerr == nil {
			target := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(data)), "ref:"))
			if _, ok := h.refs[target]; ok {
				h.headRef = target
			}
		}
	}
	if h.headRef == "" {
		for _, fallback := range []string{"refs/heads/main", "refs/heads/master"} {
			if _, ok := h.refs[fallback]; ok {
				h.headRef = fallback
				break
			}
		}
	}
	if h.headRef == "" {
		var branches []string
		for r := range h.refs {
			if strings.HasPrefix(r, "refs/heads/") {
				branches = append(branches, r)
			}
		}
		sort.Strings(branches)
		if len(branches) > 0 {
			h.headRef = branches[0]
		}
	}
	return nil
}

func (h *Helper) cmdList(ctx context.Context) error {
	if err := h.loadRemoteRefs(ctx); err != nil {
		return err
	}
	names := make([]string, 0, len(h.refs))
	for r := range h.refs {
		names = append(names, r)
	}
	sort.Strings(names)
	for _, r := range names {
		h.printf("%s %s\n", h.refs[r].sha, r)
	}
	if h.headRef != "" {
		h.printf("@%s HEAD\n", h.headRef)
	}
	h.printf("\n")
	return nil
}

// --- fetch ---

func (h *Helper) cmdFetchBatch(ctx context.Context, first string) error {
	type want struct{ sha, name string }
	wants := []want{}
	line := first
	for {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) == 3 && parts[0] == "fetch" {
			wants = append(wants, want{parts[1], parts[2]})
		}
		if !h.in.Scan() {
			break
		}
		line = h.in.Text()
		if line == "" {
			break
		}
	}

	if h.refs == nil {
		if err := h.loadRemoteRefs(ctx); err != nil {
			return err
		}
	}

	done := map[string]bool{}
	for _, w := range wants {
		if done[w.sha] {
			continue
		}
		if err := h.fetchOne(ctx, w.sha, w.name); err != nil {
			return fmt.Errorf("fetching %s (%s): %w", w.name, w.sha[:12], err)
		}
		done[w.sha] = true
	}
	h.printf("\n")
	return nil
}

func (h *Helper) fetchOne(ctx context.Context, sha, name string) error {
	key := ""
	if rr, ok := h.refs[name]; ok && rr.sha == sha {
		key = rr.key
	} else {
		// The exact sha may live under another ref, or the listing may be
		// stale; search all known bundles for it.
		for _, rr := range h.refs {
			if rr.sha == sha {
				key = rr.key
				break
			}
		}
	}
	if key == "" {
		return fmt.Errorf("no bundle found for %s", sha)
	}
	h.logf("downloading %s", key)

	body, err := h.store.Get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()

	var payload io.Reader = body
	if strings.HasSuffix(key, extEncrypted) {
		ids, err := h.fetchIdentities(ctx)
		if err != nil {
			return err
		}
		payload, err = cryptox.Decrypt(body, ids)
		if err != nil {
			return fmt.Errorf("decrypting bundle: %w (is your key granted access? see `git-remote-r2 key list`)", err)
		}
	}

	tmp, err := gitutil.TempFile("git-remote-r2-fetch-*.bundle")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return h.git.BundleUnbundle(tmp.Name())
}

// --- push ---

func (h *Helper) cmdPushBatch(ctx context.Context, first string) error {
	specs := []string{}
	line := first
	for {
		if s, ok := strings.CutPrefix(line, "push "); ok {
			specs = append(specs, s)
		}
		if !h.in.Scan() {
			break
		}
		line = h.in.Text()
		if line == "" {
			break
		}
	}

	if h.refs == nil {
		if err := h.loadRemoteRefs(ctx); err != nil {
			return err
		}
	}

	for _, spec := range specs {
		force := strings.HasPrefix(spec, "+") || h.forceAll
		spec = strings.TrimPrefix(spec, "+")
		src, dst, ok := strings.Cut(spec, ":")
		if !ok || dst == "" {
			h.printf("error %s malformed refspec\n", spec)
			continue
		}
		var err error
		if src == "" {
			err = h.pushDelete(ctx, dst)
		} else {
			err = h.pushRef(ctx, src, dst, force)
		}
		if err != nil {
			h.printf("error %s %s\n", dst, strings.ReplaceAll(err.Error(), "\n", " "))
		} else {
			h.printf("ok %s\n", dst)
		}
	}
	h.printf("\n")
	return nil
}

func (h *Helper) pushDelete(ctx context.Context, dst string) error {
	objs, err := h.store.List(ctx, h.key(dst)+"/")
	if err != nil {
		return err
	}
	if len(objs) == 0 {
		return fmt.Errorf("remote ref does not exist")
	}
	for _, o := range objs {
		if err := h.store.Delete(ctx, o.Key); err != nil {
			return err
		}
	}
	delete(h.refs, dst)
	if h.headRef == dst {
		if err := h.store.Delete(ctx, h.key(headKeyName)); err != nil {
			h.warnf("could not delete remote HEAD: %v", err)
		}
		h.headRef = ""
	}
	return nil
}

func (h *Helper) pushRef(ctx context.Context, src, dst string, force bool) error {
	localSHA, err := h.git.RevParse(src)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", src, err)
	}

	if existing, ok := h.refs[dst]; ok && existing.sha != localSHA && !force {
		if !h.git.HasObject(existing.sha) {
			return fmt.Errorf("remote is at %s which is not known locally; fetch first", existing.sha[:12])
		}
		ffwd, err := h.git.IsAncestor(existing.sha, localSHA)
		if err != nil {
			return err
		}
		if !ffwd {
			return fmt.Errorf("non-fast-forward (remote is at %s); fetch first or force-push", existing.sha[:12])
		}
	}

	// 1. Bundle the full history of the pushed commit.
	tmp, err := gitutil.TempFile("git-remote-r2-push-*.bundle")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)
	if err := h.git.BundleCreate(tmpName, localSHA); err != nil {
		return err
	}

	// 2. Encrypt (unless explicitly disabled) into the upload staging file.
	uploadPath := tmpName
	if h.cfg.Encryption == config.EncryptionAge {
		repoKey, err := h.ensureRepoKey(ctx)
		if err != nil {
			return err
		}
		recips := []age.Recipient{repoKey}
		enc, err := gitutil.TempFile("git-remote-r2-push-*.bundle.age")
		if err != nil {
			return err
		}
		encName := enc.Name()
		defer os.Remove(encName)
		src, err := os.Open(tmpName)
		if err != nil {
			enc.Close()
			return err
		}
		encErr := cryptox.Encrypt(enc, src, recips)
		src.Close()
		if cerr := enc.Close(); encErr == nil {
			encErr = cerr
		}
		if encErr != nil {
			return encErr
		}
		uploadPath = encName
	}

	// 3. Upload, then clean up superseded bundles for this ref.
	f, err := os.Open(uploadPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	newKey := h.key(dst, localSHA+h.ext())
	h.logf("uploading %s (%d bytes)", newKey, st.Size())
	if err := h.store.Put(ctx, newKey, f, st.Size()); err != nil {
		return err
	}

	if stale, err := h.store.List(ctx, h.key(dst)+"/"); err == nil {
		for _, o := range stale {
			if o.Key != newKey {
				if derr := h.store.Delete(ctx, o.Key); derr != nil {
					h.warnf("could not delete stale bundle %s: %v", o.Key, derr)
				}
			}
		}
	} else {
		h.warnf("could not list stale bundles for %s: %v", dst, err)
	}

	// 4. Make sure the remote has a HEAD so clones pick a default branch.
	if h.headRef == "" && strings.HasPrefix(dst, "refs/heads/") {
		if err := h.store.Put(ctx, h.key(headKeyName), strings.NewReader(dst), int64(len(dst))); err != nil {
			h.warnf("could not write remote HEAD: %v", err)
		} else {
			h.headRef = dst
		}
	}

	h.refs[dst] = remoteRef{sha: localSHA, key: newKey}
	return nil
}

// --- key material ---

func defaultConfigPath(name string) string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	p := path.Join(dir, "git-remote-r2", name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// ensureRepoKey returns the remote's DEK public key, initializing the
// keyring on first push: a fresh DEK is generated and wrapped to every
// configured (or identity-derived) public key.
func (h *Helper) ensureRepoKey(ctx context.Context) (age.Recipient, error) {
	if h.repoKey != nil {
		return h.repoKey, nil
	}
	kr := keyring.New(h.store, h.cfg.Prefix)
	if r, ok, err := kr.RepoRecipient(ctx); err != nil {
		return nil, err
	} else if ok {
		h.repoKey = r
		return r, nil
	}

	specs, err := h.initialRecipientSpecs()
	if err != nil {
		return nil, err
	}
	dek, err := kr.Init(ctx, specs)
	if err != nil {
		return nil, err
	}
	h.warnf("initialized repository key; access granted to %d public key(s)", len(specs))
	h.warnf("no recovery key was created; run `git-remote-r2 key recovery-init` to add one")
	h.repoKey = dek.Recipient()
	return h.repoKey, nil
}

// initialRecipientSpecs decides who can unwrap a brand-new repository key:
// explicitly configured recipients, else the public halves of the local
// identities.
func (h *Helper) initialRecipientSpecs() ([]string, error) {
	specs := append([]string{}, h.cfg.Recipients...)
	files := h.cfg.RecipientFiles
	if len(specs) == 0 && len(files) == 0 {
		if p := defaultConfigPath("recipients.txt"); p != "" {
			files = []string{p}
		}
	}
	fromFiles, err := cryptox.LoadRecipientFiles(files)
	if err != nil {
		return nil, err
	}
	for _, s := range fromFiles {
		if s = strings.TrimSpace(s); s != "" && !strings.HasPrefix(s, "#") {
			specs = append(specs, s)
		}
	}
	if len(specs) == 0 {
		if ids, err := h.loadIdentities(); err == nil {
			for _, id := range ids {
				if x, ok := id.(*age.X25519Identity); ok {
					specs = append(specs, x.Recipient().String())
				}
			}
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("cannot initialize the repository key: no public keys available; " +
			"run `git-remote-r2 setup`, set r2.ageRecipients, or opt out with r2.encryption=none")
	}
	if _, err := cryptox.ParseRecipients(specs); err != nil {
		return nil, err
	}
	return specs, nil
}

// fetchIdentities returns everything usable to decrypt bundles: the
// repository DEK (unwrapped from the keyring with the machine identities)
// first, then the machine identities themselves, which also covers an
// identity file that holds the repository key directly.
func (h *Helper) fetchIdentities(ctx context.Context) ([]age.Identity, error) {
	if h.fetchIDs != nil {
		return h.fetchIDs, nil
	}
	personal, err := h.loadIdentities()
	if err != nil {
		return nil, err
	}
	ids := personal
	kr := keyring.New(h.store, h.cfg.Prefix)
	if dek, ok, err := kr.Unwrap(ctx, personal); err != nil {
		h.warnf("reading repository keyring: %v", err)
	} else if ok {
		ids = append([]age.Identity{dek}, personal...)
	}
	h.fetchIDs = ids
	return ids, nil
}

func (h *Helper) loadIdentities() ([]age.Identity, error) {
	if h.identities != nil {
		return h.identities, nil
	}
	files := h.cfg.IdentityFiles
	if len(files) == 0 {
		if p := defaultConfigPath("identity.txt"); p != "" {
			files = []string{p}
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("bundle is age-encrypted but no identity is configured; " +
			"set r2.ageIdentityFile (git config) or GIT_REMOTE_R2_AGE_IDENTITY_FILE")
	}
	ids, err := cryptox.LoadIdentityFiles(files)
	if err != nil {
		return nil, err
	}
	h.identities = ids
	return ids, nil
}
