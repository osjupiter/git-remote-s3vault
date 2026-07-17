# git-remote-r2

A git remote helper that stores repositories in **Cloudflare R2** (or any
S3-compatible object store), **end-to-end encrypted and deduplicated** —
age-based key management on top of kopia's storage engine.

```console
$ git remote add origin r2://my-bucket/my-repo
$ git push origin main
$ git clone r2://my-bucket/my-repo
```

## Why this instead of git-remote-s3?

- **Single static binary.** Written in Go — no Python, no pip, no runtime.
  Drop `git-remote-r2` on your `PATH` and git finds it.
- **Encrypted before it leaves your machine.** Everything is encrypted
  client-side, by default, always; keys are managed sops-style with
  [age](https://age-encryption.org) (grant a teammate with one command, a
  printed recovery key restores access from nothing). The storage provider
  sees only opaque ciphertext — not even branch names.
- **Deduplicated.** Data rides on [kopia](https://kopia.io)'s
  content-defined chunking: pushes upload only changed chunks, and tags or
  branches sharing history cost almost nothing.
- **R2 first-class.** Point it at a Cloudflare account ID and the endpoint,
  region, and addressing style are derived for you. Generic S3 (AWS, MinIO,
  Garage, Ceph, …) works through the same binary.
- **Tested for real.** The e2e suite spins up MinIO in a testcontainer and
  drives the compiled binary through actual `git push`, `clone`, `pull`,
  force-pushes, tags, branch deletion, key grants, disaster recovery, and
  measured deduplication.

## Install

```console
$ go install github.com/osjupiter/git-remote-r2/cmd/git-remote-r2@latest
```

or grab a release binary and put it on your `PATH`. To also handle
`s3://` URLs, add a symlink named `git-remote-s3` pointing at the same
binary.

## Quick start

From inside any existing repository, run setup with no arguments and
answer the wizard — it asks for the backend, bucket, and credentials,
generates the encryption keys, registers the remote, and checks that the
bucket is reachable:

```console
$ git-remote-r2 setup
Interactive setup — Enter accepts the [default].

Backend:
  1) Cloudflare R2
  2) Other S3-compatible storage (MinIO, AWS S3, ...)
Backend [1]:
Cloudflare account ID: abc123
Credentials — tip: use an API token scoped to ONLY the target bucket
(Object Read & Write), so a leaked key cannot touch anything else.
Access Key ID (empty to configure later): ...
Secret Access Key:
Bucket name: my-bucket
Prefix inside the bucket [my-repo]:
Remote name [origin]:
Which key should be able to decrypt this repository?
  1) age key age1ql3z7hjy54pw3hyw… (~/.config/git-remote-r2/identity.txt)
  2) SSH key ssh-ed25519 you@laptop (~/.ssh/id_ed25519)
  3) Generate a new age key
Key [1]:
Create remote "origin" → r2://my-bucket/my-repo? [Y]:
...
```

The key list offers every age key in your machine-key file and any
decryption-capable SSH key under `~/.ssh` (passphrase-protected SSH keys
are not supported and are skipped). With no existing keys, a fresh age
key is generated without asking.

Passing the URL directly skips the wizard (handy for scripts):

```console
$ export R2_ACCOUNT_ID=<cloudflare account id>

$ git-remote-r2 setup r2://my-bucket/my-repo
✓ generated this machine's key (age identity): ~/.config/git-remote-r2/identity.txt
✓ added remote "origin" → r2://my-bucket/my-repo
✓ 1 recipient(s) configured (1 added)

No S3 credentials found (checked the environment and ~/.config/git-remote-r2/credentials).
Tip: create an R2 API token scoped to ONLY this bucket (Object Read & Write),
     so that a leaked key cannot touch anything else.

Access Key ID (leave empty to skip): ...
Secret Access Key:
✓ credentials saved to ~/.config/git-remote-r2/credentials [account:... bucket:my-bucket]
✓ bucket reachable; remote is empty (first push will initialize it)
✓ repository key created; wrapped for 1 public key(s)
✓ recovery key created — store this line in a password manager or on paper:

    AGE-SECRET-KEY-1...

  It will NOT be shown again. Anyone holding it can decrypt this repository.

All set. Next:
  git push -u origin main

$ git push -u origin main
```

Setup remembers the token in `~/.config/git-remote-r2/credentials`
(plaintext, 0600 — the same trust model as other credential files), one
entry per bucket, matching the one-token-per-bucket model.

Useful flags: `--remote <name>`, `--recipient <age1...>` (repeatable; add
teammates or CI public keys), `--account-id <id>`, `--endpoint <url>` (for
MinIO/AWS), `--identity <path>`, `--encryption none`, `--no-verify`.
Re-running setup is safe and idempotent — run it again to add recipients or
repoint the remote.

Adding a teammate later is one command (see "Envelope encryption" below):

```console
$ git-remote-r2 key grant age1<their-public-key>
✓ access granted (no re-encryption needed — existing history is immediately readable)
```

## Cloning

On a machine that already has access (a granted machine key + saved
credentials), cloning is just git:

```console
$ git clone r2://my-bucket/my-repo
```

For a machine that has nothing yet, `git-remote-r2 clone` prepares
everything first — machine key, credentials, access check — and tells you
exactly what's missing instead of failing with a cryptic decryption error:

```console
$ git-remote-r2 clone r2://my-bucket/my-repo
✓ generated this machine's key (age identity): ~/.config/git-remote-r2/identity.txt
✗ this machine's key has no access to the repository yet.

  Your public key:
    age1nEw...

  Ask a member to run:
    git-remote-r2 key grant age1nEw... r2://my-bucket/my-repo

  Or, if you hold the recovery key:
    git-remote-r2 key recover r2://my-bucket/my-repo

# ...after a member runs the grant (or you run `key recover`):
$ git-remote-r2 clone r2://my-bucket/my-repo
✓ access confirmed
Cloning into 'my-repo'...
```

Credentials are prompted for (and remembered) when needed, and the
backend settings are written into the fresh clone's repo config, so from
then on every git command just works. `--account-id` / `--endpoint` /
`--identity` flags are available as with `setup`.

### Recovery key & disaster recovery

When setup initializes a repository it also mints a **recovery key** and
prints its secret exactly once:

```
✓ recovery key created — store this line in a password manager or on paper:

    AGE-SECRET-KEY-1....

  It will NOT be shown again.
```

Store that one line somewhere durable. Losing every device is then a
non-event — a brand-new machine needs only the recovery secret and the
URL:

```console
$ git-remote-r2 key recover r2://my-bucket/my-repo
recovery key (AGE-SECRET-KEY-...):
✓ generated this machine's key (age identity): ~/.config/git-remote-r2/identity.txt
✓ this machine's key now has access
$ git clone r2://my-bucket/my-repo
```

`recover` mints a fresh machine key and grants it access using the
recovery key, so the recovery secret goes straight back in the drawer.

The recovery key is deliberately **asymmetric** (a keypair, not a
passphrase): its public half lives in the bucket
(`.keys/dek/recovery.pub`), which means a future key rotation can re-wrap
the new repository key for it *without knowing any secret*. A
passphrase-based (symmetric) recovery scheme cannot do that — rotation
would stall waiting for someone to type the passphrase.

`git-remote-r2 key recovery-init` mints a replacement recovery key at any
time (the old secret stops working). For non-interactive use set
`GIT_REMOTE_R2_RECOVERY_KEY`.

Even without a recovery key, all is not lost while any clone survives:
generate a new key and force-push every ref to re-encrypt the remote.

### Without the setup command

`setup` is a convenience, not a requirement. If a machine key exists (any
age identity file works — `age-keygen` output is fine) and the helper can
find at least one public key, the first push initializes the repository
key by itself:

```console
$ age-keygen -o ~/.config/git-remote-r2/identity.txt
$ git remote add origin r2://my-bucket/my-repo
$ git push origin main   # repository key is created here, wrapped for your key
```

The machine key at `~/.config/git-remote-r2/identity.txt` and any public
keys listed in `~/.config/git-remote-r2/recipients.txt` (or in the
`r2.ageRecipients` git config) are picked up automatically. Note that this
path creates **no recovery key** — run `git-remote-r2 key recovery-init`
afterwards if you want one.

## Configuration

Everything can be set per-remote (`remote.<name>.<key>`), globally
(`r2.<key>`), or by environment variable. Precedence: **env > remote-scoped
git config > global git config**.

| git config key | environment | meaning |
|---|---|---|
| `r2.accountId` | `R2_ACCOUNT_ID`, `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID; derives the R2 endpoint |
| `r2.endpoint` | `AWS_ENDPOINT_URL[_S3]`, `GIT_REMOTE_R2_ENDPOINT` | explicit S3 endpoint (MinIO, AWS, …); wins over accountId |
| `r2.region` | `AWS_REGION` | region (`auto` for R2, `us-east-1` otherwise) |
| `r2.usePathStyle` | `GIT_REMOTE_R2_PATH_STYLE` | path-style addressing; auto-detected for self-hosted endpoints |
| `r2.ageRecipients` (multi) | `GIT_REMOTE_R2_AGE_RECIPIENTS` (comma-sep) | public keys (`age1...` / `ssh-...`) granted access when the repository key is first created; afterwards use `key grant` |
| `r2.ageRecipientsFile` | `GIT_REMOTE_R2_AGE_RECIPIENTS_FILE` | file with one such public key per line |
| `r2.ageIdentityFile` | `GIT_REMOTE_R2_AGE_IDENTITY_FILE` | this machine's key (age identity or SSH private key), used to unwrap the repository key |
| `r2.encryption` | `GIT_REMOTE_R2_ENCRYPTION` | `age` (default) or `none` (explicit opt-out) |

### Credentials

Two sources, checked in order — nothing else is ever consulted (no
`~/.aws/credentials`, no shared config, no instance roles):

1. environment — `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
   — the same AWS-shaped key pair for R2 and any other backend
2. `~/.config/git-remote-r2/credentials` — written by `setup`, strictly
   one entry per bucket (`[account:<id> bucket:<name>]`), no fallback

If neither yields a key pair, the helper fails with instructions instead
of silently probing other credential sources.

Use **bucket-scoped R2 API tokens** (Object Read & Write on a single
bucket): a leaked key then can't reach anything but that bucket's
ciphertext. Never commit credentials into the repository — the working
tree travels with every clone; this store does not.

### MinIO / self-hosted S3 example

```console
$ export AWS_ENDPOINT_URL=http://127.0.0.1:9000
$ export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
$ git clone r2://my-bucket/my-repo
```

## How it works

### Two layers: age for keys, kopia for data

The bucket holds two things, cleanly separated:

```
<prefix>/.keys/repo.pub           # DEK public key (plaintext — it's public)
<prefix>/.keys/dek/<label>.age    # DEK, wrapped to one member key (age)
<prefix>/.keys/dek/<label>.pub    # that member's public key (for `key list`)
<prefix>/data/...                 # kopia repository: opaque encrypted blobs
```

**Key layer (age, sops-style).** Every repository gets its own
**data-encryption key (DEK)**, generated on setup / first push. It is
stored in the bucket wrapped once per member public key. Granting access
is O(1): wrap the DEK for one more key and the entire existing history
becomes readable instantly, with no re-encryption and no re-push. Repos
stay isolated — one machine key serves every repo without coupling them.

```console
$ git-remote-r2 key grant age1<teammate> ; git-remote-r2 key list ; git-remote-r2 key revoke <label>
```

`key revoke` removes a member's ability to unwrap the DEK in the future,
but anyone who already unwrapped it may have cached it — a hard cut-off
additionally requires rotating the DEK and re-pushing (planned as
`key rotate`).

**Data layer ([kopia](https://kopia.io)'s repository engine).** Each push
stores a self-contained git bundle of the ref's full history as a kopia
object; refs and HEAD are kopia manifests. The DEK is the kopia
repository password. kopia provides content-defined chunking with
**deduplication**, AES-256-GCM encryption, packing, and local caching
(under `~/.cache/git-remote-r2/`) — so although every push writes a
"full" bundle, only the chunks that actually changed are uploaded and
stored. Measured in the e2e suite: on a ~3 MB repository, pushing a tag
adds ~5 KB and a small commit ~300 KB.

- Branches and tags cost almost nothing: shared history is stored once.
- Pushes enforce fast-forward unless `--force` is used (ancestry is
  checked locally against the advertised remote sha).
- `list`/`fetch` need no local bookkeeping: git's own object database
  answers "do I already have this?".

### Threat model

Repository **contents** (commits, trees, blobs, messages, file names, ref
names) are encrypted end-to-end; the DEK never exists unencrypted outside
your machines. The storage provider sees only: opaque blob names, blob
count/sizes, access timing, the fact that the format is kopia, and the
keyring metadata (how many member slots exist and their public keys).
Ref names and commit hashes are **not** visible.

### Caveats

- Pushing still creates a full bundle locally (CPU/disk proportional to
  repository size) even though only deltas are uploaded. Fine for small
  and medium repos; the storage format would allow incremental bundles
  later without a breaking change.
- There is no garbage collection yet: storage grows by roughly the
  changed bytes per push and deleted branches free no space. A `gc`
  command is planned. Do **not** run kopia's own maintenance against the
  bucket — it does not know about the helper's manifests.
- Two clients force-pushing the same ref at the same instant race
  last-writer-wins; the ref converges to one of them.

## Development

```console
$ make test        # unit tests
$ make e2e         # full git flows against MinIO (needs Docker)
$ make build
```

## License

MIT
