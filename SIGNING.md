# Signing and verification

Release tags are signed with the WhiteMagic release tag-signing key. From
`v0.4.0` on, every release tag is signed before publication.

**The `v0.3.0` tag remains unsigned.** It was annotated without a signature —
a lapse, kept intact: a pushed release reference is not replaced or rewritten.
Signing later tags does not make `v0.3.0` signed. The `v0.3.1`–`v0.3.3`
releases were retro-signed at their historical release commits on 2026-09-24;
each tag message records the commit basis and the Rust crate line at that
commit. That documents the releases that missed signing — it does not alter
`v0.3.0`.

| Tag | Commit | Signed | Note |
|---|---|---|---|
| `v0.1.0` | spec 0.1 freeze | yes | 11/11 vectors |
| `v0.2.0` | spec 0.2 | yes | 20 vectors, schema, CI |
| `v0.3.0` | `7fb1522` | **no** | annotated only; left as-is |
| `v0.3.1` | `008735f` | yes (retro 2026-09-24) | Python 0.3.1 / Rust 0.3.1 |
| `v0.3.2` | `b2489a7` | yes (retro 2026-09-24) | Python 0.3.2 / Rust 0.3.2 |
| `v0.3.3` | `354d9b8` | yes (retro 2026-09-24) | Python 0.3.3 / Rust 0.3.2 at that commit |
| `v0.4.0` | `59b401a` | yes | spec 0.4 release candidate |

## Signing key

| Field | Value |
|---|---|
| Key | WhiteMagic release tag-signing key (Ed25519, SSH format) |
| Principal | `lbailey94@protonmail.com` |
| Public key | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8MCJkjWCilk2F+kCnZHQR9wHlNcX/aW6arKsm5SsXj lbailey94@protonmail.com (WhiteMagic release signing)` |
| Fingerprint | `SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk` |

The same key signs WhiteMagic release tags. Custody is tracked in the project's key register (offline copies verified; rotation documented).

## Verify the tag

```bash
git clone https://github.com/lbailey94/continuity-receipt && cd continuity-receipt
printf '%s\n' 'lbailey94@protonmail.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8MCJkjWCilk2F+kCnZHQR9wHlNcX/aW6arKsm5SsXj lbailey94@protonmail.com (WhiteMagic release signing)' > /tmp/cr_allowed_signers
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/tmp/cr_allowed_signers verify-tag v0.4.0
```

Expected: `Good "git" signature for lbailey94@protonmail.com with ED25519 key SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk`.

## What the signature attests — and what it does not

It attests that the maintainer froze `SPEC.md` and the test vectors at the tagged commit. It is **not** an endorsement by any standards body, a warranty of fitness, or a statement about any deployed system's behavior.

## Rotation

A changed key means a new signed tag; old tags remain verifiable with their historical keys. Key changes are noted in `CHANGELOG.md`.
