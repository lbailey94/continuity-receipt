# Signing and verification

The `continuity-receipt/0.1` release is attested by a signed git tag.

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
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/tmp/cr_allowed_signers verify-tag v0.1.0
```

Expected: `Good "git" signature for lbailey94@protonmail.com with ED25519 key SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk`.

## What the signature attests — and what it does not

It attests that the maintainer froze `SPEC.md` and the test vectors at the tagged commit. It is **not** an endorsement by any standards body, a warranty of fitness, or a statement about any deployed system's behavior.

## Rotation

A changed key means a new signed tag; old tags remain verifiable with their historical keys. Key changes are noted in `CHANGELOG.md`.
