# Verify a CPR bundle in five minutes

This local example needs Python 3.11+, Git, and network access to acquire the
source and install dependencies. Verification then runs offline. It uses a
public fixture with a test key; `TRUSTED` means the fixture meets the verifier's
rules, not that a real task occurred or that you should trust an arbitrary key.

## 1. Acquire a pinned fixture and install

Run from a fresh directory. This installs the published Python package
0.5.1 and obtains the vectors from a specific source revision:

```bash
git clone https://github.com/lbailey94/continuity-receipt.git
cd continuity-receipt
git checkout --detach 146c4d2439e4f11cc50776e754e98081bb41869e
python3 -m venv .venv
. .venv/bin/activate
python -m pip install continuity-receipt==0.5.1
cp vectors/02_happy_full.json bundle.json
cpr-verify bundle.json
# verdict: TRUSTED; exit status: 0
```

The fixture commit and installed package are distinct pins. To review source
instead, install the selected checkout with `python -m pip install .` and
follow [the review brief](REVIEW_BRIEF.md). That tests a locally built package;
it does not verify the registry artifact's provenance.

## 2. Check failure cases

These commands should return exit status 1. Inspect their JSON output as well
as their exit status:

```bash
cpr-verify vectors/03_tampered_body.json
# UNTRUSTED; errors include bad_signature
cpr-verify vectors/09_erased_content.json
# INSUFFICIENT_EVIDENCE
cpr-verify vectors/10b_anchor_missing.json --require-anchor
# PROVISIONAL
```

Only `TRUSTED` exits 0. Missing evidence and contradictory evidence are
different outcomes; neither should silently become acceptance. A receiver
must apply its own issuer, authority, completeness, and currentness policy.

## 3. Check a signed verification receipt locally

```bash
continuity-receipt-verify-receipt vectors/verification/01_valid.json \
  --bundle vectors/verification/bundle.json
# valid: true; digest_match: true; exit status: 0
continuity-receipt-verify-receipt vectors/verification/02_tampered_signature.json
# valid: false; errors include bad_signature; exit status: 1
```

A verification receipt binds a signer's recorded result to a bundle digest.
Checking it does not recompute the result or establish that the signer is an
authorized, independent, or honest evaluator. Re-run bundle verification to
compare the actual result, and pin the expected verifier key through a
channel you trust.

## Optional hosted verification

The hosted API is a separate runtime and data-handling boundary. Send only a
public fixture for this exercise. Current key eligibility and limits are at
<https://mcp.whitemagic.dev/keys>; the API contract is at
<https://api.whitemagic.dev/docs>. Obtain a key explicitly before running:

```bash
export WM_API_KEY=...  # key you obtained
curl --fail-with-body -sS https://api.whitemagic.dev/verify \
  -H "Authorization: Bearer $WM_API_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @bundle.json
```

A keyless request may return an HTTP 402 x402 offer. Inspect its current
requirements and the [hosted terms](https://www.whitemagic.dev/hosted) before
choosing to purchase anything; this recipe does not perform payment. Hosted
results and signed receipts need their own runtime/version/key evidence.

## Further checks

- [Specification](SPEC.md), [verification receipts](VERIFICATION_RECEIPTS.md),
  [threat model](THREAT_MODEL.md), and [review scope](REVIEW_BRIEF.md).
- Bundle manifests: `vectors/manifest.json`, `vectors/manifest-0.5.json`,
  and experimental `vectors/manifest-0.6.json`.
- Receipt manifest: `vectors/verification/manifest.json`.
- The audit-preparation candidate additionally provides `tools/audit_smoke.sh`
  to check an installed Python package from an empty working directory. That
  script is not part of the older fixture revision checked out above; run it
  from the selected review candidate, with jq installed, as described in its
  review brief.
- Rust: `cargo install continuity-receipt --version 0.5.1`.
  Separate language implementations in this repository are maintained by the
  same project; parity does not establish an independent audit.
