# Verify in 5 minutes

One page, copy-paste, no account required for any step except the hosted API
call — and that key is free and instant.

## 0. Install (30 seconds)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install continuity-receipt
```

## 1. Verify a bundle offline (30 seconds)

Any Continuity Receipt bundle verifies with one command — no network, no
accounts, no trust in us:

```bash
continuity-receipt-verify vectors/02_happy_full.json
# {"verdict": "TRUSTED", "errors": [], …}
```

The four verdicts are `TRUSTED`, `PROVISIONAL`, `INSUFFICIENT_EVIDENCE`,
`UNTRUSTED`. `INSUFFICIENT_EVIDENCE` is not the same as false — it means the
evidence to decide is missing. Exit code is 0 only for `TRUSTED`.

Or in Python:

```python
import json
from continuity_receipt import verify_bundle

bundle = json.load(open("bundle.json"))
result = verify_bundle(bundle)
print(result.verdict, result.codes())
```

## 2. Get a hosted verdict (60 seconds)

Free evaluation key (50 calls/day, no account): <https://mcp.whitemagic.dev/keys>

```bash
export WM_API_KEY=...   # paste the key you received
curl -s https://api.whitemagic.dev/verify \
  -H "Authorization: Bearer $WM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d @bundle.json | jq '{verdict, errors}'
```

No key at all? A keyless call answers HTTP 402 with x402 payment
requirements (USDC on Base, $0.003/call) — the response is machine-readable
and self-describing. See `api.whitemagic.dev/docs`.

## 3. Get a signed verification receipt, verify it offline (2 minutes)

Add `?receipt=1` to the same call and the service returns a signed record of
the **whole result** — verdict, errors, provisional/insufficient reasons, and
the summary — so you can audit *how and why* it was reached:

```bash
curl -s "https://api.whitemagic.dev/verify?receipt=1" \
  -H "Authorization: Bearer $WM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d @bundle.json | jq '.verification_receipt' > receipt.json

continuity-receipt-verify-receipt receipt.json --bundle bundle.json
# {"valid": true, "errors": [], "verdict": "TRUSTED", "digest_match": true, …}
```

Or in Python:

```python
import json
from continuity_receipt import verify_verification_receipt

receipt = json.load(open("receipt.json"))
bundle = json.load(open("bundle.json"))
result = verify_verification_receipt(receipt, bundle)
print(result.valid, result.verdict, result.digest_match)
```

What just happened: the receipt binds the SHA-256 of the bundle's canonical
bytes to the full result — verdict, error codes, errors, reasons, summary —
plus the verifier implementation and version, and the time — signed by the
service's `did:key` (published at `api.whitemagic.dev/info`).
`digest_match: true` proves the receipt is about *your* bundle; the signature
proves who said it. The service never stores your bundle.

Tamper with one byte of `receipt.json` and re-run — `bad_signature`. Tamper
with the bundle — `bundle_digest_mismatch`.

## What you can claim now

> "This bundle verified as TRUSTED under continuity-receipt 0.3, at time T,
> by implementation X version Y — and here is the signed statement, checkable
> offline."

That is the whole integration. No SDK required; the wire formats are JSON.

## Where things are

- Spec: `SPEC.md` · verification receipts: `VERIFICATION_RECEIPTS.md`
- Schema: `schema/` · vectors: `vectors/` (26 bundle cases) and
  `vectors/verification/` (14 receipt cases)
- Second implementation: `cargo install continuity-receipt`
- Hosted API contract: <https://api.whitemagic.dev/docs> ·
  OpenAPI: <https://api.whitemagic.dev/openapi.json>
- Keys & limits: <https://mcp.whitemagic.dev/keys> (free, instant) or
  <https://www.whitemagic.dev/contact> (invoiced, $5 / 10k calls)
