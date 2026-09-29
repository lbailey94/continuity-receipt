# Hosted receipt API raw-input hardening — 2026-09-29

The VPS service remains on verifier package `0.4.0`, supporting receipt specs
`0.1`–`0.4`. This change is in its HTTP handler, not in the published package
or receipt wire format. The reviewable source delta is
[`hosted-api-strict-json.patch`](hosted-api-strict-json.patch), applied to
`/opt/whitemagic-api/receipt-api.py`.

## Reason and scope

The current 0.5 candidate CLI rejects duplicate JSON object members and
requires UTF-8 raw input. Before this service change, the hosted 0.4 handler
used `json.loads(raw)` and accepted a duplicate-member variant of a valid
bundle as `TRUSTED`. The service now decodes request bodies as UTF-8 and rejects
duplicate object members at any depth before converting them to dictionaries.
This applies to `/verify`, `/verify-receipt` (including base64 bundle bytes),
`/verify-anchor`, `/anchors`, `/conformance`, `/mcp`, and the internal payment
receipt request. Parser recursion failures return HTTP 400. The verifier's
semantic result rules and supported versions are unchanged.

## Deployment evidence

- Source before: SHA-256 `9a938163957e951a20ffd671f52c09858414b4f1d0011d9e7eae954381bf82a0`.
- Source after: SHA-256 `604d4e5278823beb6b4cceea35faa781999ee8158f37b1f7fd6c715f853d7271`.
- Rollback copy on the VPS: `/opt/whitemagic-api/receipt-api.py.backup-2026-09-29-strict-json`.
- Rehearsed candidate on a separate loopback port with the installed 0.4.0
  package. A valid bundle returned `TRUSTED`; duplicate-member, UTF-16, BOM,
  deep JSON, and duplicate MCP inputs returned HTTP 400. A signed verification
  receipt was issued and successfully verified; duplicate members inside
  `bundle_bytes_b64` were refused.
- After service restart, the live loopback handler returned `TRUSTED` for the
  valid 0.1 bundle and HTTP 400 for duplicate-member, UTF-16, and BOM variants.
  The service was active; public `/health` returned `{"ok": true}` and `/info`
  still reported verifier `0.4.0` with specs `0.1`–`0.4`.

The public gateway's authenticated `POST /verify` path was not exercised with
a user key in this pass. Public health and info plus direct service loopback
checks cover routing health and the changed parser, respectively.

## Next agent-consumer gate

Use the offline assessment companion in `docs/AGENT_CONSUMER_PROFILE.md` with a
separately operated agent. That agent should pin its own issuer policy, obtain
the exact disclosed bundle, run verification locally, record its assessment and
reasons, and report missing evidence or integration friction. A hosted signed
verification receipt can accompany this exchange, but the relying agent must
not treat the service's `TRUSTED` verdict as authority or proof of real-world
execution.
