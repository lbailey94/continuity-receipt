# WMv9 federated `scope` diagnosis — 2026-10-01

## Finding

The observed `{scope: "wmv9"}` is a **response-envelope collision**, not evidence that the inner code scope was forwarded as `wmv9`. A read-only `code.check` sent directly to `127.0.0.1:18790` returned `{scope: "WMv9/release-freeze", state: "free"}`. The same request through `127.0.0.1:18795` with top-level routing `scope: "wmv9"` returned `{scope: "wmv9", state: "free"}`.

Current source separates the two scopes: `Gateway::dispatch_wm` resolves the top-level routing scope; `Gateway::proxy` forwards nested `args` unchanged; `HttpBacking::call` sends that route and payload to the selected backing. However, `Gateway::proxy_raw` unconditionally writes the store label into the returned envelope's `scope` field. That replaces `code.check`'s requested lease scope (and `code.claim`'s `scope`; its separate `lease_id` survives).

The live gateway and its `wmv9` backing both report executable build commit `15d6d9accb0961f41d04e9986454f2d19a398b67` and executable SHA-256 `7791a1bf6fedb1f52758cd1599ded6eac973dc4770909c23251e3462bfdcd28a`. That source commit contains the Q03 inner-args preservation fix (`c17909a`) and the gateway regression test. This does not look like an old binary for argument forwarding; the runtime implements the current response-label behavior.

## Safe read-only reproducer

Use the same inner `args` with each endpoint. The second call's top-level `scope` selects the gateway backing; its inner `args.scope` is the lease scope being checked.

```sh
curl -sS -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wm","arguments":{"route":"code.check","args":{"scope":"WMv9/release-freeze","root":"/home/lucas/Desktop/WHITEMAGIC/WMv9"}}}}' \
  http://127.0.0.1:18790/mcp

curl -sS -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wm","arguments":{"route":"code.check","scope":"wmv9","args":{"scope":"WMv9/release-freeze","root":"/home/lucas/Desktop/WHITEMAGIC/WMv9"}}}}' \
  http://127.0.0.1:18795/mcp
```

Both calls report `state: "free"`; only the direct response exposes the checked lease scope in `scope`. The federated response exposes the backing-store label there instead.

## Q03 acceptance gap and proposed fix

`scripts/q03_acceptance.py:106-109` accepts either `response.scope == lease` **or** `response.lease_id == lease`. Because the gateway's `lease_id` survives the overwrite, this assertion cannot detect response-scope loss. Its `finally` block releases through the direct endpoint but does not assert `state == "released"`. The existing spawned `federated_gateway_e2e.rs::federated_gateway_e2e_pins_scopes_and_preserves_inner_payload` is stronger: it checks the lease directly on the selected backing and confirms the other backing reports it free.

Minimal follow-up:

1. In `crates/wm-mcp/src/gateway.rs::Gateway::proxy_raw`, preserve a backing response's `scope` when it exists and attach the routing label under a distinct key such as `store_scope`. If the backing response has no `scope`, retain the current `scope` label for compatibility. Add a regression assertion covering `code.check`/`code.claim` payload scope plus `store_scope`.
2. Strengthen `scripts/q03_acceptance.py` to require `lease_id == lease`, directly `code.check` the unique lease on the selected backing and assert the expected holder/state, and assert cleanup reports `state == "released"`.

## Ledger evidence and limits

The candidate worktree's Git common directory is `/home/lucas/Desktop/WHITEMAGIC/WMv9/.git`; `code.claim` derives `wm-leases.json` from that common directory when given the candidate root. The live gateway manifest maps `wmv9` to direct endpoint `127.0.0.1:18790`. The only existing ledgers found under `WHITEMAGIC` were the WMv9 common ledger and the unrelated site ledger; neither currently contains the earlier Luna session ID or the two client paths. The WMv9 ledger is currently empty. Since the earlier claims were released before this metadata check and the ledger retains no history, current files cannot establish their prior write/release sequence. There is no evidence that they landed in another ledger; from the source routing and explicit root, they should have used the WMv9 common ledger.

No leases were created, released, or modified during this diagnosis; no source or runtime changes were made.
