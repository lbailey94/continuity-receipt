# Hosted discovery and client review — 2026-10-01

## Website production

The user explicitly requested the website edit/deploy pass. PR
[29](https://github.com/lbailey94/whitemagic-site-private/pull/29), source
`cae9885a6932cf1d2e78df72b416b3e5554a591a`, merged as
`629b60b2acad95ea1284c8933aa3711c713ef7dc` after review and green CI.
Vercel preview `whitemagic-site-keib3v6b2-lbailey94s-projects.vercel.app`
and production `whitemagic-site-5psnbuerz-lbailey94s-projects.vercel.app`
reported Ready. The latter serves https://www.whitemagic.dev.

Primary CLI assertions passed across 12 preview and 12 production routes:
English/Chinese hosted, receipts and trust pages, agent and agent-economy
JSON, API catalog, llms.txt/full and AI-agent JSON. Evidence:
`review-evidence/site-preview-2026-10-01.json` and
`review-evidence/site-production-2026-10-01.json`.
The in-app browser permission for the preview domain was declined. The CLI
check had already completed before that denial was returned; no browser retry
or alternate access to the blocked domain was attempted afterward.
Final local rendered checks and the build passed. No new remote screenshot
is claimed.

Copy distinguishes published spec 0.5, runtime 0.5.0 and experimental 0.6;
authenticated explicit owner scope and manual ownership assignment; preserved
wm-crystal/1.0; free authenticated reads/lineage with private, no-store and
authenticated conditional 304; bounded ERC outcome/signature semantics; and
caller-claim notarization. DID, profile attribution and optional-anchor
corrections from PR21 are incorporated; that superseded PR is closed.
The three patched brace-expansion entries are development dependencies;
package.json and pricing are unchanged. Primary npm audit returned zero.

The failed Vercel production build `fi0mvirfx` cloned commit `16edb1c`:
its truth gate expected MCP release 9.3.1 but found snapshot marker 9.3.0.
Commit `918a975` corrected the marker. Subsequent production builds were
Ready before this new deployment; the guard was retained.

## VPS and customer preservation

The prior explicitly approved Crystal cutover remains active; the resumed
status check found API, gateway, key issuance and Caddy active. Protected
backup/quarantine evidence is in
`review-evidence/crystal-protected-backup-summary-2026-10-01.json` and
`review-evidence/crystal-live-cutover-2026-10-01.json`.
The original, backup and quarantine encrypted-byte hashes matched during
cutover; no decryption or plaintext inspection occurred. The resumed pass
read the saved summary, not the customer envelope. No owner was inferred;
owner assignment and authorized restoration remain separate unresolved work.
The refreshed VPS static docs and server card passed public TLS consistency
checks and canonical deploy-check.

## Client follow-up

CR client: 10 independently rerun mock-only tests. WMv9 isolated client:
12 independently rerun tests including existing crypto/AAD checks. URL origins,
redirects, IDs, credential input, FIFO refusal, binary key edge bytes and
private/exclusive key generation were reviewed. The final 25-case synthetic
Crystal loopback integration passed after client hardening. Final CR suite:
160 passed, 59 explicit skips and 13 subtests. Fifty skips are the opt-in
ownership/TLS harnesses, separately exercised in this work; the Caddy/VPS TLS
25-case result predates the client-only change, with API/gateway bytes unchanged.

The canonical local hosted client matches the reviewed CR helper. Reconstruct
it using the historical canonical patch followed by client-hardening.patch.
The WMv9 port remains isolated at 15d6d9a and is retained as
`review-evidence/wmv9-crystal-client-reviewed-2026-10-01.patch`; it is not a
WMv9 main merge, binary release or deployed service change. Source/test hashes
and current state: `review-evidence/crystal-client-hardening-2026-10-01.json`.

Independent administration/adoption, W2 operator host capture, package/release
choices and verified customer owner assignment remain open external gates.
