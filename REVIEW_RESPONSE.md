# Public review response — first independent review (2026-09-24)

**Status:** response published with the 0.4.0 release. Materials frozen at tag
`v0.4.0` (spec `continuity-receipt/0.4`; Python + Rust 0.4.0 on PyPI/crates.io;
hosted verifier 0.4.0 live). The review brief for the next round is
`REVIEW_BRIEF.md`.

An independent reviewer audited the 0.3-era artifacts — the spec, both
implementations, and the hosted verifier — and returned five findings. We
treated the review as a release gate rather than a report: the fixes ship in
0.4.0, the reviewer's crash reproductions are permanent corpus cases, and the
missing checks became a conformance table. This is the point-by-point
response, written to be checkable rather than persuasive.

## Findings → fixes

1. **Malformed input (the reviewer's P0).** A whole-shape validation pass now
   runs before any semantic check in Python and Rust. It covers the structural
   types that previously crashed the verifier (non-object receipts, bodies,
   and issuers; wrong-typed anchors, revocations, and disclosure maps),
   records them as `malformed` / `anchor_invalid` / `bad_revocation` up front,
   and later passes skip malformed entries. It is not a full JSON-Schema
   validation of every nested field; remaining shape and semantic checks
   follow in their own passes. The four reproductions are permanent corpus
   cases. Input boundaries: an 8 MiB bundle cap in the CLIs, receipt-count
   (10,000) and nesting-depth (64) limits in the libraries, and Rust
   parser-recursion failures mapped to `nesting_too_deep`. Invalid, oversized,
   and deeply nested JSON all return structured output with exit 1.
   Reproduce: `python3 tools/hostile_input_probe.py --require-parity` and
   `python3 -m unittest tests.test_hostile_input -v`.

2. **TRUSTED boundary.** The README now leads with what `TRUSTED` establishes:
   it passes this format's checks under the supplied trust and revocation
   policy. The signature proves a key signed the recorded claims — not that
   the work happened, that a sandbox enforced its limits, or that termination
   occurred outside the issuer's report. Issuer honesty is stated up front and
   cross-referenced to `THREAT_MODEL.md`.

3. **Spec–implementation conformance.** `CONFORMANCE_TABLE.md` maps every
   normative requirement → Python check → Rust check → positive vector →
   negative vector, with no unexplained blank cells. Where we chose not to
   enforce, the spec text was softened rather than left implied (`agent_id` is
   documented as an opaque identifier; zero quota values mean "not enforced";
   the rest is itemized). Coverage gaps were closed with vectors 19–21 and
   `verification/21`.

4. **Offer/accept binding.** The reviewer was right that the prose promised
   more than the code checked. The binding is now carried in the wire format
   (spec 0.4): `agreement.accept` requires `offeree` and must be signed by it;
   accepts must follow their offer; `decision`, `execution`,
   `delivery.attestation`, and `settlement` carry `agreement_ref`, checked for
   resolution (absent → `INSUFFICIENT_EVIDENCE`), chronology (before the
   accept → `UNTRUSTED`), and issuer (not the offeree → `UNTRUSTED`). An
   accept nothing references is PROVISIONAL. Adversarial vectors 17–17j cover
   wrong offeree, wrong signer, accept-before-offer, bound-before-accept,
   missing agreement, unreferenced accept, and duplicate offer ids. Spec 0.4
   is a new minor; 0.1–0.3 verify under their original semantics.

5. **Integration path.** `VERIFY_IN_5_MIN.md` now shows bundle verification
   and receipt verification side by side, with the explicit note that a
   receipt check does not recompute the result, and the "tamper one byte"
   step is qualified (canonicalization: formatting changes do not alter the
   signed object). Counts are consistent across the docs.

## The hostile corpus, as a permanent artifact

- `tools/hostile_input_probe.py` generates the corpus: the four documented
  reproductions, input-boundary cases (nesting, receipt count, invalid and
  deep JSON), and deterministic leaf/deletion mutations of the published
  vectors (seeded; 8 fixed + 200 mutations by default, `--sample N`,
  `--full` for the exhaustive set).
- It asserts **structured outcomes** — a verdict from the allowed set with
  coded errors, no traceback, no panic, exit consistent with the verdict —
  and with `--require-parity`, **Python↔Rust parity** of verdicts and
  error-code sets. CI runs it at `--sample 300 --require-parity`.
- An exhaustive in-process sweep of 26,280 leaf mutations plus key-deletion
  mutations across the full vector set raises nothing in the reference
  implementation.

## What we did not do

- No independent cryptographic audit; no property-based testing beyond the
  hostile corpus (leaf replacement and key deletion are not exhaustive of
  every structural or resource-exhaustion case).
- The hosted service's private implementation is unchanged apart from the
  verifier upgrade; CBOR and HMAC remain deferred with reasons in SPEC §11.
- Residual risk is unchanged: issuer honesty and pre-revocation compromise
  remain outer-layer problems (THREAT_MODEL.md).
- Two blemishes in the frozen 0.4.0 artifacts, fixed on `main` for the next
  release: the sdist omits `CONFORMANCE_TABLE.md`, and the crates.io short
  description still reads "0.1-0.3".

## Second round

The re-review invitation is open: `REVIEW_BRIEF.md` scopes the verification
receipt format, the 0.4 binding rules and their vectors, any conformance-table
cell that looks softened to dodge work, and any hostile-input class the probe
still misses. Publication is encouraged, and the report will be published
alongside our response, as this one is.
