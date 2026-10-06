# Example 03: public-text claim review and external artifact hashes

This is a synthetic, deterministic-key mechanics example. Its short source
excerpt is copied verbatim from the repository README at the pinned commit in
`claims.json`; the program does not retrieve the URL. The two labels show the
difference between a statement directly present in an excerpt and a stronger
inference that the excerpt does not establish. They are human-authored review
labels, not an automated truth grader.

From the repository root:

```sh
python3 examples/03_public_text_claim_review/run_example.py
python3 examples/03_public_text_claim_review/verify_capture.py \
  examples/03_public_text_claim_review/out
```

To keep generated evidence outside the checkout, pass `--out /tmp/claim-review`.

`run_example.py` uses the existing 0.5 `TaskChain` and verification-receipt
APIs. It binds hashes of the excerpt, claim grades, and provenance into the
signed `task.decision`, then writes a capture manifest with SHA-256 and byte
count for each actual file, including the raw bundle and signed verification
receipt.

`verify_capture.py` is a separate consumer step. It reads actual files from
the supplied capture directory and checks their hashes against the unsigned
capture manifest. It also requires the exact expected artifact set and checks
the excerpt, claim, and provenance hashes and byte counts against the signed
`task.decision`, so rewriting the unsigned manifest cannot authorize changed
input bytes. It recomputes the action hash and checks that the signed grade
summary agrees with the claims file. Separately, it runs the local bundle
verifier and checks the signed verification receipt against the canonical
bundle digest. A valid protocol bundle and matching external artifact bytes
are distinct checks.
The example's small grade vocabulary and exact-quote check are review-policy
validation; they do not prove that a source statement is factually true or
that an omitted inference is false.

The example demonstrates only that this fixture's bytes match its manifest,
that the synthetic issuer signed the bundle, and that its signed verification
receipt matches the bundle and local verifier verdict. It does not establish
the source's truth, live retrieval, factual accuracy of the release statement,
package availability, real independent verification, issuer identity,
adoption, or any legal/compliance conclusion. The key seed is public test
material and must never sign real evidence.

Negative checks can be exercised without changing the original output:

```sh
cp -a examples/03_public_text_claim_review/out /tmp/claim-review-copy
printf 'changed\n' >> /tmp/claim-review-copy/source_excerpt.txt
python3 examples/03_public_text_claim_review/verify_capture.py /tmp/claim-review-copy
# Expected: FAIL with an artifact hash or size mismatch.
rm /tmp/claim-review-copy/source_excerpt.txt
python3 examples/03_public_text_claim_review/verify_capture.py /tmp/claim-review-copy
# Expected: FAIL because the referenced artifact is missing.
```
