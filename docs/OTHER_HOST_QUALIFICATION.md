# Other-host qualification packet for Continuity Receipt 0.5

This packet assesses a **real producer capture** made on a clean adopter host.
The public Mandala gate-lite line remains on published receipt spec 0.4. A
private candidate at
`8ea8c7eb17d576efdbfa0d311b007dd7b95f8389` pins the published
`continuity-receipt==0.5.0` package and emits spec 0.5, and a checked-in
2026-09-28 capture is same-host maintainer evidence. That capture is not an
independent-host qualification. This packet remains a pending gate until a
real capture is produced and independently reviewed on another host. Do not
run it against a fixture or reinterpret an existing 0.4 capture as adoption
evidence.

## Inputs and profile

Retain the exact raw bundle bytes, a separate state snapshot JSON, the actual files referenced by that snapshot under one artifact root, and `producer-metadata.json`. Metadata must contain nonempty `command`, `host`, and `operator` strings, `captured_bundle_sha256` matching the exact raw bundle bytes, and a `pins` object with a full lowercase `source_commit` Git object id plus `python_verifier_sha256` and `rust_verifier_sha256` in `sha256:<lowercase hex>` form. The assessor hashes the executable named first in each command (for a Python module invocation, this is the Python interpreter), requires the declared source commit to match the assessor checkout HEAD, and requires the verifier source files in that checkout to be clean. This verifies the local source checkout and exact command executable bytes against the metadata; it does not provide a reproducible-build attestation for a prebuilt Rust executable. Keep environment/installation transcript and the unedited producer output beside these artifacts.

The assessor supports the explicit `file-snapshot-v1` profile only. The separate state file is exactly `{"files":[{"path":"relative/posix/path","size":N,"sha256":"sha256:<lowercase hex>"}, ...]}`. Entries must be sorted by unique normalized relative path. `count` is the number of entries, not a byte count. `head_digest` is `sha256:` plus SHA-256 over UTF-8 compact JSON for `{"files": entries}` with recursively sorted keys, no whitespace, and no floats. The signed state commitment must declare `state_kind: "file-snapshot-v1"` and have matching count and digest. The snapshot file describes the producer's referenced state; it must be obtained separately and retained unchanged.

## Clean-host procedure

1. On the second laptop, install from the selected pinned source commit using the project's documented clean-install steps. Record OS/kernel, Python/Rust versions, commands, and any errors. Build Python and Rust verifiers from that same pinned source and record executable hashes. Use an operator able to explain how the account and host were administered; a hostname alone does not establish independent administration.
2. From the selected private candidate source, run the actual Mandala gate-lite producer with the intended test input and capture the exact emitted 0.5 bundle and the referenced state snapshot separately. Preserve the producer command, stdout/stderr, environment details that matter, source and executable pins, operator/host record, and file hashes. Do not edit, reserialize, or regenerate the bundle after capture. The public 0.4 line cannot supply this 0.5 capture.
3. From the pinned Continuity Receipt checkout, run the offline assessor. Example (replace paths and executable names with the locally built, hashed binaries):

   ```sh
   python3 tools/qualify_adopter_capture.py \
     --bundle capture/bundle.json \
     --state capture/state.json \
     --metadata capture/producer-metadata.json \
     --artifact-root capture/state-files \
     --python-verifier-command 'python3 -m continuity_receipt.verify' \
     --rust-verifier-command './rust/target/release/continuity-receipt-verify' \
     --output capture/qualification.json
   ```

   Store the JSON report with the capture. Verifier command values are parsed with shell-like quoting into an argument vector, then executed directly without a shell. `PASS` means the captured raw bundle hash matches metadata and stayed unchanged during assessment, the actual bytes of every referenced file matched its declared path/size/hash, the explicit state commitment matched, the source checkout and executable hashes matched recorded pins, and both CLI runs returned the same `TRUSTED` verdict and error codes. It does not authenticate the operator, prove how a prebuilt Rust executable was produced, or independently confirm who recorded the pins; a reviewer must check the evidence against the host and source. Missing referenced files produce `INCOMPLETE`; mismatching bytes fail.
4. Perform a negative tamper check on a copy of the captured bundle: change one byte in the signed state commitment (or the separately supplied state snapshot), then rerun the corresponding verification/assessment. Preserve the modified copy, command, output, and expected rejection. Never overwrite the original capture. The positive assessor report does not itself execute this negative control.

## Interpretation and remaining gates

`FAIL` means a mismatch, invalid input, non-`TRUSTED` result, or verifier disagreement. `INCOMPLETE` means required evidence or commands were not supplied. Temporary fixtures used by unit tests are mechanics tests only and must never be presented as adopter evidence.

Even a passing second-laptop capture is source/install and verifier interoperability evidence. It does not prove actual sandbox enforcement, hostile-tenant isolation, safe operation on an internet-facing VPS, or live-network readiness. VPS staging requires a separate host-specific review of kernel capabilities, enforced denial behavior, filesystem/network boundaries, privileges, secrets, logging, restart and recovery. Keep the independent review gate open until a reviewer other than the producer/operator can retrieve and assess the raw artifacts, pins, procedure, and results.
