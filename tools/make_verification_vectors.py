#!/usr/bin/env python3
"""Generate the verification-receipt test vectors (companion, version 1).

Receipts are built from real `verify_bundle` results (TRUSTED, PROVISIONAL,
INSUFFICIENT_EVIDENCE) plus hand-rolled negative cases for shape, consistency,
and tampering. Reproducible structure: fixed keys (`verifier-1`), fixed
`verified_at`, fixed bundle task ids. The bundle fixtures are generated through
`tools/make_vectors.py` helpers (receipt `issued_at` is time-dependent), so
regenerating rewrites the fixtures together with the receipts that bind to
them. Every vector is checked against the reference verifier before the
manifest is written, so the manifest can never drift from the implementation
silently.
"""
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import make_vectors as mv  # noqa: E402

from continuity_receipt import keys, verify_bundle  # noqa: E402
from continuity_receipt import revocations as revocations_mod  # noqa: E402
from continuity_receipt import verification  # noqa: E402
from continuity_receipt.canon import canonical_bytes, sha256_prefixed  # noqa: E402

VECTORS = ROOT / "vectors" / "verification"
VERIFIER_DID, VERIFIER_KEY = keys.generate(keys.deterministic_seed("verifier-1"))
OTHER_DID, _OTHER_KEY = keys.generate(keys.deterministic_seed("verifier-2"))
VERIFIED_AT = "2026-09-23T21:00:00Z"
IMPLEMENTATION_VERSION = "0.3.3"  # pinned in vectors; bump with the release


def write(name: str, document) -> str:
    path = VECTORS / name
    if isinstance(document, bytes):
        path.write_bytes(document)
    else:
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path.name


def sign_statement(statement: dict) -> dict:
    """Sign a hand-rolled statement (for negative vectors only)."""
    signed = dict(statement)
    signed["sig"] = {
        "alg": "ed25519",
        "key": VERIFIER_DID,
        "value": keys.sign(VERIFIER_KEY, canonical_bytes(statement)),
    }
    return signed


def base_statement(bundle: dict, result: dict) -> dict:
    return {
        "kind": verification.KIND,
        "version": verification.VERSION,
        "bundle_digest": sha256_prefixed(canonical_bytes(bundle)),
        "verdict": result["verdict"],
        "error_codes": [entry["code"] for entry in result["errors"]],
        "errors": result["errors"],
        "provisional_reasons": result["provisional_reasons"],
        "insufficient_reasons": result["insufficient_reasons"],
        "summary": result["summary"],
        "verified_at": VERIFIED_AT,
        "verifier": {"implementation": "python-reference", "version": IMPLEMENTATION_VERSION},
        "issuer": VERIFIER_DID,
    }


def issue(bundle: dict, result) -> dict:
    return verification.issue_verification_receipt(
        bundle,
        result,
        issuer=VERIFIER_DID,
        private_key=VERIFIER_KEY,
        version=IMPLEMENTATION_VERSION,
        verified_at=VERIFIED_AT,
    )


def revocation_statement(when: str) -> dict:
    statement = {"key": VERIFIER_DID, "revoked_at": when, "reason": "key-compromise"}
    return sign_statement(statement)


def main() -> int:
    VECTORS.mkdir(parents=True, exist_ok=True)

    bundle = mv.minimal_chain(
        task_id="urn:uuid:01997c4e-0000-7000-8000-000000000001", spec=mv.SPEC_03
    ).bundle()
    assert verify_bundle(bundle).verdict == "TRUSTED", "bundle fixture must verify TRUSTED"
    other_bundle = mv.full_chain(
        task_id="urn:uuid:01997c4e-0000-7000-8000-000000000002", spec=mv.SPEC_03
    ).bundle()
    assert verify_bundle(other_bundle).verdict == "TRUSTED", "other fixture must verify TRUSTED"
    write("bundle.json", bundle)
    write("other_bundle.json", other_bundle)

    # An erased-content fixture (copied byte-exact from the bundle vectors) for
    # the INSUFFICIENT_EVIDENCE receipt.
    erased_path = ROOT / "vectors" / "09_erased_content.json"
    write("erased_bundle.json", erased_path.read_bytes())
    erased_bundle = json.loads(erased_path.read_text(encoding="utf-8"))

    trusted_result = verify_bundle(bundle)
    valid = issue(bundle, trusted_result)

    rows = []

    def record(name, valid_expected, errors, note, bundle_file=None, revocations_file=None):
        rows.append(
            {
                "file": name,
                "expected_valid": valid_expected,
                "expected_errors": errors,
                "note": note,
                **({"bundle_file": bundle_file} if bundle_file else {}),
                **({"revocations_file": revocations_file} if revocations_file else {}),
            }
        )

    write("01_valid.json", valid)
    record("01_valid.json", True, [], "valid TRUSTED receipt; digest matches bundle.json",
           bundle_file="bundle.json")

    tampered_sig = json.loads(json.dumps(valid))
    first = tampered_sig["sig"]["value"][0]
    tampered_sig["sig"]["value"] = ("A" if first != "A" else "B") + tampered_sig["sig"]["value"][1:]
    write("02_tampered_signature.json", tampered_sig)
    record("02_tampered_signature.json", False, ["bad_signature"],
           "signature byte flipped after signing")

    tampered_verdict = json.loads(json.dumps(valid))
    tampered_verdict["verdict"] = "UNTRUSTED"
    write("03_tampered_verdict.json", tampered_verdict)
    record("03_tampered_verdict.json", False, ["bad_signature", "verdict_mismatch"],
           "verdict changed after signing (also inconsistent with its empty lists)")

    write("04_wrong_bundle.json", valid)
    record("04_wrong_bundle.json", False, ["bundle_digest_mismatch"],
           "valid receipt checked against a different bundle", bundle_file="other_bundle.json")

    bad_kind = json.loads(json.dumps(valid))
    bad_kind["kind"] = "continuity-receipt-verification-2"
    write("05_bad_kind.json", bad_kind)
    record("05_bad_kind.json", False, ["bad_kind", "bad_signature"],
           "kind changed after signing")

    bad_version = json.loads(json.dumps(valid))
    bad_version["version"] = 2
    write("06_bad_version.json", bad_version)
    record("06_bad_version.json", False, ["bad_version", "bad_signature"],
           "version changed after signing")

    bad_verdict = base_statement(bundle, trusted_result.as_dict())
    bad_verdict["verdict"] = "MAYBE"
    write("07_bad_verdict.json", sign_statement(bad_verdict))
    record("07_bad_verdict.json", False, ["bad_verdict"],
           "verdict outside the enum (signed as issued)")

    bad_time = base_statement(bundle, trusted_result.as_dict())
    bad_time["verified_at"] = "2026-09-23 21:00:00Z"
    write("08_bad_verified_at.json", sign_statement(bad_time))
    record("08_bad_verified_at.json", False, ["bad_verified_at"],
           "verified_at not RFC 3339 UTC (signed as issued)")

    missing_sig = json.loads(json.dumps(valid))
    del missing_sig["sig"]
    write("09_missing_sig.json", missing_sig)
    record("09_missing_sig.json", False, ["bad_signature_shape"], "sig member absent")

    wrong_issuer = json.loads(json.dumps(valid))
    wrong_issuer["issuer"] = OTHER_DID
    write("10_wrong_issuer.json", wrong_issuer)
    record("10_wrong_issuer.json", False, ["bad_signature"],
           "issuer swapped after signing (sig.key no longer matches)")

    bad_digest = base_statement(bundle, trusted_result.as_dict())
    bad_digest["bundle_digest"] = "sha256:not-hex"
    write("11_bad_digest_shape.json", sign_statement(bad_digest))
    record("11_bad_digest_shape.json", False, ["bad_bundle_digest"],
           "bundle_digest is not sha256:<64 hex> (signed as issued)")

    write("12_revoked_issuer.json", valid)
    write(
        "12_revoked_issuer.revocations.json",
        {
            "kind": revocations_mod.DOCUMENT_KIND,
            "version": revocations_mod.DOCUMENT_VERSION,
            "issued_at": VERIFIED_AT,
            "statements": [revocation_statement("2026-09-23T20:00:00Z")],
        },
    )
    record("12_revoked_issuer.json", False, ["key_revoked"],
           "issuer key revoked before verified_at", bundle_file="bundle.json",
           revocations_file="12_revoked_issuer.revocations.json")

    extra_member = base_statement(bundle, trusted_result.as_dict())
    extra_member["note"] = "additional signed member"
    write("13_unknown_member.json", sign_statement(extra_member))
    record("13_unknown_member.json", True, [],
           "additional member is signed and ignored by the verifier",
           bundle_file="bundle.json")

    bad_codes = base_statement(bundle, trusted_result.as_dict())
    bad_codes["error_codes"] = "none"
    write("14_bad_error_codes.json", sign_statement(bad_codes))
    record("14_bad_error_codes.json", False, ["bad_error_codes"],
           "error_codes is not an array of strings (signed as issued)")

    provisional_result = verify_bundle(bundle, require_anchor=True)
    assert provisional_result.verdict == "PROVISIONAL", provisional_result.as_dict()
    write("15_provisional_anchor_missing.json", issue(bundle, provisional_result))
    record("15_provisional_anchor_missing.json", True, [],
           "PROVISIONAL receipt recording anchor_missing (require_anchor run)",
           bundle_file="bundle.json")

    erased_result = verify_bundle(erased_bundle)
    assert erased_result.verdict == "INSUFFICIENT_EVIDENCE", erased_result.as_dict()
    write("16_insufficient_erased.json", issue(erased_bundle, erased_result))
    record("16_insufficient_erased.json", True, [],
           "INSUFFICIENT_EVIDENCE receipt recording erased content",
           bundle_file="erased_bundle.json")

    mismatch_verdict = base_statement(bundle, trusted_result.as_dict())
    mismatch_verdict["provisional_reasons"] = ["redacted_without_disclosure:receipts[1].body.x"]
    write("17_verdict_mismatch.json", sign_statement(mismatch_verdict))
    record("17_verdict_mismatch.json", False, ["verdict_mismatch"],
           "TRUSTED verdict with a non-empty provisional list (signed as issued)")

    mismatch_codes = base_statement(bundle, trusted_result.as_dict())
    mismatch_codes["verdict"] = "UNTRUSTED"
    mismatch_codes["errors"] = [{"code": "bad_signature", "detail": "signature does not verify",
                                 "receipt_id": None}]
    write("18_error_codes_mismatch.json", sign_statement(mismatch_codes))
    record("18_error_codes_mismatch.json", False, ["error_codes_mismatch"],
           "errors present but error_codes empty (signed as issued)")

    bad_errors = base_statement(bundle, trusted_result.as_dict())
    bad_errors["errors"] = "none"
    write("19_bad_errors.json", sign_statement(bad_errors))
    record("19_bad_errors.json", False, ["bad_errors"],
           "errors is not a list of {code} objects (signed as issued)")

    bad_summary = base_statement(bundle, trusted_result.as_dict())
    bad_summary["summary"] = []
    write("20_bad_summary.json", sign_statement(bad_summary))
    record("20_bad_summary.json", False, ["bad_summary"],
           "summary is not an object (signed as issued)")

    # Self-check every row against the reference verifier before writing.
    for row in rows:
        receipt = json.loads((VECTORS / row["file"]).read_text(encoding="utf-8"))
        bundle_input = None
        if row.get("bundle_file"):
            bundle_input = (VECTORS / row["bundle_file"]).read_bytes()
        revocation_input = None
        if row.get("revocations_file"):
            document = json.loads(
                (VECTORS / row["revocations_file"]).read_text(encoding="utf-8")
            )
            revocation_input = document["statements"]
        result = verification.verify_verification_receipt(
            receipt, bundle_input, revocation_input
        )
        assert result.valid == row["expected_valid"], (row["file"], result.as_dict())
        assert set(result.errors) == set(row["expected_errors"]), (row["file"], result.errors)
        if row["expected_valid"]:
            assert result.digest_match in (True, None), (row["file"], result.digest_match)

    (VECTORS / "manifest.json").write_text(
        json.dumps(
            {
                "kind": "continuity-receipt-verification-vectors",
                "version": 1,
                "issuer": VERIFIER_DID,
                "vectors": rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    index_lines = [
        "# Verification receipt — test vector index",
        "",
        "Companion to the core vector set (`vectors/INDEX.md`); wire format and",
        "semantics: `VERIFICATION_RECEIPTS.md`; schema:",
        "`schema/verification-receipt-1.schema.json`. Generated by",
        "`tools/make_verification_vectors.py`; machine-readable expectations in",
        "`manifest.json`. Verify with:",
        "`continuity-receipt-verify-receipt vectors/verification/<file>"
        " [--bundle vectors/verification/<bundle>] [--revocations <file>]`",
        "",
        "| Vector | Expected | Errors | Inputs | Notes |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        inputs = ", ".join(
            part for part in (row.get("bundle_file"), row.get("revocations_file")) if part
        ) or "—"
        index_lines.append(
            f"| {row['file']} | {'valid' if row['expected_valid'] else 'invalid'}"
            f" | {', '.join(row['expected_errors']) or '—'} | {inputs} | {row['note']} |"
        )
    (VECTORS / "INDEX.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    print(f"wrote {len(rows)} verification vectors to {VECTORS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
