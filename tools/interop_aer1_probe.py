#!/usr/bin/env python3
"""Interop probe: verify a live AER-1 receipt (draft-zambo-aer1-20).

AER-1 resolves every receipt at a stable public URL and offers a machine
verifier; both are reachable without an account, key, or token (draft §3,
§6, §9). This probe exercises the published verification procedure against
the live reference implementation (v1 and v2 verifier endpoints):

  1. the public receipt URL resolves (HTTP 200) without credentials
  2. the retrieved record's id matches the requested receipt id
  3. canonical_bytes decode as strict UTF-8
  4. sha256 over the decoded bytes equals output_hash
  5. the decoded length matches canonical_byte_length (when published)
  6. the verifier reports a passing commitment status ("verified" for 0.4
     receipts or "commitment_matches" for 0.3 receipts; v2
     checks.commitment_matches.passed == true)

Compatibility probe only: it checks the draft's published bytes against a
live implementation and makes no claim beyond these checks. Default fixture:
receipt 130da435-e157-498e-af90-605866a86a27 (the §3 0.3 fixture; first probed
2026-09-30) and optional 0.4 fixture abe8253b-3fee-4efc-b692-7427394b90b5.
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

DEFAULT_RECEIPT_ID = "130da435-e157-498e-af90-605866a86a27"
V04_RECEIPT_ID = "abe8253b-3fee-4efc-b692-7427394b90b5"
DEFAULT_BASE_URL = "https://zambo.dev"


def _is_strict_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _fetch(url: str, timeout: float):
    request = urllib.request.Request(url, headers={"user-agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


def probe_receipt(base: str, receipt_id: str, timeout: float) -> dict:
    page_url = f"{base}/run/{receipt_id}"
    verify_url = f"{base}/api/receipt/{receipt_id}/verify"
    verify_v2_url = f"{base}/api/v2/receipt/{receipt_id}/verify"

    results = {
        "probe": "aer1-live-receipt",
        "draft": "draft-zambo-aer1-20",
        "receipt_id": receipt_id,
        "checks": {},
    }

    # 1. public resolution, no credentials
    try:
        status, _ = _fetch(page_url, timeout)
        results["checks"]["public_url_resolves"] = status == 200
    except (urllib.error.URLError, OSError) as error:
        results["checks"]["public_url_resolves"] = False
        results["error"] = f"public URL: {error}"

    # 2-6. machine verifier record (v1 + optional v2 check inspection)
    record = None
    try:
        _, raw = _fetch(verify_url, timeout)
        record = json.loads(raw)
    except Exception as error:  # noqa: BLE001 - probe reports, never raises
        results["error"] = f"verifier fetch: {error}"

    v2_record = None
    try:
        _, raw_v2 = _fetch(verify_v2_url, timeout)
        v2_record = json.loads(raw_v2)
    except Exception:  # noqa: BLE001
        v2_record = None

    if record is not None:
        results["receipt_schema_version"] = record.get("receipt_schema_version")
        results["verification_status"] = record.get("verification_status")
        results["checks"]["id_matches"] = record.get("id") == receipt_id
        v_status = record.get("verification_status")
        v2_comm = (
            ((v2_record or {}).get("checks") or {})
            .get("commitment_matches", {})
            .get("passed")
        )
        results["checks"]["verification_status_verified"] = (
            v_status in ("verified", "commitment_matches")
            or record.get("commitment_matches") is True
            or v2_comm is True
        )
        try:
            canonical = base64.b64decode(record["canonical_bytes"], validate=True)
            results["checks"]["canonical_utf8"] = _is_strict_utf8(canonical)
            digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
            results["recomputed_output_hash"] = digest
            results["checks"]["output_hash_matches"] = (
                digest == record.get("output_hash")
            )
            length = record.get("canonical_byte_length")
            if length is not None:
                results["checks"]["canonical_length_matches"] = len(canonical) == length
        except (KeyError, ValueError) as error:
            results["checks"]["output_hash_matches"] = False
            results["error"] = f"canonical bytes: {error}"

    if isinstance(v2_record, dict) and isinstance(v2_record.get("checks"), dict):
        results["v2_checks"] = {
            k: (v.get("status") if isinstance(v, dict) else v)
            for k, v in v2_record["checks"].items()
        }

    ok = bool(results["checks"]) and all(results["checks"].values())
    results["all_checks_pass"] = ok
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--receipt-id", default=DEFAULT_RECEIPT_ID)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument(
        "--include-v04",
        action="store_true",
        help=f"also probe schema 0.4 fixture ({V04_RECEIPT_ID})",
    )
    args = parser.parse_args(argv)

    base = args.base_url.rstrip("/")
    results = probe_receipt(base, args.receipt_id, args.timeout)
    if args.include_v04 and args.receipt_id != V04_RECEIPT_ID:
        v04 = probe_receipt(base, V04_RECEIPT_ID, args.timeout)
        results["v04_fixture"] = v04
        ok = results["all_checks_pass"] and v04["all_checks_pass"]
    else:
        ok = results["all_checks_pass"]

    print(json.dumps(results, indent=2))
    print("\nINTEROP PROBE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
