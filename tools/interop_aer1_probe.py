#!/usr/bin/env python3
"""Interop probe: verify a live AER-1 receipt (draft-zambo-aer1-04).

AER-1 resolves every receipt at a stable public URL and offers a machine
verifier; both are reachable without an account, key, or token (draft §3,
§6, §9). This probe exercises the published verification procedure against
the live reference implementation:

  1. the public receipt URL resolves (HTTP 200) without credentials
  2. the retrieved record's id matches the requested receipt id
  3. canonical_bytes decode as strict UTF-8
  4. sha256 over the decoded bytes equals output_hash
  5. the decoded length matches canonical_byte_length (when published)
  6. the record reports verification_status "verified"

Compatibility probe only: it checks the draft's published bytes against a
live implementation and makes no claim beyond these checks. Default fixture:
receipt 130da435-e157-498e-af90-605866a86a27 (the §3 example; first probed
2026-09-30, matched).
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

DEFAULT_RECEIPT_ID = "130da435-e157-498e-af90-605866a86a27"
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--receipt-id", default=DEFAULT_RECEIPT_ID)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args(argv)

    receipt_id = args.receipt_id
    base = args.base_url.rstrip("/")
    page_url = f"{base}/run/{receipt_id}"
    verify_url = f"{base}/api/receipt/{receipt_id}/verify"

    results = {
        "probe": "aer1-live-receipt",
        "draft": "draft-zambo-aer1-04",
        "receipt_id": receipt_id,
        "checks": {},
    }

    # 1. public resolution, no credentials
    try:
        status, _ = _fetch(page_url, args.timeout)
        results["checks"]["public_url_resolves"] = status == 200
    except (urllib.error.URLError, OSError) as error:
        results["checks"]["public_url_resolves"] = False
        results["error"] = f"public URL: {error}"

    # 2-6. machine verifier record
    record = None
    try:
        _, raw = _fetch(verify_url, args.timeout)
        record = json.loads(raw)
    except Exception as error:  # noqa: BLE001 - probe reports, never raises
        results["error"] = f"verifier fetch: {error}"

    if record is not None:
        results["checks"]["id_matches"] = record.get("id") == receipt_id
        results["checks"]["verification_status_verified"] = (
            record.get("verification_status") == "verified"
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

    ok = bool(results["checks"]) and all(results["checks"].values())
    results["all_checks_pass"] = ok
    print(json.dumps(results, indent=2))
    print("\nINTEROP PROBE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
