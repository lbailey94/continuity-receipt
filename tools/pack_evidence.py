#!/usr/bin/env python3
"""Evidence pack export — one directory a counterparty can verify offline.

Produces, from a continuity-receipt bundle:

  bundle.json       byte-identical copy of the input
  manifest.json     SHA-256 of every file + bundle verdict summary
  verify.sh         one-command offline verification (no network)
  certificate.html  human-readable result with the honest limits
  README.txt        what this pack proves, and what it does not

Usage:
  python3 tools/pack_evidence.py BUNDLE.json [--out DIR] [--label TEXT]
"""
import argparse
import datetime as dt
import hashlib
import html
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import verify_bundle  # noqa: E402
from continuity_receipt.verify import MAX_BUNDLE_BYTES  # noqa: E402
from continuity_receipt.strict_json import loads as strict_json_loads  # noqa: E402

VERIFY_SH = """#!/bin/sh
# Offline verification of this evidence pack. No network access required.
# Verify pack file hashes before invoking a receipt verifier.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
python3 "$DIR/verify_pack.py"
if command -v continuity-receipt-verify >/dev/null 2>&1; then
  exec continuity-receipt-verify "$DIR/bundle.json"
fi
if python3 -c "import continuity_receipt" >/dev/null 2>&1; then
  exec python3 -m continuity_receipt.verify "$DIR/bundle.json"
fi
echo "No continuity-receipt verifier found. Install with: pip install continuity-receipt" >&2
exit 2
"""

README = """Evidence pack — continuity receipts
=====================================

Files
  bundle.json       byte-identical copy of the supplied receipt bundle
  manifest.json     SHA-256 digests of every file in this pack
  verify.sh         run this: it re-verifies the bundle offline
  certificate.html  a human-readable result (open in any browser)

Verifier requirements depend on the bundle spec:

  * continuity-receipt/0.1 through /0.4: published Python or Rust verifier
    0.4.0 (or newer compatible release).
  * /0.5 and /0.6: development prerelease/source build that explicitly
    supports that draft spec. Published 0.4.0 packages do not support them.

Before verification, verify.sh checks every file listed in manifest.json.
The manifest itself is an unsigned integrity index; obtain its digest through
a trusted channel if you need to authenticate the pack as a whole.

  sh verify.sh
  # or explicitly:
  # continuity-receipt-verify bundle.json
  # python3 -m continuity_receipt.verify bundle.json

What a TRUSTED verdict means
  - every receipt signature verifies against its issuer key
  - the chain links, chronology, and binding rules hold
  - any embedded anchor metadata passed the bundle verifier's checks; this
    does not verify detached timestamp proofs. Use the anchor tool with the
    required proof and independently trusted header or timestamp source.
  - revocation statements included in the bundle were checked under the
    applicable verifier rules; an omitted or stale external revocation source
    is outside this pack's evidence

What it does NOT mean
  - that the statements inside the receipts are true; issuer honesty is out
    of scope by design
  - that nothing was omitted before signing; only the recorded chain is
    covered
  - that the pack manifest was signed or obtained through a trusted channel
"""

PACK_VERIFIER = r'''#!/usr/bin/env python3
"""Check evidence-pack file hashes before running a receipt verifier."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
def unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"invalid pack manifest: duplicate member {key!r}")
        result[key] = value
    return result

manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"), object_pairs_hook=unique_members)
files = manifest.get("files")
expected_names = {"bundle.json", "verify.sh", "verify_pack.py", "README.txt", "certificate.html"}
if not isinstance(files, dict) or set(files) != expected_names:
    raise SystemExit("invalid pack manifest: files map must contain the exact evidence-pack file set")
for name, expected in files.items():
    path = Path(name)
    if path.name != name or path.is_absolute():
        raise SystemExit(f"invalid pack manifest path: {name!r}")
    actual = hashlib.sha256((root / path).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"pack hash mismatch: {name}")
if manifest.get("bundle_sha256") != files.get("bundle.json"):
    raise SystemExit("invalid pack manifest: bundle digest mismatch")
print("Evidence pack file hashes: OK (manifest is unsigned)")
'''


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def certificate_html(bundle: dict, result: dict, label: str, created: str) -> str:
    summary = result.get("summary") or {}
    errors = result.get("errors") or []
    receipt_rows = "".join(
        f"<tr><td>{esc(r.get('seq', ''))}</td>"
        f"<td><code>{esc(r.get('type', ''))}</code></td>"
        f"<td><code>{esc(r.get('issuer', ''))}</code></td></tr>"
        for r in bundle.get("receipts", [])
    )
    error_items = "".join(f"<li><code>{esc(e.get('code'))}</code> {esc(e.get('detail',''))}</li>" for e in errors) or "<li>none</li>"
    anchors = bundle.get("anchors") or []
    anchor_line = f"{len(anchors)} anchor(s) in bundle" if anchors else "no anchors in bundle"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Evidence certificate — {esc(label)}</title>
<style>
 body{{font:15px/1.6 ui-monospace,Menlo,monospace;background:#0b0f19;color:#e2e8f0;margin:0;padding:40px 20px}}
 main{{max-width:760px;margin:0 auto}}
 h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:16px;margin:26px 0 6px;color:#a78bfa}}
 .verdict{{font-size:26px;font-weight:700;margin:10px 0 2px}}
 .meta{{color:#94a3b8;font-size:13px}} table{{border-collapse:collapse;width:100%;font-size:13px}}
 td,th{{border:1px solid #1f2937;padding:6px 8px;text-align:left}} th{{background:#111827}}
 code{{color:#93c5fd}} .note{{color:#94a3b8;font-size:12px;margin-top:24px;border-top:1px solid #1f2937;padding-top:10px}}
</style></head><body><main>
<h1>Continuity receipt evidence certificate</h1>
<p class="meta">label: {esc(label)} · generated: {esc(created)} · spec: {esc(bundle.get('spec',''))} · task: <code>{esc(bundle.get('task_id',''))}</code></p>
<p class="verdict">{esc(result.get('verdict',''))}</p>
<p class="meta">receipts: {esc(summary.get('receipts',''))} · terminated: {esc(summary.get('terminated',''))} · settled: {esc(summary.get('settled',''))} · {esc(anchor_line)}</p>
<h2>Receipts</h2>
<table><tr><th>seq</th><th>type</th><th>issuer</th></tr>{receipt_rows}</table>
<h2>Errors / reasons</h2>
<ul>{error_items}</ul>
<h2>Verify this yourself (offline)</h2>
<p>Run <code>sh verify.sh</code> in this folder, or<br>
<code>continuity-receipt-verify bundle.json</code> with an implementation supporting this bundle's exact spec version.</p>
<p class="note">A valid result proves integrity and authorship of the recorded
claims — not that the claims are true; issuer honesty is out of scope by
design. <code>verify.sh</code> checks pack file hashes before verification;
the manifest is not signed.</p>
</main></body></html>
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pack-evidence", description=__doc__)
    parser.add_argument("bundle", help="path to a bundle JSON file")
    parser.add_argument("--out", default=None, help="output directory (default: <bundle>.pack)")
    parser.add_argument("--label", default=None, help="human label for the certificate")
    args = parser.parse_args(argv)

    bundle_path = Path(args.bundle)
    if not bundle_path.is_file():
        print(f"error: bundle not found: {bundle_path}", file=sys.stderr)
        return 2
    try:
        raw = bundle_path.read_bytes()
        if len(raw) > MAX_BUNDLE_BYTES:
            print(
                f"error: bundle exceeds verifier input limit ({len(raw)} bytes > {MAX_BUNDLE_BYTES})",
                file=sys.stderr,
            )
            return 2
        bundle = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        print(f"error: malformed bundle JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(bundle, dict):
        print("error: malformed bundle JSON: top-level value must be an object", file=sys.stderr)
        return 2
    result = verify_bundle(bundle).as_dict()

    out = Path(args.out) if args.out else bundle_path.with_suffix(bundle_path.suffix + ".pack")
    out.mkdir(parents=True, exist_ok=True)
    created = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    label = args.label or bundle_path.name

    (out / "bundle.json").write_bytes(raw)
    (out / "verify.sh").write_text(VERIFY_SH)
    (out / "verify.sh").chmod((out / "verify.sh").stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    (out / "README.txt").write_text(README)
    (out / "verify_pack.py").write_text(PACK_VERIFIER)
    (out / "certificate.html").write_text(certificate_html(bundle, result, label, created))

    files = {
        name: sha256_file(out / name)
        for name in ("bundle.json", "verify.sh", "README.txt", "verify_pack.py", "certificate.html")
    }
    manifest = {
        "kind": "continuity-receipt-evidence-pack/1",
        "created_at": created,
        "label": label,
        "bundle_sha256": files["bundle.json"],
        "verdict": result.get("verdict"),
        "spec": bundle.get("spec"),
        "verifier_requirement": (
            "published Python/Rust 0.4.0 or compatible" if bundle.get("spec") in {
                "continuity-receipt/0.1", "continuity-receipt/0.2",
                "continuity-receipt/0.3", "continuity-receipt/0.4",
            } else "development build explicitly supporting " + str(bundle.get("spec"))
        ),
        "summary": result.get("summary"),
        "files": files,
        "note": "verify with an implementation supporting the bundle spec; manifest is unsigned; issuer honesty out of scope",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(json.dumps({"pack": str(out), "verdict": result.get("verdict"), "files": sorted(list(files) + ["manifest.json"])}, indent=2))
    return 0 if result.get("verdict") == "TRUSTED" else 1


if __name__ == "__main__":
    sys.exit(main())
