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
import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import verify_bundle  # noqa: E402

VERIFY_SH = """#!/bin/sh
# Offline verification of this evidence pack. No network access required.
# Requires any continuity-receipt implementation >= 0.3.3:
#   pip install continuity-receipt     (or)     cargo add continuity-receipt
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
if command -v continuity-receipt-verify >/dev/null 2>&1; then
  exec continuity-receipt-verify "$DIR/bundle.json"
fi
if python3 -c "import continuity_receipt" >/dev/null 2>&1; then
  exec python3 -c "import sys; from continuity_receipt.verify import main; sys.exit(main(['$DIR/bundle.json']))"
fi
echo "No continuity-receipt verifier found. Install with: pip install continuity-receipt" >&2
exit 2
"""

README = """Evidence pack — continuity receipts
=====================================

Files
  bundle.json       the receipt chain(s), exactly as issued (canonical JSON)
  manifest.json     SHA-256 digests of every file in this pack
  verify.sh         run this: it re-verifies the bundle offline
  certificate.html  a human-readable result (open in any browser)

Verify (needs any continuity-receipt implementation >= 0.3.3):

  sh verify.sh
  # or explicitly:
  # continuity-receipt-verify bundle.json
  # python3 -m continuity_receipt.verify bundle.json

What a TRUSTED verdict means
  - every receipt signature verifies against its issuer key
  - the chain links, chronology, and binding rules hold
  - where the spec requires it, anchors/revocations were checked

What it does NOT mean
  - that the statements inside the receipts are true; issuer honesty is out
    of scope by design
  - that nothing was omitted before signing; only the recorded chain is
    covered
  - that we (the pack exporter) verified anything beyond running the
    reference verifier; check manifest.json to confirm the bundle bytes
"""


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
<code>continuity-receipt-verify bundle.json</code> with any continuity-receipt implementation &ge; 0.3.3.</p>
<p class="note">A valid result proves integrity and authorship of the recorded
claims — not that the claims are true; issuer honesty is out of scope by
design. Check <code>manifest.json</code> to confirm the bundle bytes are the
ones this certificate was generated from.</p>
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
    bundle = json.loads(bundle_path.read_bytes())
    result = verify_bundle(bundle).as_dict()

    out = Path(args.out) if args.out else bundle_path.with_suffix(bundle_path.suffix + ".pack")
    out.mkdir(parents=True, exist_ok=True)
    created = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    label = args.label or bundle_path.name

    shutil.copyfile(bundle_path, out / "bundle.json")
    (out / "verify.sh").write_text(VERIFY_SH)
    (out / "verify.sh").chmod((out / "verify.sh").stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    (out / "README.txt").write_text(README)
    (out / "certificate.html").write_text(certificate_html(bundle, result, label, created))

    files = {
        name: sha256_file(out / name)
        for name in ("bundle.json", "verify.sh", "README.txt", "certificate.html")
    }
    manifest = {
        "kind": "continuity-receipt-evidence-pack/1",
        "created_at": created,
        "label": label,
        "bundle_sha256": files["bundle.json"],
        "verdict": result.get("verdict"),
        "summary": result.get("summary"),
        "files": files,
        "note": "verify with any continuity-receipt implementation >= 0.3.3; issuer honesty out of scope",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(json.dumps({"pack": str(out), "verdict": result.get("verdict"), "files": sorted(list(files) + ["manifest.json"])}, indent=2))
    return 0 if result.get("verdict") == "TRUSTED" else 1


if __name__ == "__main__":
    sys.exit(main())
