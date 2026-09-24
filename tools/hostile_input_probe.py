#!/usr/bin/env python3
"""Hostile-input probe: assert both verifiers stay structured on bad input.

Generates a corpus of malformed bundles — the four documented reproductions
from the independent review, input-boundary cases, and deterministic leaf and
deletion mutations of the published vectors — runs each through the Python and
Rust CLI surfaces, and asserts every run returns a structured JSON outcome
(verdict + coded errors) with no traceback and no panic. A crash, a non-JSON
reply, or an exit/verdict disagreement is a failure. With `--require-parity`
(mutually exclusive with `--python-only`, so the check can never pass
vacuously) it additionally fails when the implementations disagree on the
verdict or the error-code set for a case.

    python3 tools/hostile_input_probe.py                 # 208 cases (8 fixed + 200 mutations)
    python3 tools/hostile_input_probe.py --sample 300    # CI default size
    python3 tools/hostile_input_probe.py --full          # every leaf + deletion mutation (slow)
    python3 tools/hostile_input_probe.py --python-only   # no Rust binary needed
    python3 tools/hostile_input_probe.py --require-parity
    python3 tools/hostile_input_probe.py --json          # machine-readable summary
    python3 tools/hostile_input_probe.py --manifest-out hostile-manifest.json
                                                         # pin the corpus for the
                                                         # hosted conformance referee

Exit code is 0 only when every case produced a structured outcome.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors"
VERDICTS = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")
MUTATIONS = (None, {}, [], 0, "x", True)
RUST_BINS = (
    ROOT / "rust" / "target" / "debug" / "continuity-receipt-verify",
    ROOT / "rust" / "target" / "release" / "continuity-receipt-verify",
)


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def leaf_paths(node, prefix=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from leaf_paths(value, prefix + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from leaf_paths(value, prefix + (index,))
    else:
        yield prefix


def set_path(node, path, value):
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


def key_paths(node, prefix=()):
    """Paths to every dict key and list index (structural deletion sites)."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield prefix + (key,)
            yield from key_paths(value, prefix + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield prefix + (index,)
            yield from key_paths(value, prefix + (index,))


def delete_path(node, path):
    for part in path[:-1]:
        node = node[part]
    del node[path[-1]]


def documented_cases() -> list[tuple[str, object]]:
    base = load("02_happy_full.json")
    cases: list[tuple[str, object]] = []

    bundle = copy.deepcopy(base)
    bundle["receipts"][0] = None
    cases.append(("repro.receipts[0]=null", bundle))

    bundle = copy.deepcopy(base)
    bundle["receipts"][0]["issuer"] = None
    cases.append(("repro.issuer=null", bundle))

    bundle = copy.deepcopy(base)
    for receipt in bundle["receipts"]:
        if receipt.get("type") == "settlement":
            receipt["body"]["amount"] = None
    cases.append(("repro.settlement.amount=null", bundle))

    bundle = copy.deepcopy(base)
    bundle["anchors"] = [None]
    cases.append(("repro.anchors[0]=null", bundle))

    bundle = copy.deepcopy(base)
    deep = "leaf"
    for _ in range(100):
        deep = {"next": deep}
    bundle["receipts"][0]["body"]["deep"] = deep
    cases.append(("boundary.nesting_too_deep", bundle))

    bundle = {
        "spec": "continuity-receipt/0.3",
        "task_id": "urn:uuid:00000000-0000-7000-8000-000000000000",
        "receipts": [{}] * 10_001,
    }
    cases.append(("boundary.too_many_receipts", bundle))

    cases.append(("boundary.invalid_json", '{"spec": "continuity-receipt/0.3",'))
    cases.append(("boundary.deep_json", '{"a":' * 5000 + "1" + "}" * 5000))
    return cases


def mutation_cases(full: bool, sample: int) -> list[tuple[str, object]]:
    candidates: list[tuple[str, str, tuple, object]] = []
    manifest = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["vectors"]:
        base = load(entry["file"])
        for path in leaf_paths(base):
            for value in MUTATIONS:
                candidates.append(("set", entry["file"], path, value))
        for path in key_paths(base):
            candidates.append(("delete", entry["file"], path, None))
    rng = random.Random(0xC0FFEE)
    rng.shuffle(candidates)
    selected = candidates if full else candidates[:sample]
    cases = []
    for kind, name, path, value in selected:
        bundle = load(name)
        label = ".".join(str(part) for part in path)
        if kind == "set":
            set_path(bundle, path, value)
            cases.append((f"mutate.set.{name}:{label}={value!r}", bundle))
        else:
            delete_path(bundle, path)
            cases.append((f"mutate.delete.{name}:{label}", bundle))
    return cases


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=120)


def check_structured(
    label: str, language: str, proc: subprocess.CompletedProcess
) -> tuple[str | None, tuple[str, ...] | None, str | None]:
    """Return (verdict, sorted codes, failure_reason); reason is None when structured."""
    if proc.returncode not in (0, 1):
        return None, None, f"exit {proc.returncode} (stderr: {proc.stderr.strip()[:120]!r})"
    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        return None, None, f"stdout is not JSON (stderr: {proc.stderr.strip()[:120]!r})"
    if not isinstance(payload, dict):
        return None, None, "stdout JSON is not an object"
    verdict = payload.get("verdict")
    if verdict not in VERDICTS:
        return None, None, f"verdict {verdict!r} is not one of {VERDICTS}"
    errors = payload.get("errors")
    if not isinstance(errors, list) or not all(
        isinstance(entry, dict) and isinstance(entry.get("code"), str) for entry in errors
    ):
        return None, None, f"errors is not a list of coded objects: {errors!r}"
    if proc.returncode != (0 if verdict == "TRUSTED" else 1):
        return None, None, f"exit {proc.returncode} disagrees with verdict {verdict}"
    return verdict, tuple(sorted(entry["code"] for entry in errors)), None


def write_hostile_manifest(path: str, full: bool, sample: int) -> int:
    """Pin the hostile corpus for the hosted conformance referee.

    Runs the reference (Python) verifier over every case, fails when any case
    is not structured, and writes labels plus reference expectations:
    documented reproductions and boundary cases pin verdict + codes; mutation
    cases require a structured outcome only (their exact codes are not part
    of the spec surface).
    """
    from continuity_receipt import records  # local import: CLI-only runs stay library-free

    pinned_prefixes = ("repro.", "boundary.")
    vectors = []
    cases = documented_cases() + mutation_cases(full, sample)
    with tempfile.TemporaryDirectory(prefix="cr-hostile-manifest-") as tmp:
        for index, (name, payload) in enumerate(cases):
            case_path = Path(tmp) / f"case-{index}.json"
            if isinstance(payload, str):
                case_path.write_text(payload, encoding="utf-8")
            else:
                case_path.write_text(json.dumps(payload), encoding="utf-8")
            proc = run([sys.executable, "-m", "continuity_receipt.verify", str(case_path)])
            verdict, codes, reason = check_structured(name, "python", proc)
            if reason is not None:
                print(
                    f"error: reference implementation is not structured on {name}: {reason}",
                    file=sys.stderr,
                )
                return 2
            vector = {"case": name, "require": "structured"}
            if name.startswith(pinned_prefixes):
                vector["expected_verdict"] = verdict
                vector["expected_codes"] = list(codes)
            vectors.append(vector)

    manifest = {
        "kind": "continuity-receipt-hostile-vectors",
        "version": 1,
        "spec": records.SPEC_ID,
        "generator": "tools/hostile_input_probe.py",
        "seed": "0xC0FFEE",
        "sample": sample,
        "full": full,
        "vectors": vectors,
    }
    Path(path).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} hostile cases to {path}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hostile_input_probe")
    parser.add_argument("--full", action="store_true", help="exhaustive leaf mutations (slow)")
    parser.add_argument("--sample", type=int, default=200, help="mutation sample size (default 200)")
    parser.add_argument(
        "--manifest-out",
        metavar="PATH",
        help="write the pinned hostile manifest for the conformance referee and exit",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--python-only", action="store_true", help="skip the Rust CLI")
    mode.add_argument(
        "--require-parity",
        action="store_true",
        help="fail when Python and Rust disagree (verdict or error-code set); requires Rust",
    )
    parser.add_argument("--rust-bin", metavar="PATH", help="Rust verifier binary to use")
    parser.add_argument("--json", action="store_true", help="print a machine-readable summary")
    args = parser.parse_args(argv)

    if args.manifest_out:
        return write_hostile_manifest(args.manifest_out, args.full, args.sample)

    rust_bin = None
    if not args.python_only:
        rust_bin = Path(args.rust_bin) if args.rust_bin else next(
            (path for path in RUST_BINS if path.exists()), None
        )
        if rust_bin is None:
            print(
                "error: no Rust binary found (cargo build first, or pass --rust-bin/--python-only)",
                file=sys.stderr,
            )
            return 2

    cases = documented_cases() + mutation_cases(args.full, args.sample)
    failures: list[dict] = []
    outcomes_by_case: dict[str, dict[str, tuple[str, tuple[str, ...]]]] = {}
    ran = 0
    with tempfile.TemporaryDirectory(prefix="cr-hostile-") as tmp:
        for index, (name, payload) in enumerate(cases):
            path = Path(tmp) / f"case-{index}.json"
            if isinstance(payload, str):
                path.write_text(payload, encoding="utf-8")
            else:
                path.write_text(json.dumps(payload), encoding="utf-8")

            languages = [("python", [sys.executable, "-m", "continuity_receipt.verify", str(path)])]
            if rust_bin is not None:
                languages.append(("rust", [str(rust_bin), str(path)]))
            for language, cmd in languages:
                ran += 1
                proc = run(cmd)
                verdict, codes, reason = check_structured(name, language, proc)
                if reason is not None:
                    failures.append({"case": name, "language": language, "reason": reason})
                elif verdict is not None and codes is not None:
                    outcomes_by_case.setdefault(name, {})[language] = (verdict, codes)

    parity_mismatches = []
    for case, pair in outcomes_by_case.items():
        if len(pair) != 2:
            continue
        if pair["python"][0] != pair["rust"][0]:
            parity_mismatches.append(
                {"case": case, "kind": "verdict", "python": pair["python"][0], "rust": pair["rust"][0]}
            )
        elif pair["python"][1] != pair["rust"][1]:
            parity_mismatches.append(
                {
                    "case": case,
                    "kind": "codes",
                    "python": list(pair["python"][1]),
                    "rust": list(pair["rust"][1]),
                }
            )
    if args.require_parity:
        failures.extend(
            {
                "case": mismatch["case"],
                "language": "python/rust",
                "reason": (
                    f"{mismatch['kind']} parity: python={mismatch['python']} "
                    f"rust={mismatch['rust']}"
                ),
            }
            for mismatch in parity_mismatches
        )

    summary = {
        "cases": len(cases),
        "runs": ran,
        "languages": ["python"] + ([] if rust_bin is None else ["rust"]),
        "parity_mismatches": parity_mismatches,
        "failures": failures,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        parity_note = (
            f", {len(parity_mismatches)} parity mismatches" if rust_bin is not None else ""
        )
        print(
            f"hostile-input probe: {len(cases)} cases, {ran} runs "
            f"({', '.join(summary['languages'])}), {len(failures)} failures{parity_note}"
        )
        for mismatch in parity_mismatches[:10]:
            print(
                f"  PARITY {mismatch['case']} [{mismatch['kind']}]: "
                f"python={mismatch['python']} rust={mismatch['rust']}"
            )
        for failure in failures[:20]:
            print(f"  FAIL [{failure['language']}] {failure['case']}: {failure['reason']}")
        if len(failures) > 20:
            print(f"  ... and {len(failures) - 20} more")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
