#!/usr/bin/env node
/**
 * Verification-receipt parity harness: run every vector in
 * `vectors/verification/manifest.json` through the JS verifier and compare
 * against the manifest expectations and a Python baseline
 * (test/python-baseline-receipts.json, produced by
 * `continuity-receipt-verify-receipt` from the reference package).
 *
 * Usage: node tools/parity-receipts.mjs [--baseline PATH] [--quiet] [--strict]
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { parseStrictJson, verifyVerificationReceipt } from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const vectorsDir = path.join(repoRoot, "vectors", "verification");

const args = process.argv.slice(2);
let baselinePath = path.join(here, "..", "test", "python-baseline-receipts.json");
let quiet = false;
for (let index = 0; index < args.length; index++) {
  if (args[index] === "--baseline") baselinePath = args[index + 1];
  if (args[index] === "--quiet") quiet = true;
}

const manifest = JSON.parse(await readFile(path.join(vectorsDir, "manifest.json"), "utf8"));
const entries = manifest.vectors;

let baseline = null;
if (existsSync(baselinePath)) {
  baseline = JSON.parse(await readFile(baselinePath, "utf8"));
}
const baselineByFile = new Map((baseline ?? []).map((entry) => [entry.file, entry]));

const pad = (text, width) => String(text).padEnd(width).slice(0, width);
const fmt = (list) => (Array.isArray(list) ? list.join(",") || "-" : String(list));
const rows = [];
let validDiffs = 0;
let errorDiffs = 0;
let manifestDiffs = 0;
let digestDiffs = 0;
let verdictDiffs = 0;

for (const entry of entries) {
  const file = entry.file;
  const receiptPath = path.join(vectorsDir, file);
  const python = baselineByFile.get(file);
  if (!existsSync(receiptPath)) {
    rows.push({ file, expected: entry.expected_valid, python: "-", got: "MISSING", note: "file missing" });
    manifestDiffs++;
    continue;
  }
  const receipt = parseStrictJson(await readFile(receiptPath));
  const bundle = entry.bundle_file
    ? parseStrictJson(await readFile(path.join(vectorsDir, entry.bundle_file)))
    : null;
  let revocations = null;
  if (entry.revocations_file) {
    const document = JSON.parse(await readFile(path.join(vectorsDir, entry.revocations_file), "utf8"));
    revocations = document.statements;
  }
  const result = await verifyVerificationReceipt(receipt, bundle, revocations);
  const notes = [];

  if (result.valid !== entry.expected_valid) {
    manifestDiffs++;
    notes.push(`manifest expected_valid ${entry.expected_valid}`);
  }
  const expectedSet = [...(entry.expected_errors ?? [])].sort();
  const gotSet = [...result.errors].sort();
  if (JSON.stringify(expectedSet) !== JSON.stringify(gotSet)) {
    manifestDiffs++;
    notes.push(`manifest expected_errors ${JSON.stringify(expectedSet)}`);
  }

  if (python) {
    if (result.valid !== python.valid) {
      validDiffs++;
      notes.push(`VALID python=${python.valid}`);
    }
    if (JSON.stringify(result.errors) !== JSON.stringify(python.errors)) {
      errorDiffs++;
      notes.push(`errors py=${JSON.stringify(python.errors)}`);
    }
    if (result.digest_match !== python.digest_match) {
      digestDiffs++;
      notes.push(`digest_match py=${JSON.stringify(python.digest_match)}`);
    }
    if (result.verdict !== python.verdict) {
      verdictDiffs++;
      notes.push(`verdict py=${JSON.stringify(python.verdict)}`);
    }
  }
  rows.push({
    file,
    expected: entry.expected_valid,
    python: python?.valid ?? "-",
    got: result.valid,
    pythonErrors: python?.errors ?? [],
    gotErrors: result.errors,
    note: notes.join("; "),
  });
}

if (!quiet) {
  console.log(
    [
      pad("vector", 46),
      pad("expected", 9),
      pad("python", 7),
      pad("js", 6),
      pad("python errors", 34),
      "js errors / notes",
    ].join(" "),
  );
  console.log("-".repeat(150));
  for (const row of rows) {
    console.log(
      [
        pad(row.file, 46),
        pad(row.expected, 9),
        pad(row.python, 7),
        pad(row.got, 6),
        pad(fmt(row.pythonErrors), 34),
        fmt(row.gotErrors) + (row.note ? `  [${row.note}]` : ""),
      ].join(" "),
    );
  }
}

console.log(
  `\n${rows.length} vectors: ${validDiffs} valid mismatches vs Python, ` +
    `${errorDiffs} error-list mismatches vs Python, ` +
    `${manifestDiffs} manifest expectation mismatches, ` +
    `${digestDiffs} digest_match diffs, ${verdictDiffs} verdict diffs` +
    (baseline ? ` (baseline: ${path.relative(process.cwd(), baselinePath)})` : " (no baseline)"),
);

const strict = process.argv.includes("--strict");
if (
  validDiffs > 0 ||
  errorDiffs > 0 ||
  manifestDiffs > 0 ||
  (strict && (digestDiffs > 0 || verdictDiffs > 0))
) {
  process.exitCode = 1;
}
