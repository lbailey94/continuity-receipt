#!/usr/bin/env node
/**
 * Parity harness: run every published vector through the JS verifier and
 * compare against the manifest expectations and (optionally) a Python
 * baseline (test/python-baseline.json, produced by the reference package).
 *
 * Usage: node tools/parity.mjs [--baseline PATH] [--quiet]
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { parseStrictJson, verifyBundle } from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const vectorsDir = path.join(repoRoot, "vectors");

const args = process.argv.slice(2);
let baselinePath = path.join(here, "..", "test", "python-baseline.json");
let quiet = false;
for (let index = 0; index < args.length; index++) {
  if (args[index] === "--baseline") baselinePath = args[index + 1];
  if (args[index] === "--quiet") quiet = true;
}

const manifests = ["manifest.json", "manifest-0.5.json", "manifest-0.6.json"];
const entries = [];
for (const manifest of manifests) {
  const parsed = JSON.parse(await readFile(path.join(vectorsDir, manifest), "utf8"));
  for (const entry of parsed.vectors) entries.push(entry);
}

let baseline = null;
if (existsSync(baselinePath)) {
  baseline = JSON.parse(await readFile(baselinePath, "utf8"));
}
const baselineByFile = new Map((baseline ?? []).map((entry) => [entry.file, entry]));

const pad = (text, width) => String(text).padEnd(width).slice(0, width);
const rows = [];
let verdictMismatches = 0;
let codeMissing = 0;
let codeDiffs = 0;
let reasonDiffs = 0;

for (const entry of entries) {
  const file = entry.file;
  const bundlePath = path.join(vectorsDir, file);
  if (!existsSync(bundlePath)) {
    rows.push({ file, expected: entry.expected_verdict, got: "MISSING", note: "file missing" });
    verdictMismatches++;
    continue;
  }
  const bundle = parseStrictJson(await readFile(bundlePath));
  const result = await verifyBundle(bundle, { requireAnchor: Boolean(entry.require_anchor) });
  const expected = entry.expected_verdict;
  const got = result.verdict;
  const codes = result.codes();
  const python = baselineByFile.get(file);
  const notes = [];

  if (got !== expected) {
    verdictMismatches++;
    notes.push(`VERDICT expected ${expected}`);
  } else if (entry.expected_code && !codes.includes(entry.expected_code)) {
    codeMissing++;
    notes.push(`expected_code ${entry.expected_code} missing`);
  }
  if (python) {
    const pythonCodes = python.codes ?? [];
    if (JSON.stringify([...codes].sort()) !== JSON.stringify([...pythonCodes].sort())) {
      codeDiffs++;
      notes.push(`codes py=${JSON.stringify(pythonCodes)}`);
    }
    const reasons = [...result.provisional_reasons, ...result.insufficient_reasons].sort();
    const pythonReasons = [
      ...(python.provisional ?? []),
      ...(python.insufficient ?? []),
    ].sort();
    if (JSON.stringify(reasons) !== JSON.stringify(pythonReasons)) {
      reasonDiffs++;
      notes.push(`reasons py=${JSON.stringify(pythonReasons)}`);
    }
  }
  rows.push({
    file,
    expected,
    got,
    python: python?.verdict ?? "-",
    codes: codes.join(",") || "-",
    note: notes.join("; "),
  });
}

if (!quiet) {
  console.log(
    [
      pad("vector", 42),
      pad("expected", 22),
      pad("got", 22),
      pad("python", 22),
      "notes",
    ].join(" "),
  );
  console.log("-".repeat(140));
  for (const row of rows) {
    console.log(
      [
        pad(row.file, 42),
        pad(row.expected, 22),
        pad(row.got, 22),
        pad(row.python, 22),
        row.note,
        row.codes !== "-" ? `codes=[${row.codes}]` : "",
      ].join(" "),
    );
  }
}

console.log(
  `\n${rows.length} vectors: ${verdictMismatches} verdict mismatches, ` +
    `${codeMissing} missing expected codes, ${codeDiffs} code-list diffs vs Python, ` +
    `${reasonDiffs} reason-list diffs vs Python` +
    (baseline ? ` (baseline: ${path.relative(process.cwd(), baselinePath)})` : " (no baseline)"),
);

const strict = process.argv.includes("--strict");
if (verdictMismatches > 0 || codeMissing > 0 || (strict && (codeDiffs > 0 || reasonDiffs > 0))) {
  process.exitCode = 1;
}
