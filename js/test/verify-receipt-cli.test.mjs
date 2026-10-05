import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const vectorsDir = path.join(repoRoot, "vectors", "verification");
const cli = path.join(here, "..", "dist", "verify-receipt-cli.js");
const DIGEST_01 =
  "sha256:f0c7de6ac268de40a5f08deb209a9d8bc92d921b465b6ab0dc812c193a44bb9e";

async function cliRun(args) {
  try {
    const { stdout } = await run(process.execPath, [cli, ...args]);
    return { code: 0, stdout, stderr: "" };
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
  }
}

test("CLI exits 0 for a valid receipt and prints the Python shape", async () => {
  const { code, stdout } = await cliRun([
    path.join(vectorsDir, "01_valid.json"),
    "--bundle",
    path.join(vectorsDir, "bundle.json"),
  ]);
  assert.equal(code, 0);
  const result = JSON.parse(stdout);
  assert.deepEqual(Object.keys(result), [
    "valid",
    "errors",
    "issuer",
    "verdict",
    "verified_at",
    "bundle_digest",
    "digest_match",
  ]);
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
  assert.equal(result.digest_match, true);
});

test("CLI exits 1 for an invalid receipt", async () => {
  const { code, stdout } = await cliRun([path.join(vectorsDir, "03_tampered_verdict.json")]);
  assert.equal(code, 1);
  const result = JSON.parse(stdout);
  assert.equal(result.valid, false);
  assert.deepEqual(result.errors, ["verdict_mismatch", "bad_signature"]);
});

test("CLI reports bundle digest mismatch against a different bundle", async () => {
  const { code, stdout } = await cliRun([
    path.join(vectorsDir, "04_wrong_bundle.json"),
    "--bundle",
    path.join(vectorsDir, "other_bundle.json"),
  ]);
  assert.equal(code, 1);
  const result = JSON.parse(stdout);
  assert.equal(result.digest_match, false);
  assert.deepEqual(result.errors, ["bundle_digest_mismatch"]);
});

test("CLI applies revocation lists", async () => {
  const { code, stdout } = await cliRun([
    path.join(vectorsDir, "12_revoked_issuer.json"),
    "--bundle",
    path.join(vectorsDir, "bundle.json"),
    "--revocations",
    path.join(vectorsDir, "12_revoked_issuer.revocations.json"),
  ]);
  assert.equal(code, 1);
  assert.deepEqual(JSON.parse(stdout).errors, ["key_revoked"]);

  const missing = await cliRun([
    path.join(vectorsDir, "01_valid.json"),
    "--revocations",
    path.join(vectorsDir, "does-not-exist.revocations.json"),
  ]);
  assert.equal(missing.code, 1);
  const failure = JSON.parse(missing.stdout);
  assert.equal(failure.valid, false);
  assert.deepEqual(failure.errors, ["revocations_unreachable"]);
});

test("CLI exits 2 for unreadable or malformed receipt input", async () => {
  const missing = await cliRun([path.join(vectorsDir, "nope.json")]);
  assert.equal(missing.code, 2);

  const directory = await mkdtemp(path.join(tmpdir(), "continuity-receipt-"));
  const bad = path.join(directory, "bad.json");
  await writeFile(bad, "not json", "utf8");
  const malformed = await cliRun([bad]);
  assert.equal(malformed.code, 2);
  assert.match(malformed.stderr, /receipt is not valid JSON/);

  const duplicate = path.join(directory, "duplicate.json");
  await writeFile(duplicate, '{"kind":"a","kind":"b"}', "utf8");
  assert.equal((await cliRun([duplicate])).code, 2);
});

test("CLI exits 2 for a malformed --bundle", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "continuity-receipt-"));
  const bad = path.join(directory, "bad-bundle.json");
  await writeFile(bad, "not json", "utf8");
  const { code, stderr } = await cliRun([
    path.join(vectorsDir, "01_valid.json"),
    "--bundle",
    bad,
  ]);
  assert.equal(code, 2);
  assert.match(stderr, /--bundle is not valid JSON/);
});

test("CLI --digest prints the anchoring digest", async () => {
  const { code, stdout } = await cliRun([
    path.join(vectorsDir, "01_valid.json"),
    "--digest",
  ]);
  assert.equal(code, 0);
  assert.equal(stdout.trim(), DIGEST_01);
});

test("CLI --canonical writes bytes whose hash is the printed digest", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "continuity-receipt-"));
  const target = path.join(directory, "receipt.canonical");
  const { code, stdout } = await cliRun([
    path.join(vectorsDir, "01_valid.json"),
    "--canonical",
    target,
  ]);
  assert.equal(code, 0);
  const digest = stdout.trim();
  assert.equal(digest, DIGEST_01);
  const bytes = await readFile(target);
  assert.equal("sha256:" + createHash("sha256").update(bytes).digest("hex"), digest);
  assert.ok(!bytes.includes('"sig"'));
});
