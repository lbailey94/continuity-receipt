import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const vectorsDir = path.join(repoRoot, "vectors");
const cli = path.join(here, "..", "dist", "cli.js");

async function cliRun(args) {
  try {
    const { stdout } = await run(process.execPath, [cli, ...args]);
    return { code: 0, stdout };
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
  }
}

test("CLI exits 0 for a trusted vector", async () => {
  const { code, stdout } = await cliRun([path.join(vectorsDir, "01_happy_minimal.json")]);
  assert.equal(code, 0);
  assert.equal(JSON.parse(stdout).verdict, "TRUSTED");
});

test("CLI exits 1 for an untrusted vector", async () => {
  const { code, stdout } = await cliRun([path.join(vectorsDir, "03_tampered_body.json")]);
  assert.equal(code, 1);
  assert.equal(JSON.parse(stdout).verdict, "UNTRUSTED");
});

test("CLI exits 2 for an unreadable bundle", async () => {
  const { code } = await cliRun([path.join(vectorsDir, "missing-file.json")]);
  assert.equal(code, 2);
});

test("CLI refuses duplicate JSON members", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "continuity-receipt-"));
  const file = path.join(directory, "duplicate.json");
  await writeFile(
    file,
    '{"spec":"continuity-receipt/0.4","spec":"continuity-receipt/0.4","receipts":[]}',
    "utf8",
  );
  const { code, stdout } = await cliRun([file]);
  assert.equal(code, 1);
  const result = JSON.parse(stdout);
  assert.equal(result.verdict, "UNTRUSTED");
  assert.equal(result.errors[0].code, "malformed");
});
