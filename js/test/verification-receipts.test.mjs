import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  JsonFloat,
  canonicalBytes,
  parseStrictJson,
  sha256Prefixed,
  unsignedView,
  verificationReceiptDigest,
  verifyVerificationReceipt,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const vectorsDir = path.join(repoRoot, "vectors", "verification");
const manifest = JSON.parse(await readFile(path.join(vectorsDir, "manifest.json"), "utf8"));

const DIGEST_01 =
  "sha256:f0c7de6ac268de40a5f08deb209a9d8bc92d921b465b6ab0dc812c193a44bb9e";

async function loadVector(entry) {
  const receipt = parseStrictJson(await readFile(path.join(vectorsDir, entry.file)));
  const bundle = entry.bundle_file
    ? parseStrictJson(await readFile(path.join(vectorsDir, entry.bundle_file)))
    : null;
  let revocations = null;
  if (entry.revocations_file) {
    const document = JSON.parse(
      await readFile(path.join(vectorsDir, entry.revocations_file), "utf8"),
    );
    revocations = document.statements;
  }
  return { receipt, bundle, revocations };
}

test("every verification vector reaches its expected validity and errors", async (t) => {
  for (const entry of manifest.vectors) {
    await t.test(entry.file, async () => {
      const { receipt, bundle, revocations } = await loadVector(entry);
      const result = await verifyVerificationReceipt(receipt, bundle, revocations);
      assert.equal(
        result.valid,
        entry.expected_valid,
        `${entry.file}: ${JSON.stringify(result.errors)}`,
      );
      assert.deepEqual([...result.errors].sort(), [...entry.expected_errors].sort());
    });
  }
});

test("digest binding reports true, false, or null", async () => {
  const [valid, wrong] = await Promise.all([
    loadVector(manifest.vectors.find((entry) => entry.file === "01_valid.json")),
    loadVector(manifest.vectors.find((entry) => entry.file === "04_wrong_bundle.json")),
  ]);
  const matched = await verifyVerificationReceipt(valid.receipt, valid.bundle);
  assert.equal(matched.valid, true);
  assert.equal(matched.digest_match, true);

  const mismatch = await verifyVerificationReceipt(wrong.receipt, wrong.bundle);
  assert.equal(mismatch.digest_match, false);
  assert.deepEqual(mismatch.errors, ["bundle_digest_mismatch"]);

  const unchecked = await verifyVerificationReceipt(valid.receipt);
  assert.equal(unchecked.digest_match, null);
  assert.equal(unchecked.valid, true);
});

test("receipt digest covers the JCS view minus sig", async () => {
  const { receipt } = await loadVector(
    manifest.vectors.find((entry) => entry.file === "01_valid.json"),
  );
  const expected = await sha256Prefixed(canonicalBytes(unsignedView(receipt)));
  assert.equal(await verificationReceiptDigest(receipt), expected);
  assert.equal(expected, DIGEST_01);
});

test("result shape matches the Python as_dict field order", async () => {
  const { receipt, bundle } = await loadVector(
    manifest.vectors.find((entry) => entry.file === "01_valid.json"),
  );
  const result = await verifyVerificationReceipt(receipt, bundle);
  assert.deepEqual(Object.keys(result.asDict()), [
    "valid",
    "errors",
    "issuer",
    "verdict",
    "verified_at",
    "bundle_digest",
    "digest_match",
  ]);
  assert.deepEqual(result.asDict(), {
    valid: true,
    errors: [],
    issuer: "did:key:z6MkfvFqL6qMAgXLopHUAKn1E4Mwf2HLwSrP6eTcu5vnfZZK",
    verdict: "TRUSTED",
    verified_at: "2026-09-23T21:00:00Z",
    bundle_digest:
      "sha256:0ea854078244673a93249ac2c3df35aff6dfa71602bdc556a2887da2b1a59de9",
    digest_match: true,
  });
});

test("revocation checking is opt-in and timestamp-bounded", async () => {
  const revoked = await loadVector(
    manifest.vectors.find((entry) => entry.file === "12_revoked_issuer.json"),
  );
  const without = await verifyVerificationReceipt(revoked.receipt, revoked.bundle);
  assert.equal(without.valid, true);
  const with_ = await verifyVerificationReceipt(
    revoked.receipt,
    revoked.bundle,
    revoked.revocations,
  );
  assert.equal(with_.valid, false);
  assert.deepEqual(with_.errors, ["key_revoked"]);

  const after = await loadVector(
    manifest.vectors.find(
      (entry) => entry.file === "21_valid_statement_after_verified_at.json",
    ),
  );
  const result = await verifyVerificationReceipt(
    after.receipt,
    after.bundle,
    after.revocations,
  );
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("non-objects report not_an_object", async () => {
  for (const value of [[1, 2], "receipt", 7, null]) {
    const result = await verifyVerificationReceipt(value);
    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ["not_an_object"]);
    assert.equal(result.issuer, null);
    assert.equal(result.digest_match, null);
  }
});

test("version comparison follows Python (1.0 == 1) without hiding bad_signature", async () => {
  const { receipt } = await loadVector(
    manifest.vectors.find((entry) => entry.file === "01_valid.json"),
  );
  receipt.version = new JsonFloat("1.0");
  const result = await verifyVerificationReceipt(receipt);
  assert.ok(!result.errors.includes("bad_version"));
  assert.deepEqual(result.errors, ["bad_signature"]);
});
