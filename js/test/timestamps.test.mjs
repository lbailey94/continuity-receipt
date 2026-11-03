import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  parseTimestamp, validateTimestamp, verifyBundle, verifyStatements,
  verifyVerificationReceipt,
} from "../dist/index.js";

const fixtures = new URL("../../tests/fixtures/", import.meta.url);
const times = JSON.parse(await readFile(new URL("timestamp-boundaries.json", fixtures), "utf8"));
const signed = JSON.parse(await readFile(new URL("signed-timestamp-boundaries.json", fixtures), "utf8"));

test("timestamps require complete spelling and a real calendar instant", () => {
  for (const value of times.valid) {
    assert.equal(validateTimestamp(value), true, value);
    assert.notEqual(parseTimestamp(value), null, value);
  }
  for (const value of times.invalid) {
    assert.equal(validateTimestamp(value), false, JSON.stringify(value));
    assert.equal(parseTimestamp(value), null, JSON.stringify(value));
  }
  for (const value of [null, true, 2026, {}, []]) {
    assert.equal(validateTimestamp(value), false);
  }
});

test("intact signatures cannot authorize impossible dates", async () => {
  assert.equal((await verifyBundle(signed.valid_bundle)).verdict, "TRUSTED");
  const bad = await verifyBundle(signed.invalid_bundle);
  assert.equal(bad.verdict, "UNTRUSTED");
  assert.deepEqual([...new Set(bad.codes())], ["malformed"]);
  assert.equal((await verifyVerificationReceipt(signed.valid_receipt)).valid, true);
  const receipt = await verifyVerificationReceipt(signed.invalid_receipt);
  assert.equal(receipt.valid, false);
  assert.deepEqual(receipt.errors, ["bad_verified_at"]);
});

test("signed invalid revocations fail closed", async () => {
  const result = await verifyStatements([signed.invalid_revocation]);
  assert.equal(result.revoked.length, 0);
  assert.deepEqual(result.errors.map(({ code }) => code), ["bad_revocation"]);
});
