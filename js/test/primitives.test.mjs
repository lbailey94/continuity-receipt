import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  b58encode,
  canonicalBytes,
  canonicalString,
  commitField,
  didKeyToPublicKey,
  JsonFloat,
  parseStrictJson,
  publicKeyToDidKey,
  unsignedView,
  verifyBundle,
  verifyEd25519,
  verifyFile,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const vectorsDir = path.join(repoRoot, "vectors");

test("canonical bytes are deterministic across member order", () => {
  const first = canonicalString({ b: 1, a: [1, 2, { d: "x", c: true }] });
  const second = canonicalString({ a: [1, 2, { c: true, d: "x" }], b: 1 });
  assert.equal(first, second);
});

test("canonical ordering follows Python code-point sort for ASCII", () => {
  assert.equal(canonicalString({ b: 1, a: 2, A: 3 }), '{"A":3,"a":2,"b":1}');
});

test("floats are rejected", () => {
  assert.throws(() => canonicalBytes({ amount: 1.5 }));
  assert.throws(() => canonicalBytes({ amount: Number.NaN }));
});

test("big integers serialize exactly", () => {
  assert.equal(canonicalString({ n: 18446744073709551616n }), '{"n":18446744073709551616}');
});

test("strict parser rejects duplicate members at any depth", () => {
  assert.equal(parseStrictJson('{"a":1,"nested":{"b":2}}').a, 1);
  assert.throws(() => parseStrictJson('{"nested":{"b":1,"b":2}}'), /duplicate JSON object member/);
});

test("strict parser preserves integer exactness and marks floats", () => {
  assert.equal(parseStrictJson(String(2 ** 53)), 9007199254740992n);
  assert.equal(parseStrictJson(String(Number.MAX_SAFE_INTEGER)), Number.MAX_SAFE_INTEGER);
  assert.ok(parseStrictJson("1e2") instanceof JsonFloat);
  assert.ok(parseStrictJson("0.5") instanceof JsonFloat);
});

test("did:key ed25519 round trip", () => {
  const did = "did:key:z6MkwSG2hFkD41K85fvQFtNGCZXYFUwEZDqrzahZvWHt5hm1";
  const raw = didKeyToPublicKey(did);
  assert.equal(raw.length, 32);
  assert.equal(publicKeyToDidKey(raw), did);
  const multicodec = new Uint8Array(2 + raw.length);
  multicodec.set([0xed, 0x01], 0);
  multicodec.set(raw, 2);
  assert.equal("did:key:z" + b58encode(multicodec), did);
});

test("commitField reproduces a disclosed commitment from vector 08", async () => {
  const bundle = parseStrictJson(
    await readFile(path.join(vectorsDir, "08_redacted_disclosed.json")),
  );
  const entry = bundle.disclosure_map["receipts[3].body.quality_flags"];
  const field = bundle.receipts[3].body.quality_flags;
  assert.equal(await commitField(entry.salt, entry.value), field.commit);
  assert.equal(bundle.receipts[3].body.quality_flags.redacted, true);
});

test("receipt signatures verify and tampering fails", async () => {
  const bundle = parseStrictJson(
    await readFile(path.join(vectorsDir, "01_happy_minimal.json")),
  );
  const receipt = bundle.receipts[0];
  const message = canonicalBytes(unsignedView(receipt));
  assert.equal(await verifyEd25519(receipt.sig.key, message, receipt.sig.value), true);
  receipt.body.agent_id = "tampered";
  assert.equal(
    await verifyEd25519(receipt.sig.key, canonicalBytes(unsignedView(receipt)), receipt.sig.value),
    false,
  );
});

test("verifyFile reports io_error for a missing file", async () => {
  const result = await verifyFile(path.join(vectorsDir, "does-not-exist.json"));
  assert.equal(result.verdict, "UNTRUSTED");
  assert.deepEqual(result.codes(), ["io_error"]);
});

test("verifyBundle rejects non-objects and deep nesting", async () => {
  assert.equal((await verifyBundle(null)).verdict, "UNTRUSTED");
  let deep = {};
  let cursor = deep;
  for (let index = 0; index < 70; index++) {
    cursor.next = {};
    cursor = cursor.next;
  }
  const result = await verifyBundle(deep);
  assert.ok(result.codes().includes("nesting_too_deep"));
});
