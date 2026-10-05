import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseStrictJson, verifyBundle } from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const vectorsDir = path.join(repoRoot, "vectors");

const entries = [];
for (const manifest of ["manifest.json", "manifest-0.5.json", "manifest-0.6.json"]) {
  const parsed = JSON.parse(await readFile(path.join(vectorsDir, manifest), "utf8"));
  for (const entry of parsed.vectors) entries.push(entry);
}

test("every published vector reaches its expected verdict", async (t) => {
  for (const entry of entries) {
    await t.test(entry.file, async () => {
      const bundlePath = path.join(vectorsDir, entry.file);
      assert.ok(existsSync(bundlePath), `missing vector ${entry.file}`);
      const bundle = parseStrictJson(await readFile(bundlePath));
      const result = await verifyBundle(bundle, {
        requireAnchor: Boolean(entry.require_anchor),
      });
      assert.equal(
        result.verdict,
        entry.expected_verdict,
        `${entry.file}: ${result.verdict} != ${entry.expected_verdict} — ${JSON.stringify(result.errors)}`,
      );
      if (entry.expected_code) {
        assert.ok(
          result.codes().includes(entry.expected_code),
          `${entry.file}: expected error ${entry.expected_code}, got ${JSON.stringify(result.codes())}`,
        );
      }
    });
  }
});

test("unsupported spec is refused", async () => {
  const bundle = parseStrictJson(
    await readFile(path.join(vectorsDir, "01_happy_minimal.json")),
  );
  bundle.spec = "continuity-receipt/9.9";
  const result = await verifyBundle(bundle);
  assert.equal(result.verdict, "UNTRUSTED");
  assert.ok(result.codes().includes("version_unsupported"));
});
