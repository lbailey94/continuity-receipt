#!/usr/bin/env node
/**
 * continuity-receipt-verify-receipt — verification-receipt verifier CLI.
 *
 * Mirrors the Python reference CLI: prints the full result as JSON and exits
 * 0 when the receipt is valid, 1 otherwise, 2 when the receipt (or `--bundle`)
 * is unreadable or not valid JSON.
 */

import { canonicalBytes, isPlainObject } from "./canon.js";
import {
  RevocationError,
  loadRevocationStatements,
  mergeStatements,
  parseStrictJson,
  unsignedView,
  verificationReceiptDigest,
  verifyVerificationReceipt,
} from "./index.js";

interface CliOptions {
  receipt: string;
  bundle: string | null;
  revocations: string[];
  digest: boolean;
  canonical: string | null;
}

function usage(): string {
  return [
    "usage: continuity-receipt-verify-receipt <receipt> [--bundle PATH]",
    "       [--revocations PATH|URL]... [--digest] [--canonical PATH]",
    "",
    "optional arguments:",
    "  --bundle PATH            bundle JSON file to check bundle_digest against",
    "  --revocations PATH|URL   revocation list (repeatable; REVOCATION_DISTRIBUTION.md)",
    "  --digest                 print the receipt digest (for anchoring) instead of verifying",
    "  --canonical PATH         write the canonical view (object minus sig) to PATH and print the digest",
    "  --help                   show this help",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions | null {
  const options: CliOptions = {
    receipt: "",
    bundle: null,
    revocations: [],
    digest: false,
    canonical: null,
  };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index] as string;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      return null;
    }
    if (arg === "--digest") {
      options.digest = true;
      continue;
    }
    if (arg === "--bundle" || arg === "--revocations" || arg === "--canonical") {
      const value = argv[++index];
      if (value === undefined) {
        process.stderr.write(`error: ${arg} requires a value\n`);
        process.exitCode = 2;
        return null;
      }
      if (arg === "--bundle") options.bundle = value;
      else if (arg === "--revocations") options.revocations.push(value);
      else options.canonical = value;
      continue;
    }
    if (arg.startsWith("-")) {
      process.stderr.write(`error: unrecognized argument: ${arg}\n`);
      process.exitCode = 2;
      return null;
    }
    if (options.receipt !== "") {
      process.stderr.write("error: only one receipt path is accepted\n");
      process.exitCode = 2;
      return null;
    }
    options.receipt = arg;
  }
  if (options.receipt === "") {
    process.stderr.write(usage() + "\n");
    process.exitCode = 2;
    return null;
  }
  return options;
}

async function main(argv: string[]): Promise<number> {
  const options = parseArgs(argv);
  if (options === null) return typeof process.exitCode === "number" ? process.exitCode : 2;

  const fs = await import("node:fs/promises");
  let receipt: unknown;
  try {
    const bytes = new Uint8Array(await fs.readFile(options.receipt));
    receipt = parseStrictJson(bytes);
  } catch (error) {
    process.stderr.write(`error: receipt is not valid JSON: ${(error as Error).message}\n`);
    return 2;
  }

  if (options.canonical !== null) {
    if (!isPlainObject(receipt)) {
      process.stderr.write("error: receipt is not an object\n");
      return 1;
    }
    let canonical: Uint8Array;
    try {
      canonical = canonicalBytes(unsignedView(receipt));
    } catch (error) {
      process.stderr.write(`error: ${(error as Error).message}\n`);
      return 1;
    }
    try {
      await fs.writeFile(options.canonical, canonical);
    } catch (error) {
      process.stderr.write(
        `error: cannot write ${options.canonical}: ${(error as Error).message}\n`,
      );
      return 1;
    }
    process.stdout.write((await verificationReceiptDigest(receipt)) + "\n");
    return 0;
  }

  if (options.digest) {
    try {
      process.stdout.write((await verificationReceiptDigest(receipt)) + "\n");
    } catch (error) {
      process.stderr.write(`error: ${(error as Error).message}\n`);
      return 1;
    }
    return 0;
  }

  let revocations: unknown[] | null = null;
  if (options.revocations.length > 0) {
    const groups: unknown[][] = [];
    for (const source of options.revocations) {
      try {
        groups.push(await loadRevocationStatements(source));
      } catch (error) {
        const code =
          error instanceof RevocationError ? error.code : "bad_revocations_document";
        process.stdout.write(
          JSON.stringify({ valid: false, errors: [code] }, null, 2) + "\n",
        );
        return 1;
      }
    }
    revocations = mergeStatements(...groups);
  }

  let bundle: Uint8Array | null = null;
  if (options.bundle !== null) {
    try {
      bundle = new Uint8Array(await fs.readFile(options.bundle));
    } catch (error) {
      process.stderr.write(`error: cannot read bundle: ${(error as Error).message}\n`);
      return 2;
    }
    try {
      parseStrictJson(bundle);
    } catch (error) {
      process.stderr.write(`error: --bundle is not valid JSON: ${(error as Error).message}\n`);
      return 2;
    }
  }

  const result = await verifyVerificationReceipt(receipt, bundle, revocations);
  process.stdout.write(JSON.stringify(result.asDict(), null, 2) + "\n");
  return result.valid ? 0 : 1;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    process.stderr.write(`error: ${(error as Error).stack ?? String(error)}\n`);
    process.exitCode = 2;
  },
);
