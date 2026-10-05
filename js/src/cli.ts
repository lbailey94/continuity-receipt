#!/usr/bin/env node
/**
 * continuity-receipt-verify — offline bundle verifier CLI.
 *
 * Mirrors the Python reference CLI: prints the full result as JSON and exits
 * 0 when the verdict is TRUSTED, 1 otherwise, 2 when the bundle is unreadable.
 */

import { parseStrictJson, StrictJsonError, StrictJsonNestingError } from "./strict_json.js";
import {
  MAX_BUNDLE_BYTES,
  MAX_DOCUMENT_BYTES,
  RevocationError,
  statementsFromDocument,
  verifyBundle,
} from "./index.js";

interface CliOptions {
  bundle: string;
  requireAnchor: boolean;
  revocations: string[];
}

function usage(): string {
  return [
    "usage: continuity-receipt-verify <bundle> [--require-anchor] [--revocations PATH|URL]...",
    "",
    "optional arguments:",
    "  --require-anchor        report PROVISIONAL when the bundle carries no anchor",
    "  --revocations PATH|URL  external revocation list (repeatable)",
    "  --help                  show this help",
    "  --version               print the package version",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions | null {
  const options: CliOptions = { bundle: "", requireAnchor: false, revocations: [] };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index] as string;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      return null;
    }
    if (arg === "--version") {
      process.stdout.write("0.1.0\n");
      return null;
    }
    if (arg === "--require-anchor") {
      options.requireAnchor = true;
      continue;
    }
    if (arg === "--revocations") {
      const value = argv[++index];
      if (value === undefined) {
        process.stderr.write("error: --revocations requires a value\n");
        process.exitCode = 2;
        return null;
      }
      options.revocations.push(value);
      continue;
    }
    if (arg.startsWith("-")) {
      process.stderr.write(`error: unrecognized argument: ${arg}\n`);
      process.exitCode = 2;
      return null;
    }
    if (options.bundle !== "") {
      process.stderr.write("error: only one bundle path is accepted\n");
      process.exitCode = 2;
      return null;
    }
    options.bundle = arg;
  }
  if (options.bundle === "") {
    process.stderr.write(usage() + "\n");
    process.exitCode = 2;
    return null;
  }
  return options;
}

async function loadRevocationStatements(source: string): Promise<unknown[]> {
  let text: string;
  const httpMatch = /^http:\/\/([^/:]+)/i.exec(source);
  if (/^https:\/\//i.test(source) || httpMatch !== null) {
    const host = httpMatch?.[1]?.toLowerCase() ?? "";
    if (httpMatch !== null && host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
      throw new RevocationError(
        "revocations_insecure_url",
        `refusing plain http for non-loopback host: ${source}`,
      );
    }
    let response: Response;
    try {
      response = await fetch(source);
    } catch (error) {
      throw new RevocationError(
        "revocations_unreachable",
        `cannot fetch ${source}: ${(error as Error).message}`,
      );
    }
    if (!response.ok) {
      throw new RevocationError(
        "revocations_unreachable",
        `cannot fetch ${source}: HTTP ${response.status}`,
      );
    }
    const buffer = new Uint8Array(await response.arrayBuffer());
    if (buffer.length > MAX_DOCUMENT_BYTES) {
      throw new RevocationError(
        "revocations_too_large",
        `document exceeds ${MAX_DOCUMENT_BYTES} bytes`,
      );
    }
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } else {
    const fs = await import("node:fs/promises");
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await fs.readFile(source));
    } catch (error) {
      throw new RevocationError(
        "revocations_unreachable",
        `cannot read ${source}: ${(error as Error).message}`,
      );
    }
    if (bytes.length > MAX_DOCUMENT_BYTES) {
      throw new RevocationError(
        "revocations_too_large",
        `document exceeds ${MAX_DOCUMENT_BYTES} bytes`,
      );
    }
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }
  let document: unknown;
  try {
    document = parseStrictJson(text);
  } catch (error) {
    throw new RevocationError(
      "bad_revocations_document",
      `${source} is not valid JSON: ${(error as Error).message}`,
    );
  }
  return statementsFromDocument(document);
}

async function main(argv: string[]): Promise<number> {
  const options = parseArgs(argv);
  if (options === null) return typeof process.exitCode === "number" ? process.exitCode : 2;

  let external: unknown[] | null = null;
  if (options.revocations.length > 0) {
    const merged: unknown[] = [];
    for (const source of options.revocations) {
      let statements: unknown[];
      try {
        statements = await loadRevocationStatements(source);
      } catch (error) {
        const failure =
          error instanceof RevocationError
            ? { code: error.code, detail: error.message }
            : { code: "revocations_unreachable", detail: String(error) };
        process.stdout.write(
          JSON.stringify({ verdict: "INSUFFICIENT_EVIDENCE", errors: [failure] }, null, 2) + "\n",
        );
        return 1;
      }
      merged.push(...statements);
    }
    external = merged;
  }

  const fs = await import("node:fs/promises");
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await fs.readFile(options.bundle));
  } catch (error) {
    process.stderr.write(`error: cannot read bundle: ${(error as Error).message}\n`);
    return 2;
  }
  if (bytes.length > MAX_BUNDLE_BYTES) {
    process.stdout.write(
      JSON.stringify(
        {
          verdict: "UNTRUSTED",
          errors: [
            {
              code: "bundle_too_large",
              detail: `${bytes.length} bytes exceeds limit ${MAX_BUNDLE_BYTES}`,
            },
          ],
        },
        null,
        2,
      ) + "\n",
    );
    return 1;
  }

  let bundle: unknown;
  try {
    bundle = parseStrictJson(bytes);
  } catch (error) {
    const failure =
      error instanceof StrictJsonNestingError
        ? { code: "nesting_too_deep", detail: "JSON nesting exceeds the parser limit" }
        : error instanceof StrictJsonError
          ? { code: "malformed", detail: `bundle is not valid JSON: ${error.message}` }
          : { code: "malformed", detail: `bundle is not valid JSON: ${(error as Error).message}` };
    process.stdout.write(
      JSON.stringify({ verdict: "UNTRUSTED", errors: [failure] }, null, 2) + "\n",
    );
    return 1;
  }

  const result = await verifyBundle(bundle, {
    requireAnchor: options.requireAnchor,
    externalRevocations: external,
  });
  process.stdout.write(JSON.stringify(result.asDict(), null, 2) + "\n");
  return result.verdict === "TRUSTED" ? 0 : 1;
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
