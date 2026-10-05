/** Self-signed revocation statements and external revocation list documents. */

import { canonicalBytes, isPlainObject, CanonicalizationError } from "./canon.js";
import { toHex } from "./hash.js";
import { verifyEd25519 } from "./keys.js";
import { parseTimestamp, validateTimestamp } from "./records.js";
import { parseStrictJson } from "./strict_json.js";

export const DOCUMENT_KIND = "continuity-receipt-revocations";
export const DOCUMENT_VERSION = 1;
export const MAX_DOCUMENT_BYTES = 1 << 20;

export class RevocationError extends Error {
  constructor(
    public readonly code: string,
    detail: string,
  ) {
    super(detail);
    this.name = "RevocationError";
  }
}

export interface RevokedKey {
  key: string;
  revokedAt: number;
}

export interface RevocationVerification {
  revoked: RevokedKey[];
  errors: Array<{ code: string; detail: string }>;
}

function fingerprint(statement: unknown): string {
  try {
    return toHex(canonicalBytes(statement));
  } catch {
    try {
      return JSON.stringify(statement) ?? String(statement);
    } catch {
      return String(statement);
    }
  }
}

/** Concatenate statement groups, dropping byte-identical duplicates. */
export function mergeStatements(
  ...groups: Array<unknown[] | null | undefined>
): unknown[] {
  const merged: unknown[] = [];
  const seen = new Set<string>();
  for (const group of groups) {
    for (const statement of group ?? []) {
      if (!isPlainObject(statement)) {
        merged.push(statement);
        continue;
      }
      const print = fingerprint(statement);
      if (seen.has(print)) continue;
      seen.add(print);
      merged.push(statement);
    }
  }
  return merged;
}

/**
 * Verify self-signed revocation statements (bundle shape, 0.2 §7.5).
 * Invalid statements are reported rather than throwing.
 */
export async function verifyStatements(statements: unknown[]): Promise<RevocationVerification> {
  const revoked: RevokedKey[] = [];
  const errors: Array<{ code: string; detail: string }> = [];
  for (const statement of statements) {
    if (!isPlainObject(statement)) {
      errors.push({ code: "bad_revocation", detail: "revocation statement is not an object" });
      continue;
    }
    const keyId = statement["key"];
    const revokedAt = statement["revoked_at"];
    const sig = statement["sig"];
    if (typeof keyId !== "string" || !validateTimestamp(revokedAt)) {
      errors.push({
        code: "bad_revocation",
        detail: `malformed revocation statement for ${String(keyId)}`,
      });
      continue;
    }
    if (
      !isPlainObject(sig) ||
      sig["alg"] !== "ed25519" ||
      typeof sig["value"] !== "string" ||
      sig["value"] === ""
    ) {
      errors.push({
        code: "bad_revocation",
        detail: `revocation statement unsigned for ${keyId}`,
      });
      continue;
    }
    let valid = false;
    try {
      const view: Record<string, unknown> = {};
      for (const [name, value] of Object.entries(statement)) {
        if (name !== "sig") view[name] = value;
      }
      valid = await verifyEd25519(keyId, canonicalBytes(view), sig["value"]);
    } catch (error) {
      if (!(error instanceof CanonicalizationError)) throw error;
    }
    if (!valid) {
      errors.push({
        code: "bad_revocation",
        detail: `revocation signature invalid for ${keyId}`,
      });
      continue;
    }
    const parsed = parseTimestamp(revokedAt);
    if (parsed === null) {
      errors.push({
        code: "bad_revocation",
        detail: `malformed revocation statement for ${keyId}`,
      });
      continue;
    }
    revoked.push({ key: keyId, revokedAt: parsed });
  }
  return { revoked, errors };
}

/**
 * Read, parse, and shape-check a revocation list document from a filesystem
 * path or URL, mirroring Python's `revocations.load_statements`.
 */
export async function loadRevocationStatements(source: string): Promise<unknown[]> {
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

/** Shape-check a revocation list document and return its statements. */
export function statementsFromDocument(document: unknown): unknown[] {
  if (!isPlainObject(document)) {
    throw new RevocationError("bad_revocations_document", "document is not an object");
  }
  if (document["kind"] !== DOCUMENT_KIND) {
    throw new RevocationError(
      "bad_revocations_document",
      `kind must be ${JSON.stringify(DOCUMENT_KIND)}, got ${JSON.stringify(document["kind"])}`,
    );
  }
  if (document["version"] !== DOCUMENT_VERSION) {
    throw new RevocationError(
      "bad_revocations_document",
      `version must be ${DOCUMENT_VERSION}, got ${JSON.stringify(document["version"])}`,
    );
  }
  const statements = document["statements"];
  if (!Array.isArray(statements)) {
    throw new RevocationError("bad_revocations_document", "statements must be a list");
  }
  return statements;
}
