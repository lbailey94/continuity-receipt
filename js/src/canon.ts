/**
 * JCS-subset canonicalization matching `continuity_receipt/canon.py`.
 *
 * v0 subset: sorted keys, no whitespace, UTF-8, integers/strings/bools/null
 * only; floats are rejected. Key sort is by Unicode code point (Python's
 * `sort_keys`) rather than RFC 8785's UTF-16 code units; identical for the
 * ASCII keys the schema requires.
 */

export class CanonicalizationError extends Error {
  override name = "CanonicalizationError";
}

const encoder = new TextEncoder();

/** Canonical JSON bytes for signing and hashing. Throws on floats. */
export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalString(value));
}

/** Canonical JSON text (same value as `canonicalBytes`, without encoding). */
export function canonicalString(value: unknown): string {
  const parts: string[] = [];
  writeValue(value, parts, 0);
  return parts.join("");
}

function writeValue(value: unknown, out: string[], depth: number): void {
  if (depth > 512) {
    throw new CanonicalizationError("value nesting exceeds the canonicalization limit");
  }
  if (value === null) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "number": {
      if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
        throw new CanonicalizationError(
          "floats are not allowed in continuity receipts (v0)",
        );
      }
      out.push(String(value === 0 ? 0 : value));
      return;
    }
    case "bigint":
      out.push(value.toString());
      return;
    case "string":
      out.push(encodeString(value));
      return;
    default:
      break;
  }
  if (Array.isArray(value)) {
    out.push("[");
    for (let index = 0; index < value.length; index++) {
      if (index > 0) out.push(",");
      writeValue(value[index], out, depth + 1);
    }
    out.push("]");
    return;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort(compareCodePoints);
    out.push("{");
    for (let index = 0; index < keys.length; index++) {
      const key = keys[index] as string;
      if (index > 0) out.push(",");
      out.push(encodeString(key), ":");
      writeValue(value[key], out, depth + 1);
    }
    out.push("}");
    return;
  }
  throw new CanonicalizationError(`unsupported value type: ${typeof value}`);
}

function encodeString(value: string): string {
  if (hasLoneSurrogate(value)) {
    // Python's json.dumps(ensure_ascii=False) emits the raw surrogate and the
    // subsequent .encode("utf-8") raises UnicodeEncodeError; mirror the raise.
    throw new CanonicalizationError("strings must contain valid Unicode scalar values");
  }
  return JSON.stringify(value);
}

export function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Python-style string ordering by Unicode code point. */
export function compareCodePoints(a: string, b: string): number {
  const left = a[Symbol.iterator]();
  const right = b[Symbol.iterator]();
  for (;;) {
    const l = left.next();
    const r = right.next();
    if (l.done === true && r.done === true) return 0;
    if (l.done === true) return -1;
    if (r.done === true) return 1;
    const lc = (l.value as string).codePointAt(0) as number;
    const rc = (r.value as string).codePointAt(0) as number;
    if (lc !== rc) return lc < rc ? -1 : 1;
  }
}

/**
 * v0 reference commitment: sha256(salt || '|' || JCS(value)).
 * Matches `continuity_receipt.canon.commit_field`.
 */
export async function commitField(saltHex: string, value: unknown): Promise<string> {
  const { fromHex, sha256Prefixed } = await import("./hash.js");
  const salt = fromHex(saltHex);
  const canonical = canonicalBytes(value);
  const message = new Uint8Array(salt.length + 1 + canonical.length);
  message.set(salt, 0);
  message[salt.length] = 0x7c; // "|"
  message.set(canonical, salt.length + 1);
  return sha256Prefixed(message);
}
