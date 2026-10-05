/**
 * Verification receipts (companion artifact, version 1), mirroring
 * `continuity_receipt/verification.py`.
 *
 * A verification receipt is a signed record of a bundle-verification run:
 * shape checks, internal consistency (error codes and verdict against the
 * recorded lists), an Ed25519 `did:key` signature over the JCS view minus
 * `sig`, an optional digest binding to the bundle, and an optional issuer
 * revocation check.
 */

import { canonicalBytes, isPlainObject } from "./canon.js";
import { sha256Prefixed } from "./hash.js";
import { verifyEd25519 } from "./keys.js";
import { parseTimestamp, unsignedView, validateTimestamp } from "./records.js";
import { verifyStatements } from "./revocations.js";
import { JsonFloat, parseStrictJson } from "./strict_json.js";

export const KIND = "continuity-receipt-verification";
export const VERSION = 1;
export const VERDICTS: readonly string[] = [
  "TRUSTED",
  "PROVISIONAL",
  "INSUFFICIENT_EVIDENCE",
  "UNTRUSTED",
];
const DIGEST_LENGTH = "sha256:".length + 64;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/** Mirrors Python's `VerificationReceiptResult` (`as_dict` shape). */
export class VerificationReceiptResult {
  valid = false;
  errors: string[] = [];
  issuer: unknown = null;
  verdict: unknown = null;
  verified_at: unknown = null;
  bundle_digest: unknown = null;
  digest_match: boolean | null = null;

  asDict(): Record<string, unknown> {
    return {
      valid: this.valid,
      errors: [...this.errors],
      issuer: this.issuer === undefined ? null : this.issuer,
      verdict: this.verdict === undefined ? null : this.verdict,
      verified_at: this.verified_at === undefined ? null : this.verified_at,
      bundle_digest: this.bundle_digest === undefined ? null : this.bundle_digest,
      digest_match: this.digest_match,
    };
  }
}

/**
 * SHA-256 of the canonical bytes of a verification receipt minus its `sig`
 * (the digest to anchor — `VERIFICATION_RECEIPTS.md` §Anchoring).
 */
export async function verificationReceiptDigest(receipt: unknown): Promise<string> {
  if (!isPlainObject(receipt)) {
    throw new TypeError("receipt is not an object");
  }
  return sha256Prefixed(canonicalBytes(unsignedView(receipt)));
}

/** Python's `receipt.get("version") != 1`: `1.0` and `true` also compare equal. */
function versionMatches(value: unknown): boolean {
  if (value === 1 || value === true) return true;
  if (typeof value === "bigint") return value === 1n;
  if (value instanceof JsonFloat) return Number(value.text) === 1;
  return false;
}

function isDigest(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.length === DIGEST_LENGTH &&
    DIGEST_RE.test(value)
  );
}

function errorsWellFormed(value: unknown): value is Array<Record<string, unknown>> {
  return (
    Array.isArray(value) &&
    value.every(
      (entry) => isPlainObject(entry) && typeof entry["code"] === "string",
    )
  );
}

function stringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function verdictClass(
  errors: Array<Record<string, unknown>>,
  provisional: string[],
  insufficient: string[],
): string {
  if (errors.length > 0) return "UNTRUSTED";
  if (insufficient.length > 0) return "INSUFFICIENT_EVIDENCE";
  if (provisional.length > 0) return "PROVISIONAL";
  return "TRUSTED";
}

function sameStringList(left: readonly unknown[], right: readonly unknown[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/** Accept a parsed bundle object or its JSON bytes; raise on junk (Python `_bundle_object`). */
function bundleObject(bundle: unknown): unknown {
  if (isPlainObject(bundle)) return bundle;
  if (typeof bundle === "string" || bundle instanceof Uint8Array) {
    return parseStrictJson(bundle);
  }
  if (bundle instanceof ArrayBuffer) {
    return parseStrictJson(new Uint8Array(bundle));
  }
  throw new TypeError("bundle must be an object or JSON bytes");
}

/**
 * Verify a verification receipt's shape, consistency, and signature.
 *
 * `bundle` (object or JSON bytes), when supplied, additionally checks
 * `bundle_digest` against the bundle's canonical bytes and reports
 * `digest_match`. `revocations` (statements in the 0.2 §7.5 shape), when
 * supplied, checks whether the issuer key was revoked at or before
 * `verified_at` (`key_revoked`) — without revocation input the check is
 * simply not performed.
 */
export async function verifyVerificationReceipt(
  receipt: unknown,
  bundle: unknown = null,
  revocations: unknown[] | null = null,
): Promise<VerificationReceiptResult> {
  const result = new VerificationReceiptResult();
  if (!isPlainObject(receipt)) {
    result.errors.push("not_an_object");
    return result;
  }

  const errors: string[] = [];
  if (receipt["kind"] !== KIND) {
    errors.push("bad_kind");
  }
  if (!versionMatches(receipt["version"])) {
    errors.push("bad_version");
  }
  const verdict = receipt["verdict"];
  if (typeof verdict !== "string" || !VERDICTS.includes(verdict)) {
    errors.push("bad_verdict");
  }
  const verifiedAt = receipt["verified_at"];
  if (!validateTimestamp(verifiedAt)) {
    errors.push("bad_verified_at");
  }
  const bundleDigest = receipt["bundle_digest"];
  if (!isDigest(bundleDigest)) {
    errors.push("bad_bundle_digest");
  }

  const resultErrors = receipt["errors"];
  const errorsOk = errorsWellFormed(resultErrors);
  if (!errorsOk) {
    errors.push("bad_errors");
  }
  const provisional = receipt["provisional_reasons"];
  const provisionalOk = stringList(provisional);
  if (!provisionalOk) {
    errors.push("bad_provisional_reasons");
  }
  const insufficient = receipt["insufficient_reasons"];
  const insufficientOk = stringList(insufficient);
  if (!insufficientOk) {
    errors.push("bad_insufficient_reasons");
  }
  if (!isPlainObject(receipt["summary"])) {
    errors.push("bad_summary");
  }

  const errorCodes = receipt["error_codes"];
  if (!stringList(errorCodes)) {
    errors.push("bad_error_codes");
  } else if (errorsOk) {
    const expected = resultErrors.map((entry) => entry["code"]);
    if (!sameStringList(errorCodes, expected)) {
      errors.push("error_codes_mismatch");
    }
  }
  if (
    typeof verdict === "string" &&
    VERDICTS.includes(verdict) &&
    errorsOk &&
    provisionalOk &&
    insufficientOk &&
    verdict !== verdictClass(resultErrors, provisional, insufficient)
  ) {
    errors.push("verdict_mismatch");
  }

  const issuer = receipt["issuer"];
  const sig = receipt["sig"];
  const sigShapeOk =
    isPlainObject(sig) &&
    sig["alg"] === "ed25519" &&
    typeof sig["key"] === "string" &&
    typeof sig["value"] === "string" &&
    sig["value"] !== "";
  if (!sigShapeOk) {
    errors.push("bad_signature_shape");
  } else if (
    !(typeof issuer === "string" && issuer !== "" && sig["key"] === issuer)
  ) {
    errors.push("bad_signature");
  } else {
    try {
      const message = canonicalBytes(unsignedView(receipt));
      if (!(await verifyEd25519(issuer, message, sig["value"] as string))) {
        errors.push("bad_signature");
      }
    } catch {
      errors.push("bad_signature");
    }
  }

  let digestMatch: boolean | null = null;
  if (bundle !== null && bundle !== undefined) {
    try {
      const expected = await sha256Prefixed(canonicalBytes(bundleObject(bundle)));
      digestMatch = bundleDigest === expected;
    } catch {
      digestMatch = false;
    }
    if (digestMatch !== true) {
      errors.push("bundle_digest_mismatch");
    }
  }

  if (Array.isArray(revocations) && revocations.length > 0) {
    const checked = await verifyStatements(revocations);
    for (const entry of checked.errors) {
      errors.push(entry.code);
    }
    if (validateTimestamp(verifiedAt) && typeof issuer === "string" && issuer !== "") {
      const at = parseTimestamp(verifiedAt);
      if (at !== null) {
        for (const entry of checked.revoked) {
          if (entry.key === issuer && at >= entry.revokedAt) {
            errors.push("key_revoked");
          }
        }
      }
    }
  }

  result.valid = errors.length === 0;
  result.errors = errors;
  result.issuer = issuer === undefined ? null : issuer;
  result.verdict = verdict === undefined ? null : verdict;
  result.verified_at = verifiedAt === undefined ? null : verifiedAt;
  result.bundle_digest = bundleDigest === undefined ? null : bundleDigest;
  result.digest_match = digestMatch;
  return result;
}
