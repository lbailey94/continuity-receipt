/**
 * Continuity Receipt bundle verification (0.1 + 0.2 + 0.3 + 0.4 + 0.5 + 0.6).
 *
 * Verdicts: TRUSTED | PROVISIONAL | INSUFFICIENT_EVIDENCE | UNTRUSTED
 * (IETF CTQ-aligned semantics; see spec §7).
 *
 * This is a direct port of `continuity_receipt/verify.py`; error codes and
 * reason strings are intended to match the Python reference.
 */

import { BOUND_TYPES } from "./agreements.js";
import { receiptDigest } from "./bundle.js";
import {
  canonicalBytes,
  commitField,
  compareCodePoints,
  isPlainObject,
} from "./canon.js";
import { verifyEd25519 } from "./keys.js";
import {
  attestationView,
  parseTimestamp,
  RECORD_TYPES,
  REQUIRED_FIELDS,
  requiredFields,
  SUPPORTED_SPECS,
  unsignedView,
  validateTimestamp,
} from "./records.js";
import { mergeStatements, verifyStatements } from "./revocations.js";
import {
  parseStrictJson,
  StrictJsonError,
  StrictJsonNestingError,
} from "./strict_json.js";

export const ANCHOR_TYPES: readonly string[] = ["opentimestamps", "public-chain", "custom"];
export const PROVENANCE_PREFIXES: readonly string[] = ["sha256:", "merkle-sha256:"];
export const MAX_RECEIPTS = 10_000;
export const MAX_NESTING_DEPTH = 64;
export const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;

export type Verdict = "TRUSTED" | "PROVISIONAL" | "INSUFFICIENT_EVIDENCE" | "UNTRUSTED";

export interface VerifyError {
  code: string;
  detail: string;
  receipt_id: unknown;
}

export class VerifyResult {
  verdict: Verdict = "TRUSTED";
  errors: VerifyError[] = [];
  provisional_reasons: string[] = [];
  insufficient_reasons: string[] = [];
  summary: Record<string, unknown> = {};

  codes(): string[] {
    return this.errors.map((entry) => entry.code);
  }

  asDict(): Record<string, unknown> {
    return {
      verdict: this.verdict,
      errors: this.errors,
      provisional_reasons: this.provisional_reasons,
      insufficient_reasons: this.insufficient_reasons,
      summary: this.summary,
    };
  }
}

export interface VerifyOptions {
  requireAnchor?: boolean;
  externalRevocations?: unknown[] | null;
}

type Receipt = Record<string, unknown>;

function fatal(
  result: VerifyResult,
  code: string,
  detail: string,
  receiptId: unknown = null,
): void {
  result.errors.push({ code, detail, receipt_id: receiptId === undefined ? null : receiptId });
}

function repr(value: unknown): string {
  if (value === undefined) return "None";
  if (typeof value === "bigint") return value.toString();
  try {
    const text = JSON.stringify(value);
    return text === undefined ? String(value) : text;
  } catch {
    return String(value);
  }
}

async function tryDigest(receipt: Record<string, unknown>): Promise<string | null> {
  try {
    return await receiptDigest(receipt);
  } catch {
    return null;
  }
}

function depthExceeded(node: unknown, limit: number): boolean {
  const stack: Array<[unknown, number]> = [[node, 1]];
  while (stack.length > 0) {
    const [current, depth] = stack.pop() as [unknown, number];
    if (depth > limit) return true;
    if (Array.isArray(current)) {
      for (const value of current) stack.push([value, depth + 1]);
    } else if (isPlainObject(current)) {
      for (const value of Object.values(current)) stack.push([value, depth + 1]);
    }
  }
  return false;
}

function iterRedactions(
  node: unknown,
  path: string,
  out: Array<[string, Record<string, unknown>]>,
): void {
  if (isPlainObject(node)) {
    if (node["redacted"] === true) {
      out.push([path, node]);
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      iterRedactions(value, path ? `${path}.${key}` : key, out);
    }
  } else if (Array.isArray(node)) {
    node.forEach((value, index) => {
      iterRedactions(value, `${path}[${index}]`, out);
    });
  }
}

function checkShape(result: VerifyResult, bundle: Receipt, receipts: unknown[]): void {
  for (let index = 0; index < receipts.length; index++) {
    const receipt = receipts[index];
    if (!isPlainObject(receipt)) {
      fatal(result, "malformed", `receipt ${index} is not an object`);
      continue;
    }
    const rid = typeof receipt["receipt_id"] === "string" ? receipt["receipt_id"] : null;
    if (!isPlainObject(receipt["body"])) {
      fatal(result, "malformed", "body is not an object", rid);
    }
    if (!isPlainObject(receipt["issuer"])) {
      fatal(result, "malformed", "issuer is not an object", rid);
    }
  }
  const anchors = bundle["anchors"];
  if (anchors !== null && anchors !== undefined && !Array.isArray(anchors)) {
    fatal(result, "malformed", "anchors is not a list");
  } else if (Array.isArray(anchors)) {
    for (const anchor of anchors) {
      if (!isPlainObject(anchor)) {
        fatal(result, "anchor_invalid", "anchor entry is not an object");
      }
    }
  }
  const revocations = bundle["revocations"];
  if (revocations !== null && revocations !== undefined && !Array.isArray(revocations)) {
    fatal(result, "bad_revocation", "revocations must be a list");
  } else if (Array.isArray(revocations)) {
    for (const statement of revocations) {
      if (!isPlainObject(statement)) {
        fatal(result, "bad_revocation", "revocation statements must be objects");
      }
    }
  }
  const disclosureMap = bundle["disclosure_map"];
  if (disclosureMap !== null && disclosureMap !== undefined && !isPlainObject(disclosureMap)) {
    fatal(result, "malformed", "disclosure_map is not an object");
  }
  const chainHead = bundle["chain_head"];
  if (chainHead !== null && chainHead !== undefined && !isPlainObject(chainHead)) {
    fatal(result, "malformed", "chain_head is not an object");
  }
}

export async function verifyBundle(
  bundle: unknown,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const requireAnchor = options.requireAnchor ?? false;
  const externalRevocations = options.externalRevocations ?? null;
  const result = new VerifyResult();

  if (!isPlainObject(bundle)) {
    fatal(result, "malformed", "bundle is not an object");
    return finish(result);
  }
  if (depthExceeded(bundle, MAX_NESTING_DEPTH)) {
    fatal(result, "nesting_too_deep", `bundle nesting exceeds depth ${MAX_NESTING_DEPTH}`);
    return finish(result);
  }

  const bundleSpec = bundle["spec"];
  if (typeof bundleSpec !== "string" || !SUPPORTED_SPECS.includes(bundleSpec)) {
    fatal(result, "version_unsupported", `spec=${repr(bundle["spec"])}`);
    return finish(result);
  }

  const receipts = bundle["receipts"];
  if (!Array.isArray(receipts) || receipts.length === 0) {
    fatal(result, "malformed", "bundle has no receipts");
    return finish(result);
  }
  if (receipts.length > MAX_RECEIPTS) {
    fatal(result, "too_many_receipts", `${receipts.length} receipts exceeds limit ${MAX_RECEIPTS}`);
    return finish(result);
  }

  checkShape(result, bundle, receipts);

  const taskId = bundle["task_id"] ?? null;
  let expectedPrev: string | null = null;

  for (let index = 0; index < receipts.length; index++) {
    const receipt = receipts[index];
    if (!isPlainObject(receipt)) continue;
    const rid = receipt["receipt_id"] ?? null;
    const receiptSpec = receipt["spec"];
    if (typeof receiptSpec !== "string" || !SUPPORTED_SPECS.includes(receiptSpec)) {
      fatal(result, "version_unsupported", `receipt spec=${repr(receipt["spec"])}`, rid);
    }
    if ((receipt["task_id"] ?? null) !== taskId) {
      fatal(result, "task_mismatch", "receipt task_id != bundle task_id", rid);
    }
    const recordType = receipt["type"];
    const knownType = typeof recordType === "string" && RECORD_TYPES.includes(recordType);
    const disabledType =
      recordType === "state.commitment" &&
      receiptSpec !== "continuity-receipt/0.5" &&
      receiptSpec !== "continuity-receipt/0.6";
    const disabledGrant = recordType === "authority.grant" && receiptSpec !== "continuity-receipt/0.6";
    if (!knownType || disabledType || disabledGrant) {
      fatal(result, "unknown_type", `type=${repr(recordType)}`, rid);
      continue;
    }
    const body = receipt["body"];
    if (!isPlainObject(body)) continue;
    const missing = requiredFields(recordType as string, receiptSpec).filter(
      (name) => !(name in body),
    );
    if (missing.length > 0) {
      fatal(result, "malformed", `missing body fields ${repr(missing)}`, rid);
    }
    if (receiptSpec === "continuity-receipt/0.5" || receiptSpec === "continuity-receipt/0.6") {
      check05Body(result, recordType as string, body, rid);
    }
    if (receiptSpec === "continuity-receipt/0.6") {
      check06Body(result, recordType as string, body, rid);
    }

    if (!validateTimestamp(receipt["issued_at"])) {
      fatal(
        result,
        "malformed",
        `issued_at not RFC 3339 UTC: ${repr(receipt["issued_at"])}`,
        rid,
      );
    }

    if (receipt["seq"] !== index) {
      fatal(result, "chain_break", `seq ${repr(receipt["seq"])} != position ${index}`, rid);
    }
    if ((receipt["prev"] ?? null) !== expectedPrev) {
      fatal(result, "chain_break", "prev digest mismatch", rid);
    }
    const digest = await tryDigest(receipt);
    if (digest === null) {
      fatal(
        result,
        "malformed",
        "receipt is not canonically encodable (floats are rejected)",
        rid,
      );
      expectedPrev = null;
    } else {
      expectedPrev = digest;
    }

    const issuer = receipt["issuer"];
    const sig = receipt["sig"];
    if (
      !isPlainObject(sig) ||
      sig["alg"] !== "ed25519" ||
      typeof sig["value"] !== "string" ||
      sig["value"] === ""
    ) {
      fatal(result, "bad_signature", "missing or unsupported sig", rid);
    } else {
      const issuerId = isPlainObject(issuer) ? ("id" in issuer ? issuer["id"] : "") : "";
      let message: Uint8Array | null = null;
      try {
        message = canonicalBytes(unsignedView(receipt));
      } catch {
        fatal(result, "bad_signature", "receipt is not canonically encodable", rid);
      }
      if (message !== null) {
        if (
          typeof issuerId !== "string" ||
          !(await verifyEd25519(issuerId, message, sig["value"] as string))
        ) {
          fatal(result, "bad_signature", "signature does not verify", rid);
        }
      }
    }
  }

  const wellFormed = receipts.filter(isPlainObject);
  let disclosureMap: Record<string, unknown> | null = isPlainObject(bundle["disclosure_map"])
    ? bundle["disclosure_map"]
    : null;
  checkCrossRecord(result, wellFormed);
  await checkAgreements(result, wellFormed);
  await checkAuthority(result, wellFormed);
  await checkRedactions(result, wellFormed, disclosureMap ?? {});
  await checkAttestations(result, wellFormed);
  checkProvenance(result, wellFormed);
  await checkRevocations(result, bundle, wellFormed, externalRevocations);
  await checkAnchors(result, bundle, wellFormed, requireAnchor);
  await checkChainHead(result, bundle, wellFormed, requireAnchor);

  const types = wellFormed.map((receipt) => receipt["type"] ?? null);
  const issuers = new Set<string>();
  for (const receipt of wellFormed) {
    const issuer = receipt["issuer"];
    if (isPlainObject(issuer) && typeof issuer["id"] === "string") issuers.add(issuer["id"]);
  }
  const summary: Record<string, unknown> = {
    receipts: receipts.length,
    types,
    issuers: [...issuers].sort(compareCodePoints),
    terminated: types.includes("task.termination"),
    settled: types.includes("settlement"),
  };
  result.summary = { ...summary, ...result.summary };
  return finish(result);
}

function check05Body(
  result: VerifyResult,
  recordType: string,
  body: Receipt,
  rid: unknown,
): void {
  if (
    recordType === "session.pass.created" &&
    !["gate-lite", "gate-hard", "local"].includes(body["mandala_class"] as string)
  ) {
    fatal(result, "malformed", "mandala_class must be gate-lite, gate-hard, or local", rid);
  }
  if (
    recordType === "task.execution" &&
    !["bwrap", "landlock", "bwrap-landlock", "microvm-ch", "microvm-fc", "none"].includes(
      body["sandbox_class"] as string,
    )
  ) {
    fatal(result, "malformed", "sandbox_class is unknown", rid);
  }
  if (recordType === "task.execution") {
    const sandboxClass = body["sandbox_class"];
    if (sandboxClass === "bwrap" && !("runner_profile" in body)) {
      fatal(result, "malformed", "bwrap execution requires runner_profile", rid);
    }
    if ("runner_profile" in body) {
      const digest = /^sha256:[0-9a-f]{64}$/;
      const profile = body["runner_profile"];
      let validProfile = false;
      if (isPlainObject(profile)) {
        const keys = Object.keys(profile).sort();
        validProfile =
          keys.length === 3 &&
          keys[0] === "executable_digest" &&
          keys[1] === "invocation_digest" &&
          keys[2] === "profile_id" &&
          typeof profile["profile_id"] === "string" &&
          profile["profile_id"] !== "" &&
          typeof profile["executable_digest"] === "string" &&
          digest.test(profile["executable_digest"]) &&
          typeof profile["invocation_digest"] === "string" &&
          digest.test(profile["invocation_digest"]);
      }
      if (!validProfile) {
        fatal(
          result,
          "malformed",
          "runner_profile must contain a nonempty profile_id and sha256 executable_digest and invocation_digest",
          rid,
        );
      }
    }
  }
  if (recordType === "state.commitment") {
    const digest = /^sha256:[0-9a-f]{64}$/;
    const merkle = /^merkle-sha256:[0-9a-f]{64}$/;
    if (typeof body["state_kind"] !== "string" || body["state_kind"] === "") {
      fatal(result, "malformed", "state_kind must be nonempty text", rid);
    }
    if (typeof body["scope"] !== "string" || body["scope"] === "") {
      fatal(result, "malformed", "scope must be nonempty text", rid);
    }
    const count = body["count"] ?? null;
    if (
      typeof count !== "number" ||
      !Number.isInteger(count) ||
      count < 0 ||
      count > 2 ** 53 - 1
    ) {
      fatal(
        result,
        "malformed",
        "count must be an exact JSON integer from 0 through 2^53-1",
        rid,
      );
    }
    if (typeof body["head_digest"] !== "string" || !digest.test(body["head_digest"])) {
      fatal(result, "malformed", "head_digest must be a sha256 digest", rid);
    }
    const root = body["merkle_root"] ?? null;
    if (root !== null && (typeof root !== "string" || !merkle.test(root))) {
      fatal(result, "malformed", "merkle_root must be a merkle-sha256 digest", rid);
    }
  }
}

function check06Body(
  result: VerifyResult,
  recordType: string,
  body: Receipt,
  rid: unknown,
): void {
  if (recordType !== "authority.grant") return;
  const digest = /^sha256:[0-9a-f]{64}$/;
  if (typeof body["grant_id"] !== "string" || body["grant_id"] === "") {
    fatal(result, "malformed", "grant_id must be nonempty text", rid);
  }
  const principal = body["principal"];
  if (
    !isPlainObject(principal) ||
    typeof principal["id"] !== "string" ||
    principal["id"] === "" ||
    !["self_asserted", "issuer_verified"].includes(principal["assurance"] as string)
  ) {
    fatal(
      result,
      "malformed",
      "principal must name an id and an assurance of self_asserted or issuer_verified",
      rid,
    );
  }
  if (typeof body["agent"] !== "string" || body["agent"] === "") {
    fatal(result, "malformed", "agent must be a nonempty identifier", rid);
  }
  const scope = body["scope"];
  if (
    !Array.isArray(scope) ||
    scope.length === 0 ||
    scope.some((item) => typeof item !== "string" || item === "")
  ) {
    fatal(result, "malformed", "scope must be a nonempty list of nonempty strings", rid);
  }
  const granted = body["granted_at"];
  if (!validateTimestamp(granted)) {
    fatal(result, "malformed", "granted_at must be an RFC 3339 UTC timestamp", rid);
  }
  const expires = body["expires_at"] ?? null;
  if (expires !== null) {
    if (!validateTimestamp(expires)) {
      fatal(result, "malformed", "expires_at must be an RFC 3339 UTC timestamp", rid);
    } else if (validateTimestamp(granted)) {
      const grantedAt = parseTimestamp(granted);
      const expiresAt = parseTimestamp(expires);
      if (grantedAt !== null && expiresAt !== null && expiresAt <= grantedAt) {
        fatal(result, "malformed", "expires_at must follow granted_at", rid);
      }
    }
  }
  const reviewPolicy = body["review_policy"] ?? null;
  if (reviewPolicy !== null && !["none", "flagged", "full"].includes(reviewPolicy as string)) {
    fatal(result, "malformed", "review_policy must be none, flagged, or full", rid);
  }
  const constraints = body["constraints"] ?? null;
  if (constraints !== null && !isPlainObject(constraints)) {
    fatal(result, "malformed", "constraints must be an object", rid);
  }
  const policyRef = body["policy_ref"] ?? null;
  if (policyRef !== null && (typeof policyRef !== "string" || !digest.test(policyRef))) {
    fatal(result, "malformed", "policy_ref must be a sha256 digest", rid);
  }
  const gateRef = body["gate_ref"] ?? null;
  if (gateRef !== null && (typeof gateRef !== "string" || gateRef === "")) {
    fatal(result, "malformed", "gate_ref must be nonempty text", rid);
  }
}

function checkCrossRecord(result: VerifyResult, receipts: Receipt[]): void {
  const passReceipts = receipts.filter((receipt) => receipt["type"] === "session.pass.created");
  if (passReceipts.length === 0) {
    fatal(result, "malformed", "chain has no session.pass.created receipt");
    return;
  }
  const passBody = passReceipts[0]?.["body"];
  if (!isPlainObject(passBody)) return;
  const policyVersion = passBody["policy_version"] ?? null;

  for (const receipt of receipts) {
    if (receipt["type"] !== "task.decision") continue;
    const body = receipt["body"];
    if (!isPlainObject(body)) continue;
    if ((body["policy_version"] ?? null) !== policyVersion) {
      fatal(
        result,
        "policy_mismatch",
        `decision policy ${repr(body["policy_version"])} != pass policy ${repr(passBody["policy_version"])}`,
        receipt["receipt_id"] ?? null,
      );
    }
  }

  let spendCap: unknown = passBody["spend_cap"] ?? null;
  if (spendCap !== null && !isPlainObject(spendCap)) {
    fatal(result, "malformed", "pass spend_cap is not an object", passReceipts[0]?.["receipt_id"] ?? null);
    spendCap = null;
  }
  const typeBySeq = receipts.map((receipt) => receipt["type"] ?? null);
  const settlementIndexes: number[] = [];
  const deliveryIndexes: number[] = [];
  typeBySeq.forEach((type, index) => {
    if (type === "settlement") settlementIndexes.push(index);
    if (type === "delivery.attestation") deliveryIndexes.push(index);
  });

  for (const index of settlementIndexes) {
    const settlement = receipts[index] as Receipt;
    const body = settlement["body"];
    if (!isPlainObject(body)) continue;
    const amount: unknown = "amount" in body ? body["amount"] : {};
    if (!isPlainObject(amount)) {
      fatal(result, "malformed", "settlement amount is not an object", settlement["receipt_id"] ?? null);
      continue;
    }
    if (spendCap !== null) {
      const cap = spendCap as Receipt;
      let exceeds = false;
      const currencyDiffers = (amount["currency"] ?? null) !== (cap["currency"] ?? null);
      if (currencyDiffers) {
        exceeds = true;
      } else {
        const amountMinor: unknown = "minor" in amount ? amount["minor"] : 0;
        const capMinor: unknown = "minor" in cap ? cap["minor"] : 0;
        const left = pyInt(amountMinor);
        const right = pyInt(capMinor);
        if (left === null || right === null) {
          fatal(result, "malformed", "settlement amount is not numeric", settlement["receipt_id"] ?? null);
        } else {
          exceeds = left > right;
        }
      }
      if (exceeds) {
        fatal(
          result,
          "cap_exceeded",
          `settlement ${repr(amount)} exceeds cap ${repr(spendCap)}`,
          settlement["receipt_id"] ?? null,
        );
      }
    }
    if (
      body["gated_on_delivery"] &&
      (deliveryIndexes.length === 0 || Math.min(...deliveryIndexes) > index)
    ) {
      fatal(
        result,
        "delivery_before_settlement",
        "gated settlement recorded before any delivery attestation",
        settlement["receipt_id"] ?? null,
      );
    }
  }

  if (!typeBySeq.includes("task.termination")) {
    fatal(result, "missing_termination", "task has no termination receipt");
  }
}

function pyInt(value: unknown): bigint | null {
  try {
    if (typeof value === "bigint") return value;
    if (typeof value === "boolean") return value ? 1n : 0n;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) return null;
      return BigInt(Math.trunc(value));
    }
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!/^[+-]?[0-9]+$/.test(trimmed)) return null;
      return BigInt(trimmed);
    }
  } catch {
    return null;
  }
  return null;
}

async function checkAgreements(result: VerifyResult, receipts: Receipt[]): Promise<void> {
  const offers = new Map<string, Receipt>();
  const accepts = new Map<string, Receipt>();
  for (const receipt of receipts) {
    const recordType = receipt["type"];
    if (recordType !== "agreement.offer" && recordType !== "agreement.accept") continue;
    const digest = await tryDigest(receipt);
    if (digest === null) continue;
    (recordType === "agreement.offer" ? offers : accepts).set(digest, receipt);
  }

  for (const receipt of receipts) {
    if (receipt["type"] === "agreement.accept") {
      checkAccept(result, receipt, offers);
    }
  }

  const referenced = new Set<string>();
  for (const receipt of receipts) {
    if (!BOUND_TYPES.includes(receipt["type"] as string)) continue;
    const spec = receipt["spec"];
    if (
      spec !== "continuity-receipt/0.4" &&
      spec !== "continuity-receipt/0.5" &&
      spec !== "continuity-receipt/0.6"
    ) {
      continue;
    }
    const body = receipt["body"];
    if (!isPlainObject(body)) continue;
    const ref = body["agreement_ref"] ?? null;
    if (ref === null) continue;
    const accept = typeof ref === "string" ? accepts.get(ref) : undefined;
    if (accept === undefined) {
      result.insufficient_reasons.push(
        `missing_agreement:${String(receipt["receipt_id"] ?? null)}`,
      );
      continue;
    }
    referenced.add(ref as string);
    const acceptBody = accept["body"];
    if (!isPlainObject(acceptBody)) continue;
    const acceptIssued = accept["issued_at"];
    const boundIssued = receipt["issued_at"];
    if (validateTimestamp(acceptIssued) && validateTimestamp(boundIssued)) {
      const acceptAt = parseTimestamp(acceptIssued);
      const boundAt = parseTimestamp(boundIssued);
      if (acceptAt !== null && boundAt !== null && boundAt < acceptAt) {
        fatal(
          result,
          "agreement_before_accept",
          `bound receipt issued before its accept ${String(accept["receipt_id"] ?? null)}`,
          receipt["receipt_id"] ?? null,
        );
      }
    }
    const issuer = receipt["issuer"];
    const issuerId = isPlainObject(issuer) ? (issuer["id"] ?? null) : null;
    const offeree = acceptBody["offeree"] ?? null;
    if (typeof offeree === "string" && issuerId !== offeree) {
      fatal(
        result,
        "agreement_issuer_mismatch",
        `bound receipt issuer ${repr(issuerId)} is not the offeree`,
        receipt["receipt_id"] ?? null,
      );
    }
  }

  checkAgreementCompleteness(result, receipts, accepts, referenced);
}

function checkAccept(result: VerifyResult, receipt: Receipt, offers: Map<string, Receipt>): void {
  const body = receipt["body"];
  if (!isPlainObject(body)) return;
  const offerRef = body["offer_ref"] ?? null;
  const offer = typeof offerRef === "string" ? offers.get(offerRef) : undefined;
  if (offer === undefined) {
    result.insufficient_reasons.push(`missing_offer:${String(receipt["receipt_id"] ?? null)}`);
    return;
  }
  const offerBody = offer["body"];
  if (!isPlainObject(offerBody)) return;
  const validUntil = offerBody["valid_until"];
  if (!validateTimestamp(validUntil)) {
    fatal(
      result,
      "malformed",
      `offer valid_until not RFC 3339 UTC: ${repr(validUntil)}`,
      offer["receipt_id"] ?? null,
    );
    return;
  }
  if (
    (body["offer_id"] ?? null) !== (offerBody["offer_id"] ?? null) ||
    (body["terms_hash"] ?? null) !== (offerBody["terms_hash"] ?? null)
  ) {
    fatal(
      result,
      "offer_mismatch",
      "accept does not match the referenced offer",
      receipt["receipt_id"] ?? null,
    );
    return;
  }
  const acceptIssued = receipt["issued_at"];
  if (validateTimestamp(acceptIssued)) {
    const acceptAt = parseTimestamp(acceptIssued);
    const validAt = parseTimestamp(validUntil);
    if (acceptAt !== null && validAt !== null && acceptAt > validAt) {
      fatal(
        result,
        "offer_expired",
        `accept issued after offer valid_until ${validUntil}`,
        receipt["receipt_id"] ?? null,
      );
    }
  }
  const spec = receipt["spec"];
  if (
    spec !== "continuity-receipt/0.4" &&
    spec !== "continuity-receipt/0.5" &&
    spec !== "continuity-receipt/0.6"
  ) {
    return;
  }
  const offeree = body["offeree"] ?? null;
  const issuer = receipt["issuer"];
  const issuerId = isPlainObject(issuer) ? (issuer["id"] ?? null) : null;
  if (typeof offeree !== "string" || offeree === "") {
    fatal(
      result,
      "malformed",
      `accept offeree is not a string: ${repr(offeree)}`,
      receipt["receipt_id"] ?? null,
    );
  } else if (issuerId !== offeree || offeree !== (offerBody["offeree"] ?? null)) {
    fatal(
      result,
      "offeree_mismatch",
      `accept offeree ${repr(offeree)} does not match the signer ${repr(issuerId)} / offer`,
      receipt["receipt_id"] ?? null,
    );
  }
  const offerIssued = offer["issued_at"];
  if (validateTimestamp(acceptIssued) && validateTimestamp(offerIssued)) {
    const acceptAt = parseTimestamp(acceptIssued);
    const offerAt = parseTimestamp(offerIssued);
    if (acceptAt !== null && offerAt !== null && acceptAt < offerAt) {
      fatal(
        result,
        "accept_before_offer",
        `accept issued before offer ${String(offer["receipt_id"] ?? null)}`,
        receipt["receipt_id"] ?? null,
      );
    }
  }
}

function checkAgreementCompleteness(
  result: VerifyResult,
  receipts: Receipt[],
  accepts: Map<string, Receipt>,
  referenced: Set<string>,
): void {
  for (const [digest, accept] of accepts) {
    const spec = accept["spec"];
    if (
      (spec === "continuity-receipt/0.4" ||
        spec === "continuity-receipt/0.5" ||
        spec === "continuity-receipt/0.6") &&
      !referenced.has(digest)
    ) {
      result.provisional_reasons.push(
        `agreement_unreferenced:${String(accept["receipt_id"] ?? null)}`,
      );
    }
  }
  for (const receipt of receipts) {
    const spec = receipt["spec"];
    if (
      spec !== "continuity-receipt/0.4" &&
      spec !== "continuity-receipt/0.5" &&
      spec !== "continuity-receipt/0.6"
    ) {
      continue;
    }
    if (!BOUND_TYPES.includes(receipt["type"] as string)) continue;
    const body = receipt["body"];
    if (!isPlainObject(body) || (body["agreement_ref"] ?? null) !== null) continue;
    const issuer = receipt["issuer"];
    const issuerId = isPlainObject(issuer) ? (issuer["id"] ?? null) : null;
    const boundIssued = receipt["issued_at"];
    if (typeof issuerId !== "string" || !validateTimestamp(boundIssued)) continue;
    const boundAt = parseTimestamp(boundIssued);
    if (boundAt === null) continue;
    for (const accept of accepts.values()) {
      const acceptSpec = accept["spec"];
      if (
        acceptSpec !== "continuity-receipt/0.4" &&
        acceptSpec !== "continuity-receipt/0.5" &&
        acceptSpec !== "continuity-receipt/0.6"
      ) {
        continue;
      }
      const acceptBody = accept["body"];
      if (!isPlainObject(acceptBody) || (acceptBody["offeree"] ?? null) !== issuerId) continue;
      const acceptIssued = accept["issued_at"];
      if (!validateTimestamp(acceptIssued)) continue;
      const acceptAt = parseTimestamp(acceptIssued);
      if (acceptAt !== null && acceptAt <= boundAt) {
        result.provisional_reasons.push(
          `missing_agreement_ref:${String(receipt["receipt_id"] ?? null)}`,
        );
        break;
      }
    }
  }
}

async function checkAuthority(result: VerifyResult, receipts: Receipt[]): Promise<void> {
  const grants = new Map<string, Receipt>();
  for (const receipt of receipts) {
    if (receipt["type"] !== "authority.grant") continue;
    const digest = await tryDigest(receipt);
    if (digest !== null) grants.set(digest, receipt);
  }

  const referenced = new Set<string>();
  for (const receipt of receipts) {
    if (!BOUND_TYPES.includes(receipt["type"] as string)) continue;
    if (receipt["spec"] !== "continuity-receipt/0.6") continue;
    const body = receipt["body"];
    if (!isPlainObject(body)) continue;
    const ref = body["authority_ref"] ?? null;
    if (ref === null) continue;
    const grant = typeof ref === "string" ? grants.get(ref) : undefined;
    if (grant === undefined) {
      result.insufficient_reasons.push(
        `missing_authority:${String(receipt["receipt_id"] ?? null)}`,
      );
      continue;
    }
    referenced.add(ref as string);
    const grantBody = grant["body"];
    if (!isPlainObject(grantBody)) continue;
    const grantIssued = grant["issued_at"];
    const boundIssued = receipt["issued_at"];
    let effective: unknown = grantIssued ?? null;
    const grantedAt = grantBody["granted_at"];
    if (validateTimestamp(grantedAt)) {
      if (!validateTimestamp(effective)) {
        effective = grantedAt;
      } else {
        const effectiveAt = parseTimestamp(effective);
        const grantedTime = parseTimestamp(grantedAt);
        if (
          effectiveAt !== null &&
          grantedTime !== null &&
          grantedTime > effectiveAt
        ) {
          effective = grantedAt;
        }
      }
    }
    if (validateTimestamp(effective) && validateTimestamp(boundIssued)) {
      const effectiveAt = parseTimestamp(effective);
      const boundAt = parseTimestamp(boundIssued);
      if (effectiveAt !== null && boundAt !== null && boundAt < effectiveAt) {
        fatal(
          result,
          "authority_before_grant",
          `bound receipt issued before its authority grant ${String(grant["receipt_id"] ?? null)}`,
          receipt["receipt_id"] ?? null,
        );
      }
    }
    const issuer = receipt["issuer"];
    const issuerId = isPlainObject(issuer) ? (issuer["id"] ?? null) : null;
    const agent = grantBody["agent"] ?? null;
    if (typeof agent === "string" && issuerId !== agent) {
      fatal(
        result,
        "authority_agent_mismatch",
        `bound receipt issuer ${repr(issuerId)} is not the grant's agent`,
        receipt["receipt_id"] ?? null,
      );
    }
    const expires = grantBody["expires_at"] ?? null;
    if (validateTimestamp(expires) && validateTimestamp(boundIssued)) {
      const expiresAt = parseTimestamp(expires);
      const boundAt = parseTimestamp(boundIssued);
      if (expiresAt !== null && boundAt !== null && boundAt > expiresAt) {
        fatal(
          result,
          "authority_expired",
          `bound receipt issued after the authority window ${expires}`,
          receipt["receipt_id"] ?? null,
        );
      }
    }
  }

  for (const [digest, grant] of grants) {
    if (!referenced.has(digest)) {
      result.provisional_reasons.push(
        `authority_unreferenced:${String(grant["receipt_id"] ?? null)}`,
      );
    }
  }
}

async function checkRedactions(
  result: VerifyResult,
  receipts: Receipt[],
  disclosureMap: Record<string, unknown>,
): Promise<void> {
  const redactions: Array<[string, Record<string, unknown>]> = [];
  iterRedactions(receipts, "receipts", redactions);
  for (const [path, field] of redactions) {
    if (requiredFieldForPath(path, receipts) !== null) {
      fatal(result, "redacted_required", `required field redacted at ${path}`);
      continue;
    }
    const entry = disclosureMap[path];
    if (isPlainObject(entry) && "salt" in entry && "value" in entry) {
      try {
        const commit = await commitField(entry["salt"] as string, entry["value"]);
        if (commit !== (field["commit"] ?? null)) {
          fatal(result, "commit_mismatch", `commit mismatch at ${path}`);
        }
      } catch {
        fatal(result, "commit_mismatch", `disclosure entry malformed at ${path}`);
      }
      continue;
    }
    if (field["erased"]) {
      result.insufficient_reasons.push(`erased_content:${path}`);
    } else {
      result.provisional_reasons.push(`redacted_without_disclosure:${path}`);
    }
  }
}

async function checkAttestations(result: VerifyResult, receipts: Receipt[]): Promise<void> {
  const seen: Array<Record<string, unknown>> = [];
  for (const receipt of receipts) {
    if (receipt["type"] !== "delivery.attestation") continue;
    const body = isPlainObject(receipt["body"]) ? receipt["body"] : {};
    const counterparty: unknown = "counterparty" in body ? body["counterparty"] : {};
    const attestation: unknown = isPlainObject(counterparty)
      ? (counterparty["attestation"] ?? null)
      : null;
    if (!attestation) {
      seen.push({
        receipt_id: receipt["receipt_id"] ?? null,
        counterparty: isPlainObject(counterparty) ? (counterparty["id"] ?? null) : null,
        attestation: "absent",
      });
      continue;
    }
    let view: Uint8Array | null = null;
    let attestationKey: string | null = null;
    let attestationValue: string | null = null;
    if (isPlainObject(attestation)) {
      const key = attestation["key"];
      const value = attestation["value"];
      if (
        attestation["alg"] === "ed25519" &&
        typeof key === "string" &&
        typeof value === "string"
      ) {
        attestationKey = key;
        attestationValue = value;
        try {
          view = canonicalBytes(attestationView(body));
        } catch {
          view = null;
        }
      }
    }
    const valid =
      view !== null &&
      attestationKey !== null &&
      attestationValue !== null &&
      (await verifyEd25519(attestationKey, view, attestationValue));
    seen.push({
      receipt_id: receipt["receipt_id"] ?? null,
      counterparty: isPlainObject(counterparty) ? (counterparty["id"] ?? null) : null,
      attestation: valid ? "valid" : "invalid",
      key: attestationKey,
    });
    if (!valid) {
      fatal(
        result,
        "bad_attestation",
        "counterparty attestation does not verify",
        receipt["receipt_id"] ?? null,
      );
    }
  }
  if (seen.length > 0) {
    result.summary["attestations"] = seen;
  }
}

function checkProvenance(result: VerifyResult, receipts: Receipt[]): void {
  for (const receipt of receipts) {
    if (receipt["type"] !== "task.decision") continue;
    const body = receipt["body"];
    if (!isPlainObject(body)) continue;
    const provenance = body["input_provenance"];
    if (!isPlainObject(provenance)) continue;
    const observed = provenance["observed_sources_hash"] ?? null;
    if (observed === null) continue;
    if (
      typeof observed !== "string" ||
      !PROVENANCE_PREFIXES.some((prefix) => observed.startsWith(prefix))
    ) {
      fatal(
        result,
        "provenance_invalid",
        `observed_sources_hash has unsupported form: ${repr(observed)}`,
        receipt["receipt_id"] ?? null,
      );
    }
  }
}

async function checkRevocations(
  result: VerifyResult,
  bundle: Receipt,
  receipts: Receipt[],
  externalRevocations: unknown[] | null,
): Promise<void> {
  const bundleRevocations: unknown = bundle["revocations"] || [];
  if (!Array.isArray(bundleRevocations)) return;
  if (!bundleRevocations.every(isPlainObject)) return;
  let merged: unknown[];
  let revoked: Array<{ key: string; revokedAt: number }>;
  let statementErrors: Array<{ code: string; detail: string }>;
  try {
    merged = mergeStatements(bundleRevocations, externalRevocations);
    const verification = await verifyStatements(merged);
    revoked = verification.revoked;
    statementErrors = verification.errors;
  } catch (error) {
    fatal(result, "bad_revocation", `revocations unusable: ${(error as Error).message}`);
    return;
  }
  for (const { code, detail } of statementErrors) {
    fatal(result, code, detail);
  }
  const checked = revoked.length;

  for (const receipt of receipts) {
    const issuer = receipt["issuer"];
    const keyId = isPlainObject(issuer) ? (issuer["id"] ?? null) : null;
    const issued = receipt["issued_at"];
    if (typeof keyId !== "string" || !validateTimestamp(issued)) continue;
    const issuedAt = parseTimestamp(issued);
    if (issuedAt === null) continue;
    for (const entry of revoked) {
      if (entry.key === keyId && issuedAt >= entry.revokedAt) {
        fatal(
          result,
          "key_revoked",
          `issuer key ${keyId} was revoked at ${new Date(entry.revokedAt).toISOString()}`,
          receipt["receipt_id"] ?? null,
        );
      }
    }
  }
  if (merged.length > 0) {
    result.summary["revocations_checked"] = checked;
  }
  if (externalRevocations !== null) {
    result.summary["revocations_external"] = externalRevocations.length;
  }
}

async function checkAnchors(
  result: VerifyResult,
  bundle: Receipt,
  receipts: Receipt[],
  requireAnchor: boolean,
): Promise<void> {
  const anchors = bundle["anchors"];
  if (!anchors) {
    if (requireAnchor) {
      result.provisional_reasons.push("anchor_missing");
    }
    return;
  }
  if (!Array.isArray(anchors)) return;
  const byId = new Map<string, Receipt>();
  for (const receipt of receipts) {
    const rid = receipt["receipt_id"];
    if (typeof rid === "string") byId.set(rid, receipt);
  }
  const kinds: string[] = [];
  for (const anchor of anchors) {
    if (!isPlainObject(anchor)) continue;
    const targetKey = anchor["target"] ?? null;
    const target = typeof targetKey === "string" ? byId.get(targetKey) : undefined;
    const digest = target !== undefined ? await tryDigest(target) : null;
    if (target === undefined || digest === null || (anchor["hash"] ?? null) !== digest) {
      fatal(result, "anchor_invalid", `anchor invalid for ${repr(anchor["target"])}`);
      continue;
    }
    const meta = anchor["anchor"] ?? null;
    if (meta !== null) {
      if (!isPlainObject(meta) || !ANCHOR_TYPES.includes(meta["type"] as string)) {
        fatal(
          result,
          "anchor_invalid",
          `unknown anchor type: ${isPlainObject(meta) ? repr(meta["type"]) : repr(meta)}`,
        );
        continue;
      }
      kinds.push(meta["type"] as string);
    }
  }
  if (anchors.length > 0) {
    result.summary["anchors"] = kinds.length > 0 ? kinds : ["hash-only"];
  }
}

/**
 * Optional bundle-level commitment to the final receipt (`chain_head`).
 *
 * Absence is not an error. When present it must match the final receipt's
 * seq, receipt_id, and canonical digest; an optional `anchored` disclosure
 * reuses the anchor type vocabulary.
 */
async function checkChainHead(
  result: VerifyResult,
  bundle: Receipt,
  receipts: Receipt[],
  requireAnchor: boolean,
): Promise<void> {
  const head = bundle["chain_head"];
  if (head === null || head === undefined || !isPlainObject(head)) {
    return; // absence is fine; a wrong shape was recorded as malformed
  }
  const last = receipts.length > 0 ? receipts[receipts.length - 1] : null;
  if (!isPlainObject(last)) {
    return; // empty/ill-formed chains already carry their own error
  }
  const digest = await tryDigest(last);
  if (digest === null) {
    return; // not canonically encodable; already recorded
  }
  if (
    (head["seq"] ?? null) !== (last["seq"] ?? null) ||
    (head["receipt_id"] ?? null) !== (last["receipt_id"] ?? null) ||
    (head["digest"] ?? null) !== digest
  ) {
    fatal(result, "head_mismatch", "chain_head does not match the final receipt");
    return;
  }
  const anchored = head["anchored"] ?? null;
  if (anchored === null) {
    if (requireAnchor) {
      result.provisional_reasons.push("head_anchor_missing");
    }
    return;
  }
  if (
    !isPlainObject(anchored) ||
    !ANCHOR_TYPES.includes(anchored["type"] as string) ||
    typeof anchored["proof_ref"] !== "string" ||
    anchored["proof_ref"] === ""
  ) {
    fatal(result, "head_anchor_invalid", "chain_head anchored entry is invalid");
    return;
  }
  result.summary["chain_head"] = { seq: last["seq"] ?? null, anchored: anchored["type"] };
}

function requiredFieldForPath(path: string, receipts: Receipt[]): string | null {
  const parts = path.split(".");
  if (parts.length >= 3 && (parts[0] as string).startsWith("receipts[") && parts[1] === "body") {
    const indexText = (parts[0] as string).slice("receipts[".length).replace(/\]$/, "");
    if (!/^[0-9]+$/.test(indexText)) return null;
    const receipt = receipts[Number.parseInt(indexText, 10)];
    if (!isPlainObject(receipt)) return null;
    const recordType = receipt["type"];
    if (
      typeof recordType === "string" &&
      recordType in REQUIRED_FIELDS &&
      REQUIRED_FIELDS[recordType]?.includes(parts[2] as string)
    ) {
      return parts[2] as string;
    }
  }
  return null;
}

function finish(result: VerifyResult): VerifyResult {
  if (result.errors.length > 0) {
    result.verdict = "UNTRUSTED";
  } else if (result.insufficient_reasons.length > 0) {
    result.verdict = "INSUFFICIENT_EVIDENCE";
  } else if (result.provisional_reasons.length > 0) {
    result.verdict = "PROVISIONAL";
  } else {
    result.verdict = "TRUSTED";
  }
  return result;
}

/**
 * Read, strictly parse, and verify a bundle file. Parse/IO failures are
 * returned as UNTRUSTED results (`malformed`, `nesting_too_deep`,
 * `bundle_too_large`, `io_error`), matching the Python CLI's fail-closed
 * posture.
 */
export async function verifyFile(path: string, options: VerifyOptions = {}): Promise<VerifyResult> {
  const result = new VerifyResult();
  let bytes: Uint8Array;
  try {
    const fs = await import("node:fs/promises");
    bytes = new Uint8Array(await fs.readFile(path));
  } catch (error) {
    fatal(result, "io_error", `cannot read bundle: ${(error as Error).message}`);
    return finish(result);
  }
  if (bytes.length > MAX_BUNDLE_BYTES) {
    fatal(result, "bundle_too_large", `${bytes.length} bytes exceeds limit ${MAX_BUNDLE_BYTES}`);
    return finish(result);
  }
  let bundle: unknown;
  try {
    bundle = parseStrictJson(bytes);
  } catch (error) {
    if (error instanceof StrictJsonNestingError) {
      fatal(result, "nesting_too_deep", "JSON nesting exceeds the parser limit");
      return finish(result);
    }
    if (error instanceof StrictJsonError) {
      fatal(result, "malformed", `bundle is not valid JSON: ${error.message}`);
      return finish(result);
    }
    throw error;
  }
  return verifyBundle(bundle, options);
}
