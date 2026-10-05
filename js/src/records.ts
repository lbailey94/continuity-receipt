/** Receipt envelopes, body requirements, and timestamp helpers (0.1-0.6). */

import { canonicalBytes } from "./canon.js";
import { sha256Prefixed } from "./hash.js";
import type { JsonFloat } from "./strict_json.js";

export const SPEC_ID = "continuity-receipt/0.5";

export const SUPPORTED_SPECS: readonly string[] = [
  "continuity-receipt/0.1",
  "continuity-receipt/0.2",
  "continuity-receipt/0.3",
  "continuity-receipt/0.4",
  "continuity-receipt/0.5",
  "continuity-receipt/0.6",
];

export const RECORD_TYPES: readonly string[] = [
  "session.pass.created",
  "task.decision",
  "task.execution",
  "delivery.attestation",
  "task.termination",
  "settlement",
  "authority.succession",
  "agreement.offer",
  "agreement.accept",
  "state.commitment",
  "authority.grant",
];

export const REQUIRED_FIELDS: Record<string, readonly string[]> = {
  "session.pass.created": [
    "gate_id",
    "mandala_class",
    "quotas",
    "expires_at",
    "policy_version",
    "mandate_ref",
    "agent_id",
  ],
  "task.decision": [
    "action",
    "action_args_hash",
    "model",
    "input_provenance",
    "decision",
    "policy_version",
  ],
  "task.execution": ["tool_calls", "egress", "resources", "sandbox_class"],
  "delivery.attestation": ["request_hash", "response_hash", "counterparty"],
  "task.termination": ["reason", "limits_at_stop", "remaining"],
  settlement: ["rail", "rail_ref", "amount", "gated_on_delivery", "settled_at"],
  "authority.succession": ["from_authority", "to_authority", "effective_at", "reason"],
  "agreement.offer": ["offer_id", "offeree", "terms_hash", "valid_until", "nonce"],
  "agreement.accept": ["offer_ref", "offer_id", "terms_hash"],
  "state.commitment": ["state_kind", "scope", "count", "head_digest"],
  "authority.grant": ["grant_id", "principal", "agent", "scope", "granted_at"],
};

export const REQUIRED_FIELDS_04: Record<string, readonly string[]> = {
  "agreement.accept": ["offer_ref", "offer_id", "terms_hash", "offeree"],
};

const SPEC_04_PLUS = new Set([
  "continuity-receipt/0.4",
  "continuity-receipt/0.5",
  "continuity-receipt/0.6",
]);

const SPEC_05_PLUS = new Set(["continuity-receipt/0.5", "continuity-receipt/0.6"]);

export function requiredFields(recordType: string, spec?: unknown): readonly string[] {
  if (SPEC_04_PLUS.has(spec as string) && recordType in REQUIRED_FIELDS_04) {
    return REQUIRED_FIELDS_04[recordType] as readonly string[];
  }
  if (recordType === "state.commitment" && !SPEC_05_PLUS.has(spec as string)) {
    return [];
  }
  if (recordType === "authority.grant" && spec !== "continuity-receipt/0.6") {
    return [];
  }
  return REQUIRED_FIELDS[recordType] ?? [];
}

export function validateBody(recordType: string, body: unknown, spec?: unknown): void {
  if (!(recordType in REQUIRED_FIELDS)) {
    throw new Error(`unknown_type: ${recordType}`);
  }
  if (recordType === "state.commitment" && !SPEC_05_PLUS.has(spec as string)) {
    throw new Error(`unknown_type: ${recordType} in ${String(spec)}`);
  }
  if (recordType === "authority.grant" && spec !== "continuity-receipt/0.6") {
    throw new Error(`unknown_type: ${recordType} in ${String(spec)}`);
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new Error(`malformed body for ${recordType}: not an object`);
  }
  const record = body as Record<string, unknown>;
  const missing = requiredFields(recordType, spec).filter((name) => !(name in record));
  if (missing.length > 0) {
    throw new Error(`malformed body for ${recordType}: missing ${JSON.stringify(missing)}`);
  }
}

const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

export function validateTimestamp(value: unknown): value is string {
  return typeof value === "string" && TIMESTAMP_RE.test(value);
}

/** Epoch milliseconds for a validated RFC 3339 UTC timestamp; null if invalid. */
export function parseTimestamp(value: string): number | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
  if (match === null) return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction] = match;
  const date = new Date(0);
  date.setUTCFullYear(Number(yearText), Number(monthText) - 1, Number(dayText));
  date.setUTCHours(Number(hourText), Number(minuteText), Number(secondText), 0);
  const millis = fraction === undefined ? 0 : Number(fraction.padEnd(3, "0"));
  const time = date.getTime() + millis;
  return Number.isNaN(time) ? null : time;
}

export function unsignedView(receipt: Record<string, unknown>): Record<string, unknown> {
  const view: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(receipt)) {
    if (key !== "sig") view[key] = value;
  }
  return view;
}

/** The view a counterparty attestation signs: body without counterparty.attestation. */
export function attestationView(body: Record<string, unknown>): Record<string, unknown> {
  const view: Record<string, unknown> = { ...body };
  const counterparty = view["counterparty"];
  if (typeof counterparty === "object" && counterparty !== null && !Array.isArray(counterparty)) {
    const copy: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(counterparty as Record<string, unknown>)) {
      if (key !== "attestation") copy[key] = value;
    }
    view["counterparty"] = copy;
  }
  return view;
}

/** Convenience for tests/parity: sha256 over the unsigned receipt view. */
export async function receiptDigest(receipt: Record<string, unknown>): Promise<string> {
  return sha256Prefixed(canonicalBytes(unsignedView(receipt)));
}

/** Marker type aliases kept small for callers that build bundles. */
export type Receipt = Record<string, unknown>;
export type JsonFloatMarker = JsonFloat;
