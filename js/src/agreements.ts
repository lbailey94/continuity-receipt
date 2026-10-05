/** Agreement binding constants, mirroring `continuity_receipt/agreements.py`. */

import { canonicalBytes } from "./canon.js";
import { sha256Prefixed } from "./hash.js";

/** Record types the accept binds in 0.4+ (the stages after the agreement). */
export const BOUND_TYPES: readonly string[] = [
  "task.decision",
  "task.execution",
  "delivery.attestation",
  "settlement",
];

/** The grounded commitment to off-receipt terms (JCS canonical bytes). */
export async function termsHash(terms: unknown): Promise<string> {
  return sha256Prefixed(canonicalBytes(terms));
}
