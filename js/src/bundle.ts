/** Bundle-level helpers (chain digests), mirroring `continuity_receipt/bundle.py`. */

import { canonicalBytes } from "./canon.js";
import { sha256Prefixed } from "./hash.js";
import { unsignedView } from "./records.js";

export async function receiptDigest(receipt: Record<string, unknown>): Promise<string> {
  return sha256Prefixed(canonicalBytes(unsignedView(receipt)));
}
