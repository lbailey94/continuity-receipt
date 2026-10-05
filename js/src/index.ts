/** continuity-receipt — offline verifier (ESM). */

export {
  canonicalBytes,
  canonicalString,
  commitField,
  compareCodePoints,
  isPlainObject,
  CanonicalizationError,
} from "./canon.js";
export { fromHex, toHex, sha256, sha256Prefixed } from "./hash.js";
export {
  b58decode,
  b58encode,
  b64uDecode,
  didKeyToPublicKey,
  publicKeyToDidKey,
  verifyEd25519,
} from "./keys.js";
export {
  SPEC_ID,
  SUPPORTED_SPECS,
  RECORD_TYPES,
  REQUIRED_FIELDS,
  REQUIRED_FIELDS_04,
  requiredFields,
  validateBody,
  validateTimestamp,
  parseTimestamp,
  unsignedView,
  attestationView,
  receiptDigest,
} from "./records.js";
export { termsHash, BOUND_TYPES } from "./agreements.js";
export {
  JsonFloat,
  parseStrictJson,
  StrictJsonError,
  StrictJsonNestingError,
} from "./strict_json.js";
export {
  mergeStatements,
  verifyStatements,
  statementsFromDocument,
  RevocationError,
  DOCUMENT_KIND,
  DOCUMENT_VERSION,
  MAX_DOCUMENT_BYTES,
} from "./revocations.js";
export type { RevokedKey, RevocationVerification } from "./revocations.js";
export {
  verifyBundle,
  verifyFile,
  VerifyResult,
  ANCHOR_TYPES,
  PROVENANCE_PREFIXES,
  MAX_RECEIPTS,
  MAX_NESTING_DEPTH,
  MAX_BUNDLE_BYTES,
} from "./verify.js";
export type { Verdict, VerifyError, VerifyOptions } from "./verify.js";
