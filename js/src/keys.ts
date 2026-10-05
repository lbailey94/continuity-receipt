/**
 * Ed25519 `did:key` (z6Mk...) keys, mirroring `continuity_receipt/keys.py`.
 *
 * Verification prefers WebCrypto (`crypto.subtle`, available in Node >= 18
 * and browsers); a `node:crypto` fallback is loaded dynamically when the
 * runtime's WebCrypto lacks Ed25519.
 */

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MULTICODEC_ED25519 = Uint8Array.of(0xed, 0x01);

// SubjectPublicKeyInfo DER prefix for a raw Ed25519 public key.
const ED25519_SPKI_PREFIX = Uint8Array.of(
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
);

export function b58decode(text: string): Uint8Array {
  let number = 0n;
  for (const char of text) {
    const index = B58_ALPHABET.indexOf(char);
    if (index < 0) throw new Error(`invalid base58 character: ${JSON.stringify(char)}`);
    number = number * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  let rest = number;
  while (rest > 0n) {
    bytes.unshift(Number(rest & 0xffn));
    rest >>= 8n;
  }
  let pad = 0;
  for (const char of text) {
    if (char === "1") pad++;
    else break;
  }
  return Uint8Array.from([...new Array<number>(pad).fill(0), ...bytes]);
}

export function b58encode(data: Uint8Array): string {
  let number = 0n;
  for (const byte of data) number = number * 256n + BigInt(byte);
  let encoded = "";
  while (number > 0n) {
    const remainder = Number(number % 58n);
    encoded = B58_ALPHABET[remainder] + encoded;
    number /= 58n;
  }
  let pad = 0;
  for (const byte of data) {
    if (byte === 0) pad++;
    else break;
  }
  return "1".repeat(pad) + encoded;
}

/** Decode an unpadded base64url string the way Python's urlsafe_b64decode does. */
export function b64uDecode(text: string): Uint8Array {
  const translated = text.replace(/-/g, "+").replace(/_/g, "/");
  const cleaned = translated.replace(/[^A-Za-z0-9+/]/g, "");
  if (cleaned.length % 4 === 1) {
    throw new Error("invalid base64url value");
  }
  const padded = cleaned + "=".repeat((4 - (cleaned.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    out[index] = binary.charCodeAt(index);
  }
  return out;
}

/** Raw 32-byte Ed25519 public key for a `did:key:z6Mk...` identifier. */
export function didKeyToPublicKey(did: string): Uint8Array {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) {
    throw new Error(`unsupported did:key form: ${String(did).slice(0, 24)}`);
  }
  const raw = b58decode(did.slice("did:key:z".length));
  if (
    raw.length !== 34 ||
    raw[0] !== MULTICODEC_ED25519[0] ||
    raw[1] !== MULTICODEC_ED25519[1]
  ) {
    throw new Error("did:key is not an Ed25519 key");
  }
  return raw.slice(2);
}

export function publicKeyToDidKey(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.length !== 32) throw new Error("Ed25519 public keys are 32 bytes");
  const multicodec = new Uint8Array(2 + rawPublicKey.length);
  multicodec.set(MULTICODEC_ED25519, 0);
  multicodec.set(rawPublicKey, 2);
  return "did:key:z" + b58encode(multicodec);
}

/**
 * Verify an Ed25519 signature over `message`. Never throws: any unsupported
 * did:key, malformed signature encoding, or verification failure returns false.
 */
export async function verifyEd25519(
  did: string,
  message: Uint8Array,
  signatureB64u: string,
): Promise<boolean> {
  let publicKey: Uint8Array;
  try {
    publicKey = didKeyToPublicKey(did);
  } catch {
    return false;
  }
  let signature: Uint8Array;
  try {
    signature = b64uDecode(signatureB64u);
  } catch {
    return false;
  }
  if (signature.length !== 64) return false;
  try {
    const subtle = globalThis.crypto?.subtle;
    if (subtle) {
      const key = await subtle.importKey(
        "raw",
        publicKey as BufferSource,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return await subtle.verify(
        { name: "Ed25519" },
        key,
        signature as BufferSource,
        message as BufferSource,
      );
    }
  } catch {
    // fall through to the Node-native implementation
  }
  return verifyEd25519Node(publicKey, message, signature);
}

async function verifyEd25519Node(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const nodeCrypto = await import("node:crypto");
    const der = new Uint8Array(ED25519_SPKI_PREFIX.length + publicKey.length);
    der.set(ED25519_SPKI_PREFIX, 0);
    der.set(publicKey, ED25519_SPKI_PREFIX.length);
    const key = nodeCrypto.createPublicKey({
      key: Buffer.from(der),
      format: "der",
      type: "spki",
    });
    return nodeCrypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}
