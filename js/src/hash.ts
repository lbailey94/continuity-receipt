/** SHA-256 and hex helpers built only on WebCrypto / built-ins. */

export function toHex(bytes: Uint8Array): string {
  const table = "0123456789abcdef";
  let out = "";
  for (const byte of bytes) {
    out += table[byte >> 4];
    out += table[byte & 0x0f];
  }
  return out;
}

/**
 * Hex decode mirroring Python's `bytes.fromhex` (ASCII whitespace between
 * digits is ignored; odd length and non-hex digits raise).
 */
export function fromHex(text: string): Uint8Array {
  const cleaned = text.replace(/[\t\n\v\f\r ]/g, "");
  if (cleaned.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(cleaned)) {
    throw new Error("non-hexadecimal number found in fromhex() arg");
  }
  const out = new Uint8Array(cleaned.length / 2);
  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(cleaned.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

export function getSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("WebCrypto SubtleCrypto is not available in this environment");
  }
  return subtle;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await getSubtle().digest("SHA-256", data as BufferSource);
  return new Uint8Array(digest);
}

export async function sha256Prefixed(data: Uint8Array): Promise<string> {
  return "sha256:" + toHex(await sha256(data));
}
