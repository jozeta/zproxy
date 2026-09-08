// Hex-digest hashing via the Web Crypto API (crypto.subtle), available in
// both extension pages and the service worker (both are secure contexts) —
// no bundled hash library needed. MD5 is deliberately not offered: it isn't
// implemented by SubtleCrypto (it's cryptographically broken, so browsers
// never added it), and hand-rolling one just for legacy-hash-comparison use
// cases isn't worth the added surface. Used by the Decoder view and
// Intruder's payload processing rules.
async function digestHex(algorithm, text) {
  const bytes = new TextEncoder().encode(text ?? "");
  const digest = await crypto.subtle.digest(algorithm, bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const sha1Hex = (text) => digestHex("SHA-1", text);
export const sha256Hex = (text) => digestHex("SHA-256", text);
export const sha384Hex = (text) => digestHex("SHA-384", text);
export const sha512Hex = (text) => digestHex("SHA-512", text);
