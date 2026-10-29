// Hex-digest hashing. SHA-family digests and HMAC go through the Web Crypto
// API (crypto.subtle), available in both extension pages and the service
// worker (both are secure contexts). MD5 and CRC-32 aren't in SubtleCrypto
// (MD5 is cryptographically broken, so browsers never added it), but
// testers constantly need them to recognize or reproduce legacy hashes and
// checksums, so both are small pure-JS implementations below — for
// comparison and payload generation only, never for securing anything.
// Used by the Decoder view and Intruder's payload processing rules.
async function digestHex(algorithm, text) {
  const bytes = new TextEncoder().encode(text ?? "");
  const digest = await crypto.subtle.digest(algorithm, bytes);
  return toHex(new Uint8Array(digest));
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const sha1Hex = (text) => digestHex("SHA-1", text);
export const sha256Hex = (text) => digestHex("SHA-256", text);
export const sha384Hex = (text) => digestHex("SHA-384", text);
export const sha512Hex = (text) => digestHex("SHA-512", text);

/** HMAC-SHA-256 of `text` keyed with `key` (both UTF-8), as hex. */
export async function hmacSha256Hex(key, text) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey("raw", enc.encode(key ?? ""), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(text ?? ""))));
}

// --- MD5 (RFC 1321) ---
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

/** MD5 of `text` (UTF-8), as hex. Synchronous. */
export function md5Hex(text) {
  const msg = new TextEncoder().encode(text ?? "");
  const bitLen = msg.length * 8;
  const padded = new Uint8Array((((msg.length + 8) >> 6) + 1) * 64);
  padded.set(msg);
  padded[msg.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLen >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bitLen / 2 ** 32), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  for (let off = 0; off < padded.length; off += 64) {
    const M = Array.from({ length: 16 }, (_, i) => view.getUint32(off + i * 4, true));
    let [a, b, c, d] = [a0, b0, c0, d0];
    for (let i = 0; i < 64; i++) {
      let f;
      let g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      const sum = (a + f + MD5_K[i] + M[g]) >>> 0;
      a = d;
      d = c;
      c = b;
      b = (b + ((sum << MD5_S[i]) | (sum >>> (32 - MD5_S[i])))) >>> 0;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }
  const out = new DataView(new ArrayBuffer(16));
  [a0, b0, c0, d0].forEach((w, i) => out.setUint32(i * 4, w, true));
  return toHex(new Uint8Array(out.buffer));
}

// --- CRC-32 (IEEE 802.3, as used by zip/gzip/PNG) ---
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

/** CRC-32 of `text` (UTF-8), as 8 hex digits. Synchronous. */
export function crc32Hex(text) {
  let crc = 0xffffffff;
  for (const byte of new TextEncoder().encode(text ?? "")) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
}
