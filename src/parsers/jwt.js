// Decodes JWTs for inspection only. NEVER validates signatures, NEVER trusts
// decoded claims as authenticated — see docs/SECURITY.md "A2".

function base64UrlToUtf8(segment) {
  const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function isJwtLike(value) {
  if (typeof value !== "string") return false;
  const parts = value.trim().split(".");
  return parts.length === 3 && parts.every((p) => p.length > 0 && /^[A-Za-z0-9_-]+$/.test(p));
}

export function decodeJwt(token) {
  const parts = String(token).trim().split(".");
  if (parts.length !== 3) {
    return { ok: false, error: "Not a 3-part JWT (expected header.payload.signature)." };
  }
  const [headerB64, payloadB64, signature] = parts;
  try {
    const header = JSON.parse(base64UrlToUtf8(headerB64));
    const payload = JSON.parse(base64UrlToUtf8(payloadB64));
    return {
      ok: true,
      header,
      payload,
      signature,
      signatureVerified: false,
      warning: "Signature was NOT verified. Decoding a JWT proves nothing about its authenticity.",
    };
  } catch (err) {
    return { ok: false, error: `Failed to decode JWT segments: ${err.message}` };
  }
}

export function extractBearerToken(authorizationHeaderValue) {
  if (!authorizationHeaderValue) return null;
  const match = authorizationHeaderValue.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

/** Scans a header list for an Authorization: Bearer JWT, returning it decoded or null. */
export function findJwtInHeaders(headerList) {
  const authHeader = headerList.find((h) => h.name.toLowerCase() === "authorization");
  if (!authHeader) return null;
  const token = extractBearerToken(authHeader.value);
  if (!token || !isJwtLike(token)) return null;
  return decodeJwt(token);
}
