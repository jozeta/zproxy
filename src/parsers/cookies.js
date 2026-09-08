// Parsing for the `Cookie` request header and `Set-Cookie` response header.
// This is text parsing only — actual cookie storage CRUD goes through
// chrome.cookies (see src/background and the Cookies UI panel).

export function parseCookieHeader(value) {
  if (!value) return [];
  return value
    .split(";")
    .map((pair) => {
      const idx = pair.indexOf("=");
      if (idx === -1) return { name: pair.trim(), value: "" };
      return { name: pair.slice(0, idx).trim(), value: pair.slice(idx + 1).trim() };
    })
    .filter((c) => c.name.length > 0);
}

export function serializeCookieHeader(cookies) {
  return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}

const KNOWN_ATTRS = new Set(["expires", "max-age", "domain", "path", "secure", "httponly", "samesite"]);

export function parseSetCookie(value) {
  const parts = value
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return null;
  const [nameValue, ...attrParts] = parts;
  const idx = nameValue.indexOf("=");
  if (idx === -1) return null;

  const cookie = {
    name: nameValue.slice(0, idx).trim(),
    value: nameValue.slice(idx + 1).trim(),
    domain: null,
    path: null,
    expires: null,
    maxAge: null,
    secure: false,
    httpOnly: false,
    sameSite: null,
  };

  for (const attr of attrParts) {
    const eqIdx = attr.indexOf("=");
    const key = (eqIdx === -1 ? attr : attr.slice(0, eqIdx)).trim().toLowerCase();
    const val = eqIdx === -1 ? "" : attr.slice(eqIdx + 1).trim();
    if (!KNOWN_ATTRS.has(key)) continue;
    switch (key) {
      case "expires":
        cookie.expires = val;
        break;
      case "max-age":
        cookie.maxAge = Number(val);
        break;
      case "domain":
        cookie.domain = val;
        break;
      case "path":
        cookie.path = val;
        break;
      case "secure":
        cookie.secure = true;
        break;
      case "httponly":
        cookie.httpOnly = true;
        break;
      case "samesite":
        cookie.sameSite = val;
        break;
    }
  }
  return cookie;
}

/** A response can carry multiple Set-Cookie headers with the same name. */
export function parseAllSetCookies(headerList) {
  return headerList
    .filter((h) => h.name.toLowerCase() === "set-cookie")
    .map((h) => parseSetCookie(h.value))
    .filter(Boolean);
}
