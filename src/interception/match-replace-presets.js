// One-click starting points for Match & Replace, covering the rewrites
// testers reach for most. Presets are added DISABLED — nothing changes on
// the wire until the tester has looked at the rule and switched it on.
export const MATCH_REPLACE_PRESETS = [
  {
    id: "xff-localhost",
    label: "Spoof client IP (X-Forwarded-For: 127.0.0.1)",
    rule: { name: "Spoof client IP as localhost", engine: "static", scope: "request", location: "header", headerName: "X-Forwarded-For", staticAction: "set", staticValue: "127.0.0.1" },
  },
  {
    id: "origin-evil",
    label: "Send a cross-site Origin (CORS test)",
    rule: { name: "Cross-site Origin", engine: "static", scope: "request", location: "header", headerName: "Origin", staticAction: "set", staticValue: "https://evil.example" },
  },
  {
    id: "remove-csp",
    label: "Remove Content-Security-Policy (test without CSP)",
    rule: { name: "Strip CSP from responses", engine: "static", scope: "response", location: "header", headerName: "Content-Security-Policy", staticAction: "remove" },
  },
  {
    id: "remove-xfo",
    label: "Remove X-Frame-Options (allow framing)",
    rule: { name: "Strip X-Frame-Options", engine: "static", scope: "response", location: "header", headerName: "X-Frame-Options", staticAction: "remove" },
  },
  {
    id: "no-conditional",
    label: "Disable caching (remove If-None-Match)",
    rule: { name: "Always fetch fresh responses", engine: "static", scope: "request", location: "header", headerName: "If-None-Match", staticAction: "remove" },
  },
  {
    id: "mobile-ua",
    label: "Pretend to be a mobile browser",
    rule: {
      name: "Mobile User-Agent",
      engine: "static",
      scope: "request",
      location: "header",
      headerName: "User-Agent",
      staticAction: "set",
      staticValue: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    },
  },
  {
    id: "unhide-fields",
    label: "Reveal hidden form fields",
    rule: { name: "Show hidden inputs", engine: "content", scope: "response", location: "body", matchType: "regex", match: "type=([\"']?)hidden\\1", replace: "type=$1text$1" },
  },
  {
    id: "enable-controls",
    label: "Enable disabled form controls",
    rule: { name: "Remove disabled attributes", engine: "content", scope: "response", location: "body", matchType: "regex", match: "\\sdisabled(=([\"'])[^\"']*\\2)?(?=[\\s/>])", replace: "" },
  },
  {
    id: "admin-flag",
    label: "Flip an isAdmin:false flag to true",
    rule: { name: "isAdmin → true", engine: "content", scope: "response", location: "body", matchType: "regex", match: "(\"isAdmin\"\\s*:\\s*)false", replace: "$1true" },
  },
  {
    id: "strip-httponly",
    label: "Drop HttpOnly from Set-Cookie (test script access)",
    rule: { name: "Strip HttpOnly", engine: "content", scope: "response", location: "header", headerName: "Set-Cookie", matchType: "regex", match: ";\\s*HttpOnly", replace: "" },
  },
];
