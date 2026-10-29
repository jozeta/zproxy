// Vulnerable JavaScript library detection — the passive check Burp calls
// "Vulnerable JavaScript dependency" and Retire.js exists for. Finds a
// library's version in a captured script body (its license banner or
// version constant) or in its URL (jquery-3.4.1.min.js, CDN paths like
// /npm/lodash@4.17.15/ or /libs/moment.js/2.29.1/), then matches it
// against known-vulnerable ranges.
//
// The ranges are a curated subset of the Retire.js repository
// (github.com/RetireJS/retire.js, repository/jsrepository-v4.json, read
// 2026-10-29): the most widely deployed libraries and their most
// significant advisories, not every entry. A version below every listed
// range is still flagged when the library is end-of-life. Update by
// re-reading that file; ranges are [atOrAbove, below).

/** Compares dotted versions with optional pre-release tags ("1.2.3", "3.0.0-rc.1", "1.0.0.beta.3"). */
export function compareVersions(a, b) {
  const parse = (v) => {
    const [main, ...pre] = String(v).toLowerCase().split(/[-+]/);
    const parts = main.split(".");
    const nums = [];
    let tail = pre.join("-");
    for (const p of parts) {
      if (/^\d+$/.test(p)) nums.push(Number(p));
      else {
        tail = [p, ...parts.slice(parts.indexOf(p) + 1)].join(".") + (tail ? `-${tail}` : "");
        break;
      }
    }
    return { nums, pre: tail };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1; // a release sorts after its own pre-releases
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

const V = "(\\d+\\.\\d+(?:\\.\\d+)?(?:-[0-9A-Za-z]+(?:\\.[0-9A-Za-z]+)*)?)"; // version capture used in every pattern

// severity: Retire's "critical" is folded into "high" (ZProxy's top level).
const LIBRARIES = [
  {
    id: "jquery",
    name: "jQuery",
    content: [`/\\*!? jQuery v${V}`, `\\* jQuery JavaScript Library v${V}`, `[^a-z.]jquery:[ ]?"${V}"`],
    file: [`jquery-${V}(?:\\.min)?\\.js`, `/jquery@${V}/`, `/jquery/${V}/jquery(?:\\.min)?\\.js`],
    vulns: [
      { below: "1.9.0", severity: "medium", ids: ["CVE-2012-6708"], summary: "selector string interpreted as HTML" },
      { atOrAbove: "1.4.0", below: "3.0.0", severity: "medium", ids: ["CVE-2015-9251"], summary: "cross-origin AJAX responses executed" },
      { atOrAbove: "1.1.4", below: "3.4.0", severity: "medium", ids: ["CVE-2019-11358"], summary: "prototype pollution via extend()" },
      { atOrAbove: "1.0.3", below: "3.5.0", severity: "medium", ids: ["CVE-2020-11022", "CVE-2020-11023"], summary: "XSS via htmlPrefilter / <option> HTML" },
    ],
    eol: { below: "3.0.0", note: "jQuery 1.x and 2.x are end-of-life" },
  },
  {
    id: "jquery-ui",
    name: "jQuery UI",
    content: [`/\\*!? jQuery UI - v${V}`, `/\\*!?[\\n *]+jQuery UI ${V}`],
    file: [`/jquery-ui@${V}/`, `/jqueryui/${V}/`],
    vulns: [
      { below: "1.13.0", severity: "medium", ids: ["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"], summary: "XSS in Datepicker and position()" },
      { below: "1.13.2", severity: "medium", ids: ["CVE-2022-31160"], summary: "XSS in checkboxradio labels" },
    ],
  },
  {
    id: "angularjs",
    name: "AngularJS",
    content: [`/\\*[*\\s]+(?:@license )?AngularJS v${V}`, `errors\\.angularjs\\.org/${V}/`],
    file: [`/angular(?:js)?@${V}/`, `/angular\\.js/${V}/`],
    vulns: [
      { below: "1.7.9", severity: "high", ids: ["CVE-2019-10768"], summary: "prototype pollution" },
      { below: "1.8.0", severity: "medium", ids: ["CVE-2020-7676"], summary: "XSS via JQLite DOM insertion" },
      { atOrAbove: "1.3.0", below: "1.8.4", severity: "high", ids: ["CVE-2024-21490"], summary: "super-linear backtracking (ReDoS)" },
    ],
    eol: { below: "2.0.0", note: "AngularJS (1.x) reached end-of-life in January 2022 and gets no more security fixes" },
  },
  {
    id: "bootstrap",
    name: "Bootstrap",
    content: [`/\\*!? Bootstrap v${V}`, `\\* Bootstrap v${V}`],
    file: [`/bootstrap@${V}/`, `/twitter-bootstrap/${V}/`, `/bootstrap/${V}/`],
    vulns: [
      { atOrAbove: "3.0.0", below: "3.4.1", severity: "medium", ids: ["CVE-2019-8331", "CVE-2018-14042"], summary: "XSS via tooltip/popover data attributes" },
      { atOrAbove: "4.0.0", below: "4.3.1", severity: "medium", ids: ["CVE-2019-8331"], summary: "XSS via tooltip/popover data attributes" },
      { atOrAbove: "1.4.0", below: "3.4.2", severity: "medium", ids: ["CVE-2024-6485"], summary: "XSS via data-* attributes" },
    ],
    eol: { below: "4.0.0", note: "Bootstrap 3 and earlier are end-of-life" },
  },
  {
    id: "lodash",
    name: "Lodash",
    content: [`@license\\s+(?:lodash|Lodash) ${V}`, `lodash\\.com[\\s\\S]{0,1500}?VERSION\\s*=\\s*['"]${V}['"]`],
    file: [`/lodash@${V}/`, `/lodash\\.js/${V}/`],
    vulns: [
      { below: "4.17.12", severity: "high", ids: ["CVE-2019-10744"], summary: "prototype pollution via defaultsDeep" },
      { below: "4.17.19", severity: "high", ids: ["CVE-2020-8203"], summary: "prototype pollution via zipObjectDeep" },
      { below: "4.17.21", severity: "high", ids: ["CVE-2021-23337"], summary: "command injection via template()" },
    ],
  },
  {
    id: "underscore",
    name: "Underscore.js",
    content: [`//[\\s]*Underscore\\.js ${V}`],
    file: [`/underscore@${V}/`, `/underscore\\.js/${V}/`],
    vulns: [{ atOrAbove: "1.3.2", below: "1.12.1", severity: "high", ids: ["CVE-2021-23358"], summary: "code injection via template()" }],
  },
  {
    id: "moment",
    name: "Moment.js",
    content: [`//!? moment\\.js(?:[\\n\\r]+)//!? version : ${V}`, `/\\* Moment\\.js +\\| +version : ${V}`],
    file: [`/moment@${V}/`, `/moment\\.js/${V}/`],
    vulns: [
      { below: "2.19.3", severity: "high", ids: ["CVE-2017-18214"], summary: "ReDoS" },
      { below: "2.29.2", severity: "high", ids: ["CVE-2022-24785"], summary: "path traversal via locale" },
      { atOrAbove: "2.18.0", below: "2.29.4", severity: "high", ids: ["CVE-2022-31129"], summary: "ReDoS in RFC 2822 parsing" },
    ],
  },
  {
    id: "handlebars",
    name: "Handlebars",
    content: [`Handlebars\\.VERSION = "${V}"`, `/\\*+![\\s]+(?:@license)?[\\s]+handlebars v+${V}`],
    file: [`/handlebars@${V}/`, `/handlebars\\.js/${V}/`],
    vulns: [
      { below: "4.5.3", severity: "high", ids: ["CVE-2019-20920", "CVE-2019-19919"], summary: "code execution via lookup helper" },
      { below: "4.7.7", severity: "high", ids: ["CVE-2021-23369", "CVE-2021-23383"], summary: "remote code execution when compiling templates" },
    ],
  },
  {
    id: "dompurify",
    name: "DOMPurify",
    content: [`DOMPurify\\.version ?= ?['"]${V}['"]`, `/\\*! @license DOMPurify ${V}`],
    file: [`/dompurify@${V}/`, `/dompurify/${V}/`],
    vulns: [
      { below: "2.0.17", severity: "medium", ids: ["CVE-2020-26870"], summary: "mutation XSS via MathML" },
      { below: "2.5.4", severity: "high", ids: ["CVE-2024-45801", "CVE-2024-47875"], summary: "prototype pollution and nesting-based mXSS" },
      { atOrAbove: "3.0.0", below: "3.1.3", severity: "high", ids: ["CVE-2024-45801", "CVE-2024-47875"], summary: "prototype pollution and nesting-based mXSS" },
      { below: "3.2.4", severity: "medium", ids: ["CVE-2025-26791"], summary: "XSS (template literal handling)" },
    ],
  },
  {
    id: "vue",
    name: "Vue.js",
    content: [`/\\*!\\n \\* Vue\\.js v${V}`, `Vue\\.version = '${V}'`],
    file: [`/vue@${V}/`, `/vue/${V}/`],
    vulns: [
      { below: "2.5.17", severity: "medium", ids: ["retire:vue-11"], summary: "SSR XSS via v-bind" },
      { atOrAbove: "2.0.0", below: "3.0.0", severity: "low", ids: ["CVE-2024-9506"], summary: "ReDoS in parseHTML" },
    ],
    eol: { atOrAbove: "2.0.0", below: "3.0.0", note: "Vue 2 reached end-of-life on 31 December 2023" },
  },
  {
    id: "react",
    name: "React",
    content: [`/\\*\\* @license React v${V}`, `/\\*\\*\\n +\\* React v${V}`],
    file: [`/react(?:-dom)?@${V}/`],
    vulns: [
      { below: "0.14.0", severity: "high", ids: ["GHSA-hg79-j56m-fxgv"], summary: "untrusted objects rendered as children" },
      { atOrAbove: "16.0.0", below: "16.4.2", severity: "medium", ids: ["CVE-2018-6341"], summary: "XSS via attribute names (SSR)" },
    ],
  },
  {
    id: "axios",
    name: "axios",
    content: [`axios v${V}`, `VERSION\\s*=\\s*["']${V}["'][\\s\\S]{0,300}?axios`],
    file: [`/axios@${V}/`, `/axios/${V}/`],
    vulns: [
      { below: "0.21.1", severity: "medium", ids: ["CVE-2020-28168"], summary: "SSRF via redirects" },
      { atOrAbove: "0.8.1", below: "0.28.0", severity: "medium", ids: ["CVE-2023-45857"], summary: "XSRF-TOKEN leaked to third-party hosts" },
      { below: "0.30.0", severity: "high", ids: ["CVE-2025-27152"], summary: "SSRF and credential leak via absolute URLs" },
    ],
  },
  {
    id: "knockout",
    name: "Knockout",
    content: [`(?:\\*|//) Knockout JavaScript library v${V}`],
    file: [`knockout-${V}(?:\\.min)?\\.js`],
    vulns: [{ below: "3.5.0", severity: "medium", ids: ["CVE-2019-14862"], summary: "XSS via attr name binding" }],
  },
  {
    id: "mustache",
    name: "mustache.js",
    content: [`name:\\s*['"]mustache\\.js['"],\\s*version:\\s*['"]${V}['"]`],
    file: [`/mustache@${V}/`],
    vulns: [{ below: "2.2.1", severity: "high", ids: ["CVE-2015-8862"], summary: "weak HTML escaping" }],
  },
  {
    id: "backbone",
    name: "Backbone.js",
    content: [`//[ ]+Backbone\\.js ${V}`, `Backbone\\.VERSION *= *["']${V}["']`],
    file: [`/backbone@${V}/`],
    vulns: [{ atOrAbove: "0.3.3", below: "0.5.0", severity: "medium", ids: ["CVE-2016-10537"], summary: "XSS" }],
  },
  {
    id: "prototypejs",
    name: "Prototype",
    content: [`Prototype JavaScript framework, version ${V}`],
    file: [`prototype-${V}(?:\\.min)?\\.js`],
    vulns: [{ below: "1.7.4", severity: "high", ids: ["CVE-2020-27511"], summary: "ReDoS in stripTags/unescapeHTML" }],
  },
  {
    id: "dojo",
    name: "Dojo",
    content: [],
    file: [`dojo-${V}(?:\\.min)?\\.js`, `/dojo/${V}/`],
    vulns: [{ below: "1.16.5", severity: "high", ids: ["CVE-2021-23450", "CVE-2020-5258"], summary: "prototype pollution" }],
  },
  {
    id: "ckeditor",
    name: "CKEditor 4",
    content: [`window\\.CKEDITOR=function\\(\\)\\{var [a-z]=\\{timestamp:"[^"]+",version:"${V}`],
    file: [`/ckeditor/${V}/`, `/ckeditor@${V}/`],
    vulns: [
      { below: "4.17.0", severity: "medium", ids: ["CVE-2021-41164", "CVE-2021-41165"], summary: "XSS in core" },
      { below: "4.21.0", severity: "medium", ids: ["CVE-2023-28439"], summary: "XSS in Iframe/Media Embed" },
    ],
    eol: { below: "5.0.0", note: "CKEditor 4's free version reached end-of-life in June 2023" },
  },
  {
    id: "tinymce",
    name: "TinyMCE",
    content: [`/\\*\\*[\\s]*\\* TinyMCE version ${V}`],
    file: [`/tinymce/${V}/tinymce(?:\\.min)?\\.js`, `/tinymce@${V}/`],
    vulns: [
      { below: "5.10.9", severity: "medium", ids: ["CVE-2023-48219", "CVE-2023-45818"], summary: "mutation XSS" },
      { atOrAbove: "6.0.0", below: "6.7.3", severity: "medium", ids: ["CVE-2023-48219", "CVE-2023-45818"], summary: "mutation XSS" },
    ],
  },
  {
    id: "plupload",
    name: "Plupload",
    content: [`\\* Plupload - multi-runtime File Uploader(?:\\r|\\n)+ \\* v${V}`],
    file: [`/plupload/${V}/`],
    vulns: [{ below: "2.3.9", severity: "medium", ids: ["CVE-2021-23562"], summary: "XSS via file names" }],
  },
  {
    id: "jquery-prettyphoto",
    name: "prettyPhoto",
    content: [`\\.prettyPhoto[ ]?=[ ]?\\{version:[ ]?(?:'|")${V}(?:'|")`],
    file: [],
    vulns: [{ below: "3.1.6", severity: "high", ids: ["CVE-2013-6837"], summary: "DOM XSS" }],
  },
];

const COMPILED = LIBRARIES.map((lib) => ({
  ...lib,
  contentRes: lib.content.map((s) => new RegExp(s, "i")),
  fileRes: lib.file.map((s) => new RegExp(s, "i")),
}));

/** [{id, name, version, source}] found in a script/HTML body and/or its URL — at most one per library. */
export function detectLibraries(body, url) {
  const found = new Map();
  const text = typeof body === "string" ? body.slice(0, 400_000) : "";
  let path = "";
  try {
    path = decodeURIComponent(new URL(url).pathname);
  } catch {
    path = url || "";
  }
  for (const lib of COMPILED) {
    for (const re of lib.fileRes) {
      const m = path.match(re);
      if (m) {
        found.set(lib.id, { id: lib.id, name: lib.name, version: m[1], source: "url" });
        break;
      }
    }
    if (found.has(lib.id) || !text) continue;
    for (const re of lib.contentRes) {
      const m = text.match(re);
      if (m) {
        found.set(lib.id, { id: lib.id, name: lib.name, version: m[1], source: "content" });
        break;
      }
    }
  }
  return [...found.values()];
}

function inRange(version, { atOrAbove, below }) {
  return (!atOrAbove || compareVersions(version, atOrAbove) >= 0) && (!below || compareVersions(version, below) < 0);
}

/** {severity, advisories, fixedIn, eol} for a detected library version, or null if nothing known applies. */
export function assessLibrary(id, version) {
  const lib = LIBRARIES.find((l) => l.id === id);
  if (!lib) return null;
  const advisories = lib.vulns.filter((v) => inRange(version, v));
  const eol = lib.eol && inRange(version, lib.eol) ? lib.eol.note : null;
  if (advisories.length === 0 && !eol) return null;
  const rank = { low: 1, medium: 2, high: 3 };
  const severity = advisories.reduce((s, a) => (rank[a.severity] > rank[s] ? a.severity : s), "low");
  const fixedIn = advisories.reduce((max, a) => (!max || compareVersions(a.below, max) > 0 ? a.below : max), null);
  return { severity, advisories, fixedIn, eol };
}

export const KNOWN_LIBRARY_COUNT = LIBRARIES.length;
