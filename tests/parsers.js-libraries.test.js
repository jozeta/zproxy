import { test } from "node:test";
import assert from "node:assert/strict";
import { compareVersions, detectLibraries, assessLibrary } from "../src/parsers/js-libraries.js";

test("compareVersions orders releases, missing parts, and pre-releases", () => {
  assert.equal(compareVersions("1.12.4", "3.0.0"), -1);
  assert.equal(compareVersions("3.5.0", "3.5"), 0);
  assert.equal(compareVersions("4.17.21", "4.17.3"), 1);
  assert.equal(compareVersions("3.0.0-rc.1", "3.0.0"), -1);
  assert.equal(compareVersions("1.0.0.beta.3", "1.0.0"), -1);
  assert.equal(compareVersions("2.0.0", "2.0.0-beta"), 1);
});

test("detects libraries from their real license banners", () => {
  const found = (body) => detectLibraries(body, "https://app.test/static/vendor.js").map((l) => `${l.id}@${l.version}`);
  assert.deepEqual(found("/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */"), ["jquery@1.12.4"]);
  assert.deepEqual(found("/*!\n  * Bootstrap v3.3.7 (http://getbootstrap.com)\n  */"), ["bootstrap@3.3.7"]);
  assert.deepEqual(found("/**\n * @license AngularJS v1.8.3\n * (c) 2010-2020 Google LLC."), ["angularjs@1.8.3"]);
  assert.deepEqual(found("/*! @license DOMPurify 2.3.1 | (c) Cure53 */"), ["dompurify@2.3.1"]);
  assert.deepEqual(found("//! moment.js\n//! version : 2.29.1\n//! authors"), ["moment@2.29.1"]);
  assert.deepEqual(found("console.log('no libraries here')"), []);
});

test("detects libraries from file names and CDN URLs", () => {
  const ids = (url) => detectLibraries("", url).map((l) => `${l.id}@${l.version}`);
  assert.deepEqual(ids("https://app.test/js/jquery-3.4.1.min.js"), ["jquery@3.4.1"]);
  assert.deepEqual(ids("https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"), ["lodash@4.17.15"]);
  assert.deepEqual(ids("https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js"), ["moment@2.18.1"]);
  assert.deepEqual(ids("https://unpkg.com/react-dom@16.4.1/umd/react-dom.production.min.js"), ["react@16.4.1"]);
});

test("assessLibrary reports matching advisories, the fix version, and end-of-life", () => {
  const jq = assessLibrary("jquery", "1.12.4");
  assert.equal(jq.severity, "medium");
  assert.ok(jq.advisories.some((a) => a.ids.includes("CVE-2015-9251")));
  assert.equal(jq.fixedIn, "3.5.0");
  assert.match(jq.eol, /end-of-life/);

  const lodash = assessLibrary("lodash", "4.17.15");
  assert.equal(lodash.severity, "high");
  assert.equal(lodash.fixedIn, "4.17.21");

  const angular = assessLibrary("angularjs", "1.8.3");
  assert.equal(angular.severity, "high"); // CVE-2024-21490 (>=1.3.0 <1.8.4)
  assert.ok(angular.eol);
});

test("current versions raise nothing", () => {
  assert.equal(assessLibrary("jquery", "3.7.1"), null);
  assert.equal(assessLibrary("lodash", "4.17.21"), null);
  assert.equal(assessLibrary("bootstrap", "5.3.3"), null);
  assert.equal(assessLibrary("nope", "1.0.0"), null);
});

test("ranges are half-open: the fixed version itself is clean", () => {
  assert.equal(assessLibrary("handlebars", "4.7.7"), null);
  assert.ok(assessLibrary("handlebars", "4.7.6"));
  assert.equal(assessLibrary("underscore", "1.3.1"), null); // below atOrAbove
});
