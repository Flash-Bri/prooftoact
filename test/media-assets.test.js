import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const SVG_PATH = new URL("../docs/media/architecture.svg", import.meta.url);
const PNG_PATH = new URL("../docs/media/architecture.png", import.meta.url);
const README_PATH = new URL("../README.md", import.meta.url);
const RIGHTS_PATH = new URL("../docs/media/RIGHTS.md", import.meta.url);
const WEB_PATH = new URL("../web/index.html", import.meta.url);

const SVG_SHA256 =
  "5e897dbfd926486203362cf517c967e44d799edbf7f56d1d01b16307ec02724c";
const PNG_SHA256 =
  "6228172f7a5a462940a05543ee455e0de21aa53c805e9466076b9e33fed1f168";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("standalone architecture SVG is accessible and self-contained", () => {
  const source = readFileSync(SVG_PATH, "utf8");

  assert.equal(sha256(source), SVG_SHA256);
  assert.match(source, /width="2200"/);
  assert.match(source, /height="720"/);
  assert.match(source, /viewBox="0 0 1100 360"/);
  assert.match(source, /role="img"/);
  assert.match(source, /aria-labelledby="title description"/);
  assert.match(
    source,
    /<title id="title">Tideproof evidence, proposal, authority, and recovery boundaries<\/title>/
  );
  assert.match(
    source,
    /<desc id="description">[\s\S]*Untrusted evidence passes through CockroachDB/
  );
  assert.doesNotMatch(
    source,
    /<(?:script|image|foreignObject)\b|(?:href|xlink:href)=|@import|url\(\s*["']?https?:/i
  );
});

test("architecture PNG is the exact reviewed 2200 by 720 export", () => {
  const image = readFileSync(PNG_PATH);

  assert.equal(sha256(image), PNG_SHA256);
  assert.deepEqual(
    image.subarray(0, 8),
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
  );
  assert.equal(image.subarray(12, 16).toString("ascii"), "IHDR");
  assert.equal(image.readUInt32BE(16), 2200);
  assert.equal(image.readUInt32BE(20), 720);
});

test("public surfaces and rights ledger bind the reviewed architecture assets", () => {
  const readme = readFileSync(README_PATH, "utf8");
  const rights = readFileSync(RIGHTS_PATH, "utf8");
  const web = readFileSync(WEB_PATH, "utf8");

  assert.match(
    readme,
    /!\[Tideproof trust boundaries:[^\]]+\]\(docs\/media\/architecture\.svg\)/
  );
  assert.match(
    readme,
    /\[`docs\/ARCHITECTURE\.md`\]\(docs\/ARCHITECTURE\.md\)/
  );
  assert.match(web, /<img\s+[\s\S]*?src="\/architecture\.svg"/);
  assert.match(web, /width="2200"[\s\S]*?height="720"/);
  assert.doesNotMatch(web, /<svg\b/);
  assert.match(rights, /`C08 \/ V09`/);
  assert.match(rights, new RegExp(SVG_SHA256));
  assert.match(rights, new RegExp(PNG_SHA256));
  assert.match(
    rights,
    /`C08 \/ V09`[\s\S]*Nunan, 2026-07-31 — `CLEARED_CURRENT`/
  );
});
