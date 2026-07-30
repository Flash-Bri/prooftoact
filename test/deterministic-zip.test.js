import assert from "node:assert/strict";
import test from "node:test";
import { singleFileZip } from "../scripts/lib/deterministic-zip.js";

test("single-file ZIP output is byte-identical across host timezones", () => {
  const originalTimezone = process.env.TZ;
  const payload = Buffer.from(
    '"use strict";\nexports.handler = async () => ({ ok: true });\n',
    "utf8"
  );
  const archives = [];
  try {
    for (const timezone of [
      "UTC",
      "America/New_York",
      "America/Los_Angeles"
    ]) {
      process.env.TZ = timezone;
      archives.push(singleFileZip("index.js", payload));
    }
  } finally {
    if (originalTimezone === undefined) {
      delete process.env.TZ;
    } else {
      process.env.TZ = originalTimezone;
    }
  }

  assert.deepEqual(archives[0], archives[1]);
  assert.deepEqual(archives[0], archives[2]);
});

test("single-file ZIP contains one stored index.js entry", () => {
  const payload = Buffer.from("module.exports = 7;\n", "utf8");
  const archive = singleFileZip("index.js", payload);
  const nameLength = archive.readUInt16LE(26);
  const extraLength = archive.readUInt16LE(28);
  const contentOffset = 30 + nameLength + extraLength;
  const centralOffset = contentOffset + payload.length;

  assert.equal(archive.readUInt32LE(0), 0x04034b50);
  assert.equal(archive.readUInt16LE(8), 0);
  assert.equal(archive.readUInt32LE(18), payload.length);
  assert.equal(
    archive.subarray(30, 30 + nameLength).toString("utf8"),
    "index.js"
  );
  assert.deepEqual(
    archive.subarray(contentOffset, centralOffset),
    payload
  );
  assert.equal(archive.readUInt32LE(centralOffset), 0x02014b50);
  assert.equal(
    archive.readUInt32LE(archive.length - 22),
    0x06054b50
  );
  assert.equal(archive.readUInt16LE(archive.length - 14), 1);
  assert.equal(archive.readUInt16LE(archive.length - 12), 1);
});

test("single-file ZIP rejects unsafe or ambiguous inputs", () => {
  assert.throws(
    () => singleFileZip("../index.js", Buffer.from("x")),
    /DETERMINISTIC_ZIP_INPUT_REJECTED/
  );
  assert.throws(
    () => singleFileZip("index.js", Buffer.alloc(0)),
    /DETERMINISTIC_ZIP_INPUT_REJECTED/
  );
});
