import assert from "node:assert/strict";
import test from "node:test";
import {
  deterministicZip,
  singleFileZip,
} from "../scripts/lib/deterministic-zip.js";

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

test("multi-file ZIP is sorted, stored, and deterministic", () => {
  const entries = [
    {
      fileName: "THIRD_PARTY_NOTICES.txt",
      content: Buffer.from("notices\n"),
    },
    {
      fileName: "index.js",
      content: Buffer.from("module.exports = 7;\n"),
    },
  ];
  const first = deterministicZip(entries);
  const second = deterministicZip(entries);
  assert.deepEqual(first, second);

  const endOffset = first.length - 22;
  const centralOffset = first.readUInt32LE(endOffset + 16);
  assert.equal(first.readUInt16LE(endOffset + 8), 2);
  assert.equal(first.readUInt16LE(endOffset + 10), 2);

  const names = [];
  let offset = 0;
  while (offset < centralOffset) {
    assert.equal(first.readUInt32LE(offset), 0x04034b50);
    assert.equal(first.readUInt16LE(offset + 8), 0);
    const contentBytes = first.readUInt32LE(offset + 18);
    const nameBytes = first.readUInt16LE(offset + 26);
    const extraBytes = first.readUInt16LE(offset + 28);
    names.push(
      first.subarray(offset + 30, offset + 30 + nameBytes).toString("utf8")
    );
    offset += 30 + nameBytes + extraBytes + contentBytes;
  }
  assert.deepEqual(names, ["THIRD_PARTY_NOTICES.txt", "index.js"]);
});

test("multi-file ZIP rejects duplicate or unsorted entries", () => {
  const content = Buffer.from("x");
  assert.throws(
    () =>
      deterministicZip([
        { fileName: "index.js", content },
        { fileName: "THIRD_PARTY_NOTICES.txt", content },
      ]),
    /DETERMINISTIC_ZIP_INPUT_REJECTED/
  );
  assert.throws(
    () =>
      deterministicZip([
        { fileName: "index.js", content },
        { fileName: "index.js", content },
      ]),
    /DETERMINISTIC_ZIP_INPUT_REJECTED/
  );
});
