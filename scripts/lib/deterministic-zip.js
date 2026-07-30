import fs from "node:fs";

const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const ZIP_VERSION = 20;
const UNIX_ZIP_VERSION = (3 << 8) | ZIP_VERSION;
const FIXED_DOS_DATE = ((2026 - 1980) << 9) | (7 << 5) | 30;
const FIXED_DOS_TIME = 0;
const STORED = 0;
const REGULAR_FILE_0644 = (0o100644 * 65_536) >>> 0;

const CRC32_TABLE = Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit += 1) {
    crc = (crc & 1) === 1
      ? 0xedb88320 ^ (crc >>> 1)
      : crc >>> 1;
  }
  return crc >>> 0;
});

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function assertArchiveInput(fileName, content) {
  if (
    typeof fileName !== "string" ||
    fileName.length === 0 ||
    fileName.length > 255 ||
    fileName.includes("/") ||
    fileName.includes("\\") ||
    Buffer.byteLength(fileName, "utf8") !== fileName.length ||
    !Buffer.isBuffer(content) ||
    content.length === 0 ||
    content.length > 0xffffffff
  ) {
    throw new Error("DETERMINISTIC_ZIP_INPUT_REJECTED");
  }
}

export function singleFileZip(fileName, content) {
  assertArchiveInput(fileName, content);
  const name = Buffer.from(fileName, "utf8");
  const checksum = crc32(content);

  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(LOCAL_FILE_HEADER_SIGNATURE, 0);
  localHeader.writeUInt16LE(ZIP_VERSION, 4);
  localHeader.writeUInt16LE(0, 6);
  localHeader.writeUInt16LE(STORED, 8);
  localHeader.writeUInt16LE(FIXED_DOS_TIME, 10);
  localHeader.writeUInt16LE(FIXED_DOS_DATE, 12);
  localHeader.writeUInt32LE(checksum, 14);
  localHeader.writeUInt32LE(content.length, 18);
  localHeader.writeUInt32LE(content.length, 22);
  localHeader.writeUInt16LE(name.length, 26);
  localHeader.writeUInt16LE(0, 28);

  const localRecord = Buffer.concat([localHeader, name, content]);
  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(CENTRAL_DIRECTORY_SIGNATURE, 0);
  centralHeader.writeUInt16LE(UNIX_ZIP_VERSION, 4);
  centralHeader.writeUInt16LE(ZIP_VERSION, 6);
  centralHeader.writeUInt16LE(0, 8);
  centralHeader.writeUInt16LE(STORED, 10);
  centralHeader.writeUInt16LE(FIXED_DOS_TIME, 12);
  centralHeader.writeUInt16LE(FIXED_DOS_DATE, 14);
  centralHeader.writeUInt32LE(checksum, 16);
  centralHeader.writeUInt32LE(content.length, 20);
  centralHeader.writeUInt32LE(content.length, 24);
  centralHeader.writeUInt16LE(name.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(REGULAR_FILE_0644, 38);
  centralHeader.writeUInt32LE(0, 42);
  const centralRecord = Buffer.concat([centralHeader, name]);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(END_OF_CENTRAL_DIRECTORY_SIGNATURE, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralRecord.length, 12);
  end.writeUInt32LE(localRecord.length, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([localRecord, centralRecord, end]);
}

export function writeSingleFileZip(destination, fileName, content) {
  const archive = singleFileZip(fileName, content);
  fs.writeFileSync(destination, archive, { mode: 0o644 });
  return archive;
}

export const __test = {
  crc32,
  FIXED_DOS_DATE,
  FIXED_DOS_TIME
};
