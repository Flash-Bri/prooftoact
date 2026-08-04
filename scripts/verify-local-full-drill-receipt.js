import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  localFullDrillSourceBindings,
  validateLocalFullDrillReceiptBytes
} from "../src/local-full-drill.js";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

function readReceipt(receiptPath) {
  const resolved = path.resolve(process.cwd(), receiptPath);
  const stat = fs.lstatSync(resolved);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.size <= 0 ||
    stat.size > 1024 * 1024
  ) {
    throw new Error("LOCAL_FULL_DRILL_RECEIPT_FILE_REJECTED");
  }
  return fs.readFileSync(resolved);
}

export function verifyLocalFullDrillReceiptFile(receiptPath) {
  return validateLocalFullDrillReceiptBytes(readReceipt(receiptPath), {
    sourceBindings: localFullDrillSourceBindings(ROOT)
  });
}

function main() {
  if (
    process.argv.length !== 3 ||
    typeof process.argv[2] !== "string" ||
    process.argv[2].length === 0
  ) {
    throw new Error("LOCAL_FULL_DRILL_ARGUMENTS_REJECTED");
  }
  process.stdout.write(
    `${JSON.stringify(verifyLocalFullDrillReceiptFile(process.argv[2]), null, 2)}\n`
  );
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    main();
  } catch (error) {
    process.stderr.write(
      `${/^LOCAL_FULL_DRILL_[A-Z0-9_]+$/.test(error?.message ?? "") ? error.message : "LOCAL_FULL_DRILL_UNKNOWN"}\n`
    );
    process.exitCode = 1;
  }
}
