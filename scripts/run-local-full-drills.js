import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  buildLocalFullDrillReceipt,
  localFullDrillSourceBindings,
  serializeLocalFullDrillReceipt
} from "../src/local-full-drill.js";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

export function runLocalFullDrills() {
  return buildLocalFullDrillReceipt({
    sourceBindings: localFullDrillSourceBindings(ROOT)
  });
}

function main() {
  if (process.argv.length !== 2) {
    throw new Error("LOCAL_FULL_DRILL_ARGUMENTS_REJECTED");
  }
  process.stdout.write(serializeLocalFullDrillReceipt(runLocalFullDrills()));
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
