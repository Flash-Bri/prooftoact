import fs from "node:fs";
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

function main(args = process.argv.slice(2)) {
  if (
    !(
      args.length === 0 ||
      (args.length === 2 &&
        args[0] === "--output" &&
        args[1] === "evidence/local-full-drill-100-2026-08-04.json")
    )
  ) {
    throw new Error("LOCAL_FULL_DRILL_ARGUMENTS_REJECTED");
  }
  const serialized = serializeLocalFullDrillReceipt(runLocalFullDrills());
  if (args.length === 0) {
    process.stdout.write(serialized);
    return;
  }
  fs.writeFileSync(path.join(ROOT, args[1]), serialized, {
    encoding: "utf8",
    flag: "w",
    mode: 0o644
  });
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
