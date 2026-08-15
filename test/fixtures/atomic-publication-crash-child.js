import fs from "node:fs";
import path from "node:path";
import { publishOrReadExactOwnedFile } from
  "../../src/cloud/atomic-create-only-file.js";

const rootPath = fs.realpathSync(process.env.PUBLICATION_ROOT);
const filePath = path.resolve(process.env.PUBLICATION_PATH);
const phase = process.env.PUBLICATION_FAULT_PHASE ?? "";

if (path.dirname(filePath) !== rootPath) {
  throw new Error("ATOMIC_PUBLICATION_FIXTURE_PATH_REJECTED");
}

const bytes = Buffer.from(
  '{"marker":"atomic-publication-crash-matrix-v1"}\n',
  "utf8"
);
const result = publishOrReadExactOwnedFile({
  bytes,
  code: "ATOMIC_PUBLICATION_FIXTURE_REJECTED",
  fault(observed) {
    if (observed === phase) process.exit(73);
  },
  filePath,
  rootPath
});

process.stdout.write(`${JSON.stringify({ created: result.created })}\n`);
