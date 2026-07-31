import fs from "node:fs";
import path from "node:path";

export function rawTextPlugin() {
  return {
    name: "tideproof-raw-text",
    setup(build) {
      build.onResolve({ filter: /\?raw$/ }, (args) => ({
        path: path.resolve(args.resolveDir, args.path.slice(0, -4)),
        namespace: "tideproof-raw-text"
      }));
      build.onLoad(
        { filter: /.*/, namespace: "tideproof-raw-text" },
        (args) => ({
          contents: fs.readFileSync(args.path, "utf8"),
          loader: "text",
          resolveDir: path.dirname(args.path)
        })
      );
    }
  };
}
