export const OFFICIAL_NODE_RUNTIME_DISTRIBUTION =
  "nodejs.org-release-v22.23.1";

export const OFFICIAL_NODE_RUNTIME = Object.freeze({
  "darwin-arm64": Object.freeze({
    sha256: "2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d",
    version: "v22.23.1"
  }),
  "linux-x64": Object.freeze({
    sha256: "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068",
    version: "v22.23.1"
  })
});

export function expectedOfficialNodeRuntime(platform, architecture) {
  const expected = OFFICIAL_NODE_RUNTIME[`${platform}-${architecture}`];
  if (expected === undefined) {
    throw new Error("OFFICIAL_NODE_RUNTIME_METADATA_REJECTED");
  }
  return Object.freeze({
    architecture,
    distribution: OFFICIAL_NODE_RUNTIME_DISTRIBUTION,
    platform,
    sha256: expected.sha256,
    version: expected.version
  });
}

export function validateOfficialNodeRuntimeMetadata(value) {
  let expected;
  try {
    expected = expectedOfficialNodeRuntime(
      value?.platform,
      value?.architecture
    );
  } catch (cause) {
    throw new Error("OFFICIAL_NODE_RUNTIME_METADATA_REJECTED", { cause });
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join("\n") !==
      [
        "architecture",
        "distribution",
        "platform",
        "sha256",
        "version"
      ].sort().join("\n") ||
    Object.keys(expected).some((key) => value[key] !== expected[key])
  ) {
    throw new Error("OFFICIAL_NODE_RUNTIME_METADATA_REJECTED");
  }
  return Object.freeze({ ...value });
}
