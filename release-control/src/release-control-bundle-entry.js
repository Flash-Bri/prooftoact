// Exact exports for the content-addressed production runtime.
export { attestReleaseControlTable } from
  "../../scripts/lib/release-control-table-identity.js";
export { createReleaseControlAwsRuntime } from
  "./release-control-aws-runtime.js";
export { createReleaseControlDynamoDbStore } from
  "./release-control-dynamodb-store.js";
