import {
  ACCOUNT_ID,
  APP_SOURCE,
  ARTIFACT_NAMES,
  HEX_64,
  PARAMETER_KEYS,
  REGION,
  UUID,
  VERSION_ID,
  asBytes,
  base64Sha256,
  canonicalDigest,
  canonicalJson,
  exactKeys,
  plainObject,
  providerRequestId,
  requireCondition,
  responseBodyBytes,
  sha256
} from "./release-provider-common.js";
import { validatePrepareCommand } from "./release-provider-permit-reader.js";

const MAX_OBJECT_BYTES = 20 * 1024 * 1024;
const REQUEST_SCHEMA = "prooftoact.prepare-provider-request.v1";
const DISPATCH_SCHEMA = "prooftoact.prepare-provider-dispatch.v1";
const MINIMUM_MUTATION_REMAINING_MS = 30_000;
const REVIEWED_GATE2_TEMPLATE_SHA256 =
  "a10066b23925cf2921b15eaa0d52e7ac8ef7a5f46e0ab260431a340e897cc3a1";

function bucketName(value, code) {
  requireCondition(typeof value === "string" && value.length >= 3 &&
    value.length <= 63 &&
    /^(?!xn--)(?!.*\.\.)(?!\d{1,3}(?:\.\d{1,3}){3}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u
      .test(value), code);
  return value;
}

function checksumFromHex(value) {
  return Buffer.from(value, "hex").toString("base64");
}

function validateArtifact(value, bucket, code) {
  requireCondition(exactKeys(value, ["body", "descriptor"]) &&
    exactKeys(value.descriptor, [
      "bytes", "checksumSha256", "codeSha256", "contentType", "kind",
      "name", "s3Bucket", "s3Key", "sha256", "sourceSha256"
    ]), code);
  const descriptor = value.descriptor;
  requireCondition(ARTIFACT_NAMES.includes(descriptor.name) &&
    descriptor.kind === "LAMBDA_ZIP" &&
    descriptor.contentType === "application/zip" &&
    descriptor.s3Bucket === bucket && HEX_64.test(descriptor.sha256 ?? "") &&
    HEX_64.test(descriptor.sourceSha256 ?? "") &&
    /^[A-Za-z0-9+/]{43}=$/u.test(descriptor.codeSha256 ?? "") &&
    descriptor.checksumSha256 === checksumFromHex(descriptor.sha256) &&
    descriptor.s3Key ===
      `gate2/${APP_SOURCE.commit}/${descriptor.name}-${descriptor.sha256}.zip` &&
    Number.isSafeInteger(descriptor.bytes) && descriptor.bytes > 0 &&
    descriptor.bytes <= MAX_OBJECT_BYTES, code);
  const body = asBytes(value.body, MAX_OBJECT_BYTES, code);
  requireCondition(body.length === descriptor.bytes &&
    sha256(body) === descriptor.sha256 &&
    base64Sha256(body) === descriptor.checksumSha256, code);
  return Object.freeze({ body, descriptor: Object.freeze({ ...descriptor }) });
}

function validateTemplate(value, bucket, command, code) {
  requireCondition(exactKeys(value, ["body", "descriptor"]) &&
    exactKeys(value.descriptor, [
      "bytes", "checksumSha256", "contentType", "kind", "name",
      "s3Bucket", "s3Key", "sha256"
    ]), code);
  const descriptor = value.descriptor;
  requireCondition(descriptor.kind === "CLOUDFORMATION_TEMPLATE" &&
    descriptor.name === "gate2-template" &&
    descriptor.contentType === "application/json" &&
    descriptor.s3Bucket === bucket && descriptor.sha256 ===
      REVIEWED_GATE2_TEMPLATE_SHA256 && descriptor.sha256 ===
      command.templateSha256 &&
    descriptor.checksumSha256 === checksumFromHex(descriptor.sha256) &&
    descriptor.s3Key ===
      `gate2/${APP_SOURCE.commit}/gate2-template-${descriptor.sha256}.json` &&
    Number.isSafeInteger(descriptor.bytes) && descriptor.bytes > 0 &&
    descriptor.bytes <= 1024 * 1024, code);
  const body = asBytes(value.body, 1024 * 1024, code);
  requireCondition(body.length === descriptor.bytes &&
    sha256(body) === descriptor.sha256 &&
    base64Sha256(body) === descriptor.checksumSha256, code);
  return Object.freeze({ body, descriptor: Object.freeze({ ...descriptor }) });
}

function artifactPrefix(name) {
  return `${name[0].toUpperCase()}${name.slice(1)}`;
}

function validateParameterBindings(value, artifacts, bucket, command, code) {
  requireCondition(Array.isArray(value) && value.length === 45 &&
    value.every((entry) => exactKeys(entry, [
      "ParameterKey", "Source", "Value"
    ]) && PARAMETER_KEYS.includes(entry.ParameterKey) &&
      ["LITERAL", "OBJECT_VERSION"].includes(entry.Source) &&
      typeof entry.Value === "string" && entry.Value.length > 0 &&
      entry.Value.length <= 2048) &&
    value.map(({ ParameterKey }) => ParameterKey).join("\n") ===
      PARAMETER_KEYS.join("\n"), code);
  const byKey = Object.fromEntries(value.map((entry) => [entry.ParameterKey,
    entry]));
  requireCondition(byKey.ArtifactBucket.Source === "LITERAL" &&
    byKey.ArtifactBucket.Value === bucket &&
    byKey.SourceCommit.Source === "LITERAL" &&
    byKey.SourceCommit.Value === APP_SOURCE.commit &&
    byKey.TreeDigest.Source === "LITERAL" &&
    byKey.TreeDigest.Value === APP_SOURCE.tree &&
    byKey.EnableProbeFunctions.Source === "LITERAL" &&
    byKey.EnableProbeFunctions.Value === "false", code);
  for (const artifact of artifacts) {
    const prefix = artifactPrefix(artifact.descriptor.name);
    requireCondition(
      byKey[`${prefix}ArtifactKey`].Source === "LITERAL" &&
      byKey[`${prefix}ArtifactKey`].Value === artifact.descriptor.s3Key &&
      byKey[`${prefix}ArtifactDigest`].Source === "LITERAL" &&
      byKey[`${prefix}ArtifactDigest`].Value === artifact.descriptor.sha256 &&
      byKey[`${prefix}ArtifactCodeSha256`].Source === "LITERAL" &&
      byKey[`${prefix}ArtifactCodeSha256`].Value ===
        artifact.descriptor.codeSha256 &&
      byKey[`${prefix}SourceDigest`].Source === "LITERAL" &&
      byKey[`${prefix}SourceDigest`].Value ===
        artifact.descriptor.sourceSha256 &&
      byKey[`${prefix}ArtifactVersion`].Source === "OBJECT_VERSION" &&
      byKey[`${prefix}ArtifactVersion`].Value === artifact.descriptor.name,
    code);
  }
  requireCondition(value.filter(({ Source }) =>
    Source === "OBJECT_VERSION").length === 6 &&
    command.parameterManifestSha256 === canonicalDigest(value), code);
  return Object.freeze(value.map((entry) => Object.freeze({ ...entry })));
}

function validateResourceInventory(value, command, code) {
  requireCondition(Array.isArray(value) && value.length > 0 &&
    value.length <= 128 && value.every((entry) => exactKeys(entry, [
      "logicalId", "type"
    ]) && /^[A-Za-z][A-Za-z0-9]{0,254}$/u.test(entry.logicalId ?? "") &&
      /^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$/u.test(entry.type ?? "")) &&
    value.map(({ logicalId }) => logicalId).join("\n") ===
      [...value].map(({ logicalId }) => logicalId).sort().join("\n") &&
    new Set(value.map(({ logicalId }) => logicalId)).size === value.length &&
    canonicalDigest(value) === command.resourceInventorySha256, code);
  return Object.freeze(value.map((entry) => Object.freeze({ ...entry })));
}

export function validatePrepareRequest(request, command) {
  const code = "RELEASE_PROVIDER_PREPARE_REQUEST_REJECTED";
  const tableArn = command?.namespaceArn;
  const acceptedCommand = validatePrepareCommand(command, tableArn);
  const accountId = tableArn.split(":")[4];
  requireCondition(exactKeys(request, [
    "accountId", "artifactBucket", "artifacts", "capabilities",
    "changeSetName", "changeSetType", "cloudFormationRoleArn",
    "commandSha256", "createResourceInventory", "intentId",
    "parameterBindings", "region", "schemaVersion", "stackName", "template"
  ]) && request.schemaVersion === REQUEST_SCHEMA &&
    request.accountId === accountId && ACCOUNT_ID.test(accountId) &&
    request.region === REGION && request.commandSha256 ===
      acceptedCommand.commandSha256 && request.intentId &&
    UUID.test(request.intentId) && request.stackName === command.stackName &&
    request.changeSetName === command.changeSetName &&
    request.changeSetType === "CREATE" &&
    canonicalJson(request.capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    request.cloudFormationRoleArn ===
      `arn:aws:iam::${accountId}:role/ProofToActGate2CloudFormation`, code);
  const bucket = bucketName(request.artifactBucket, code);
  requireCondition(Array.isArray(request.artifacts) &&
    request.artifacts.length === 6, code);
  const artifacts = request.artifacts.map((entry) =>
    validateArtifact(entry, bucket, code));
  requireCondition(artifacts.map(({ descriptor }) => descriptor.name)
    .join("\n") === ARTIFACT_NAMES.join("\n") &&
    acceptedCommand.artifactManifestSha256 === canonicalDigest({
      artifactBucket: bucket,
      artifacts: artifacts.map(({ descriptor }) => descriptor)
    }), code);
  const template = validateTemplate(request.template, bucket, acceptedCommand,
    code);
  const parameterBindings = validateParameterBindings(
    request.parameterBindings, artifacts, bucket, acceptedCommand, code);
  const createResourceInventory = validateResourceInventory(
    request.createResourceInventory, acceptedCommand, code);
  return Object.freeze({
    ...request,
    artifacts,
    artifactBucket: bucket,
    command: acceptedCommand,
    createResourceInventory,
    parameterBindings,
    template
  });
}

function exactTransport(transport) {
  requireCondition(exactKeys(transport, [
    "createChangeSet", "getObject", "headObject", "putObject"
  ]) && Object.values(transport).every((entry) => typeof entry === "function"),
  "RELEASE_PROVIDER_DISPATCH_TRANSPORT_REJECTED");
  return transport;
}

function errorCode(error) {
  const value = typeof error?.message === "string" ? error.message : "UNKNOWN";
  return value.replace(/[^A-Z0-9_]/giu, "_").toUpperCase().slice(0, 96);
}

function metadataFor(descriptor, command, intentId) {
  return Object.freeze({
    "prooftoact-command-sha256": command.commandSha256,
    "prooftoact-intent-id": intentId,
    "prooftoact-kind": descriptor.kind,
    "prooftoact-name": descriptor.name,
    "prooftoact-sha256": descriptor.sha256
  });
}

function objectInput(object, command, intentId) {
  const descriptor = object.descriptor;
  return Object.freeze({
    Body: object.body,
    Bucket: descriptor.s3Bucket,
    ChecksumAlgorithm: "SHA256",
    ChecksumSHA256: descriptor.checksumSha256,
    ContentLength: descriptor.bytes,
    ContentType: descriptor.contentType,
    ExpectedBucketOwner: command.namespaceArn.split(":")[4],
    IfNoneMatch: "*",
    Key: descriptor.s3Key,
    Metadata: metadataFor(descriptor, command, intentId),
    ServerSideEncryption: "AES256"
  });
}

async function verifyObjectVersion(provider, object, command, intentId,
  versionId = null) {
  const descriptor = object.descriptor;
  const base = {
    Bucket: descriptor.s3Bucket,
    ChecksumMode: "ENABLED",
    ExpectedBucketOwner: command.namespaceArn.split(":")[4],
    Key: descriptor.s3Key,
    ...(versionId === null ? {} : { VersionId: versionId })
  };
  const head = await provider.headObject(base);
  const observedVersion = head?.VersionId;
  requireCondition(VERSION_ID.test(observedVersion ?? "") &&
    observedVersion !== "null" &&
    (versionId === null || versionId === observedVersion) &&
    head.DeleteMarker !== true && head.ContentLength === descriptor.bytes &&
    head.ChecksumSHA256 === descriptor.checksumSha256 &&
    head.ContentType === descriptor.contentType &&
    head.ServerSideEncryption === "AES256" &&
    canonicalJson(head.Metadata) ===
      canonicalJson(metadataFor(descriptor, command, intentId)),
  "RELEASE_PROVIDER_OBJECT_HEAD_REJECTED");
  const response = await provider.getObject({ ...base, VersionId: observedVersion });
  requireCondition(response?.VersionId === observedVersion &&
    response.DeleteMarker !== true && response.ContentLength === descriptor.bytes &&
    response.ChecksumSHA256 === descriptor.checksumSha256 &&
    response.ContentType === descriptor.contentType &&
    response.ServerSideEncryption === "AES256" &&
    canonicalJson(response.Metadata) ===
      canonicalJson(metadataFor(descriptor, command, intentId)),
  "RELEASE_PROVIDER_OBJECT_GET_REJECTED");
  const bytes = await responseBodyBytes(response.Body, descriptor.bytes,
    "RELEASE_PROVIDER_OBJECT_BODY_REJECTED");
  requireCondition(sha256(bytes) === descriptor.sha256,
    "RELEASE_PROVIDER_OBJECT_BODY_REJECTED");
  return Object.freeze({
    descriptor,
    etag: typeof head.ETag === "string" ? head.ETag : null,
    versionId: observedVersion
  });
}

async function uploadOne(provider, object, command, intentId,
  mutationAuthority) {
  const input = objectInput(object, command, intentId);
  mutationAuthority.assertCurrent(`PutObject:${object.descriptor.name}`);
  let response;
  let acknowledged = false;
  try {
    response = await provider.putObject(input);
    acknowledged = true;
  } catch {
    response = null;
  }
  const version = await verifyObjectVersion(
    provider, object, command, intentId,
    acknowledged ? response?.VersionId ?? null : null
  );
  if (acknowledged) {
    requireCondition(VERSION_ID.test(response?.VersionId ?? "") &&
      response.VersionId !== "null" &&
      response.VersionId === version.versionId &&
      response.ChecksumSHA256 === object.descriptor.checksumSha256 &&
      response.ServerSideEncryption === "AES256",
    "RELEASE_PROVIDER_OBJECT_PUT_REJECTED");
  }
  return Object.freeze({
    ...version,
    putAcknowledged: acknowledged,
    status: acknowledged ? "PUT_ACKNOWLEDGED_EXACT" :
      "PUT_ACK_UNKNOWN_EXACT_READBACK"
  });
}

function resolveParameters(bindings, versions) {
  return Object.freeze(bindings.map((binding) => Object.freeze({
    ParameterKey: binding.ParameterKey,
    ParameterValue: binding.Source === "LITERAL"
      ? binding.Value : versions[binding.Value]
  })));
}

function encodedS3Path(bucket, key, versionId) {
  const encoded = key.split("/").map(encodeURIComponent).join("/");
  return `https://s3.us-east-1.amazonaws.com/${bucket}/${encoded}` +
    `?versionId=${encodeURIComponent(versionId)}`;
}

function createChangeSetInput(accepted, objectVersions, parameters) {
  const templateVersion = objectVersions.find(({ descriptor }) =>
    descriptor.kind === "CLOUDFORMATION_TEMPLATE");
  const resolvedBinding = {
    commandSha256: accepted.command.commandSha256,
    intentId: accepted.intentId,
    objectVersions: objectVersions.map(({ descriptor, versionId }) => ({
      name: descriptor.name,
      s3Key: descriptor.s3Key,
      sha256: descriptor.sha256,
      versionId
    })),
    parameters,
    templateUrl: encodedS3Path(
      accepted.artifactBucket,
      templateVersion.descriptor.s3Key,
      templateVersion.versionId
    )
  };
  const resolvedBindingSha256 = canonicalDigest(resolvedBinding);
  const input = {
    Capabilities: ["CAPABILITY_NAMED_IAM"],
    ChangeSetName: accepted.changeSetName,
    ChangeSetType: "CREATE",
    ClientToken: accepted.intentId,
    Description: `ProofToAct PREPARE ${resolvedBindingSha256}`,
    IncludeNestedStacks: false,
    Parameters: parameters,
    RoleARN: accepted.cloudFormationRoleArn,
    StackName: accepted.stackName,
    Tags: [
      { Key: "Project", Value: "ProofToAct" },
      { Key: "Purpose", Value: "BoundedHackathonRelease" },
      { Key: "SourceCommit", Value: APP_SOURCE.commit }
    ],
    TemplateURL: resolvedBinding.templateUrl
  };
  return Object.freeze({
    input: Object.freeze(input),
    resolvedBinding: Object.freeze(resolvedBinding),
    resolvedBindingSha256
  });
}

function validateAuthorityNotAfter(value) {
  const code = "RELEASE_PROVIDER_AUTHORITY_NOT_AFTER_REJECTED";
  const timestamp = Date.parse(value ?? "");
  requireCondition(typeof value === "string" && Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value, code);
  return Object.freeze({ timestamp, value });
}

function createMutationAuthority(clock, authorityNotAfter) {
  const deadline = validateAuthorityNotAfter(authorityNotAfter);
  return Object.freeze({
    authorityNotAfter: deadline.value,
    assertCurrent(action) {
      const code = "RELEASE_PROVIDER_MUTATION_AUTHORITY_WINDOW_REJECTED";
      const now = clock();
      requireCondition(typeof action === "string" && action.length > 0 &&
        Number.isSafeInteger(now) && now >= 0 &&
        deadline.timestamp - now > MINIMUM_MUTATION_REMAINING_MS, code);
      return Object.freeze({
        action,
        checkedAt: new Date(now).toISOString(),
        remainingMs: deadline.timestamp - now
      });
    }
  });
}

function dispatcherWithClock({ clock, transport }) {
  const provider = exactTransport(transport);
  requireCondition(typeof clock === "function",
    "RELEASE_PROVIDER_DISPATCH_CLOCK_REJECTED");
  return Object.freeze({
    async dispatch(input) {
      const code = "RELEASE_PROVIDER_PREPARE_DISPATCH_REJECTED";
      requireCondition(exactKeys(input, [
        "authorityNotAfter", "permit", "request"
      ]), code);
      const { authorityNotAfter, permit, request } = input;
      requireCondition(plainObject(permit) &&
        permit.schemaVersion === "prooftoact.prepare-provider-permit.v1" &&
        permit.status === "EXACT_DURABLE_INTENT_CONFIRMED" &&
        permit.readOnly === true && permit.stronglyConsistent === true &&
        HEX_64.test(permit.permitSha256 ?? "") &&
        permit.permitSha256 === canonicalDigest((({ permitSha256: _, ...rest }) =>
          rest)(permit)), code);
      const accepted = validatePrepareRequest(request, permit.command);
      requireCondition(permit.intent.intentId === accepted.intentId &&
        permit.command.commandSha256 === accepted.commandSha256, code);
      const mutationAuthority = createMutationAuthority(clock,
        authorityNotAfter);
      const orderedObjects = [...accepted.artifacts, accepted.template];
      const uploaded = [];
      try {
        for (const object of orderedObjects) {
          uploaded.push(await uploadOne(provider, object, accepted.command,
            accepted.intentId, mutationAuthority));
        }
      } catch (cause) {
        const authorityStopped = cause?.message ===
          "RELEASE_PROVIDER_MUTATION_AUTHORITY_WINDOW_REJECTED";
        const receipt = {
          schemaVersion: DISPATCH_SCHEMA,
          status: authorityStopped
            ? "AUTHORITY_WINDOW_UPLOAD_STOPPED"
            : "AMBIGUOUS_UPLOAD_STOPPED",
          accepted: false,
          authorityNotAfter: mutationAuthority.authorityNotAfter,
          changeSetCreateAttempted: false,
          commandSha256: accepted.commandSha256,
          intentId: accepted.intentId,
          mutationSequenceStopped: true,
          providerRequestId: null,
          reasonCode: errorCode(cause),
          retryAllowed: false,
          uploaded: uploaded.map(({ descriptor, putAcknowledged, status,
            versionId }) => ({
            name: descriptor.name, putAcknowledged, sha256: descriptor.sha256,
            status, versionId
          }))
        };
        return Object.freeze({ ...receipt,
          providerReceiptSha256: canonicalDigest(receipt) });
      }
      const versions = Object.fromEntries(uploaded.filter(({ descriptor }) =>
        descriptor.kind === "LAMBDA_ZIP").map(({ descriptor, versionId }) =>
        [descriptor.name, versionId]));
      const parameters = resolveParameters(accepted.parameterBindings, versions);
      const changeSet = createChangeSetInput(accepted, uploaded, parameters);
      let response;
      let changeSetCreateAttempted = false;
      try {
        mutationAuthority.assertCurrent("CreateChangeSet");
        changeSetCreateAttempted = true;
        response = await provider.createChangeSet(changeSet.input);
      } catch (cause) {
        const authorityStopped = cause?.message ===
          "RELEASE_PROVIDER_MUTATION_AUTHORITY_WINDOW_REJECTED" &&
          changeSetCreateAttempted === false;
        const receipt = {
          schemaVersion: DISPATCH_SCHEMA,
          status: authorityStopped
            ? "AUTHORITY_WINDOW_BEFORE_CHANGE_SET"
            : "AMBIGUOUS_CREATE_CHANGE_SET_ACK",
          accepted: false,
          authorityNotAfter: mutationAuthority.authorityNotAfter,
          changeSetCreateAttempted,
          commandSha256: accepted.commandSha256,
          intentId: accepted.intentId,
          mutationSequenceStopped: true,
          providerRequestId: null,
          reasonCode: errorCode(cause),
          resolvedBindingSha256: changeSet.resolvedBindingSha256,
          retryAllowed: false,
          uploaded: uploaded.map(({ descriptor, putAcknowledged, status,
            versionId }) => ({
            name: descriptor.name, putAcknowledged, sha256: descriptor.sha256,
            status, versionId
          }))
        };
        return Object.freeze({ ...receipt,
          providerReceiptSha256: canonicalDigest(receipt) });
      }
      const account = accepted.accountId;
      requireCondition(
        new RegExp(`^arn:aws:cloudformation:us-east-1:${account}:changeSet/` +
          `${accepted.changeSetName}/[0-9a-f-]{36}$`, "u")
          .test(response?.Id ?? "") &&
        new RegExp(`^arn:aws:cloudformation:us-east-1:${account}:stack/` +
          `${accepted.stackName}/[0-9a-f-]{36}$`, "u")
          .test(response?.StackId ?? ""), code);
      const requestId = providerRequestId(response?.$metadata?.requestId, code);
      const receipt = {
        schemaVersion: DISPATCH_SCHEMA,
        status: "CREATE_CHANGE_SET_ACKNOWLEDGED_READBACK_REQUIRED",
        accepted: false,
        authorityNotAfter: mutationAuthority.authorityNotAfter,
        changeSetArn: response.Id,
        changeSetCreateAttempted: true,
        commandSha256: accepted.commandSha256,
        intentId: accepted.intentId,
        mutationSequenceStopped: true,
        providerRequestId: requestId,
        resolvedBindingSha256: changeSet.resolvedBindingSha256,
        retryAllowed: false,
        stackId: response.StackId,
        uploaded: uploaded.map(({ descriptor, putAcknowledged, status,
          versionId }) => ({
          name: descriptor.name, putAcknowledged, sha256: descriptor.sha256,
          status, versionId
        }))
      };
      return Object.freeze({
        ...receipt,
        providerReceiptSha256: canonicalDigest(receipt)
      });
    }
  });
}

export function createPrepareDispatcher(configuration) {
  requireCondition(exactKeys(configuration, ["transport"]),
    "RELEASE_PROVIDER_DISPATCH_CONFIGURATION_REJECTED");
  return dispatcherWithClock({ clock: Date.now,
    transport: configuration.transport });
}

export function exactObjectInput(input, write) {
  const expected = [
    "Bucket", "ChecksumAlgorithm", "ChecksumSHA256", "ContentLength",
    "ContentType", "ExpectedBucketOwner", "IfNoneMatch", "Key", "Metadata",
    "ServerSideEncryption", "Body"
  ];
  requireCondition(exactKeys(input, expected) && write === true &&
    input.IfNoneMatch === "*" && input.ChecksumAlgorithm === "SHA256" &&
    input.ServerSideEncryption === "AES256" &&
    ACCOUNT_ID.test(input.ExpectedBucketOwner ?? ""),
  "RELEASE_PROVIDER_S3_WRITE_INPUT_REJECTED");
  return input;
}

export function exactReadInput(input, allowNoVersion) {
  const keys = Object.keys(input).sort().join("\n");
  const withVersion = [
    "Bucket", "ChecksumMode", "ExpectedBucketOwner", "Key", "VersionId"
  ].sort().join("\n");
  const withoutVersion = [
    "Bucket", "ChecksumMode", "ExpectedBucketOwner", "Key"
  ].sort().join("\n");
  requireCondition((keys === withVersion || allowNoVersion &&
    keys === withoutVersion) && input.ChecksumMode === "ENABLED" &&
    ACCOUNT_ID.test(input.ExpectedBucketOwner ?? "") &&
    (input.VersionId === undefined || VERSION_ID.test(input.VersionId) &&
      input.VersionId !== "null"),
  "RELEASE_PROVIDER_S3_READ_INPUT_REJECTED");
  return input;
}

export function exactChangeSetInput(input) {
  requireCondition(exactKeys(input, [
    "Capabilities", "ChangeSetName", "ChangeSetType", "ClientToken",
    "Description", "IncludeNestedStacks", "Parameters", "RoleARN",
    "StackName", "Tags", "TemplateURL"
  ]) && input.ChangeSetType === "CREATE" &&
    input.ClientToken && UUID.test(input.ClientToken) &&
    canonicalJson(input.Capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    input.IncludeNestedStacks === false && Array.isArray(input.Parameters) &&
    input.Parameters.length === 45 && input.StackName === "prooftoact-gate2" &&
    /^prooftoact-release-[a-z0-9-]{1,64}$/u.test(input.ChangeSetName ?? "") &&
    /^https:\/\/s3\.us-east-1\.amazonaws\.com\//u.test(input.TemplateURL ?? ""),
  "RELEASE_PROVIDER_CREATE_CHANGE_SET_INPUT_REJECTED");
  return input;
}

export const __test = Object.freeze({
  MINIMUM_MUTATION_REMAINING_MS,
  checksumFromHex,
  createMutationAuthority,
  createChangeSetInput,
  encodedS3Path,
  errorCode,
  exactChangeSetInput,
  exactObjectInput,
  exactReadInput,
  metadataFor,
  resolveParameters,
  validateArtifact,
  validateParameterBindings,
  validateTemplate,
  verifyObjectVersion
});
