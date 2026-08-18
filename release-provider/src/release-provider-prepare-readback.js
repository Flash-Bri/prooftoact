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

const READBACK_SCHEMA = "prooftoact.provider-broker-finalizer-readback.v1";
const MAX_OBJECT_BYTES = 20 * 1024 * 1024;
const REVIEWED_GATE2_TEMPLATE_SHA256 =
  "a10066b23925cf2921b15eaa0d52e7ac8ef7a5f46e0ab260431a340e897cc3a1";

function exactTransport(transport) {
  requireCondition(exactKeys(transport, [
    "describeChangeSet", "describeStackEvents", "describeStackResources",
    "describeStacks", "getObject", "getTemplate", "headObject"
  ]) && Object.values(transport).every((entry) => typeof entry === "function"),
  "RELEASE_PROVIDER_READBACK_TRANSPORT_REJECTED");
  return transport;
}

function checksumFromHex(value) {
  return Buffer.from(value, "hex").toString("base64");
}

function acceptObject(value, bucket, command, template) {
  const code = "RELEASE_PROVIDER_READBACK_OBJECT_REJECTED";
  const descriptorKeys = template
    ? ["bytes", "checksumSha256", "contentType", "kind", "name",
        "s3Bucket", "s3Key", "sha256"]
    : ["bytes", "checksumSha256", "codeSha256", "contentType", "kind",
        "name", "s3Bucket", "s3Key", "sha256", "sourceSha256"];
  requireCondition(exactKeys(value, ["body", "descriptor"]) &&
    exactKeys(value.descriptor, descriptorKeys), code);
  const descriptor = value.descriptor;
  if (template) {
    requireCondition(descriptor.kind === "CLOUDFORMATION_TEMPLATE" &&
      descriptor.name === "gate2-template" &&
      descriptor.contentType === "application/json" &&
      descriptor.sha256 === REVIEWED_GATE2_TEMPLATE_SHA256 &&
      descriptor.sha256 === command.templateSha256 && descriptor.s3Key ===
        `gate2/${APP_SOURCE.commit}/gate2-template-${descriptor.sha256}.json`,
    code);
  } else {
    requireCondition(ARTIFACT_NAMES.includes(descriptor.name) &&
      descriptor.kind === "LAMBDA_ZIP" &&
      descriptor.contentType === "application/zip" &&
      HEX_64.test(descriptor.codeSha256 ?? "") === false &&
      /^[A-Za-z0-9+/]{43}=$/u.test(descriptor.codeSha256 ?? "") &&
      HEX_64.test(descriptor.sourceSha256 ?? "") && descriptor.s3Key ===
        `gate2/${APP_SOURCE.commit}/${descriptor.name}-${descriptor.sha256}.zip`,
    code);
  }
  requireCondition(descriptor.s3Bucket === bucket &&
    HEX_64.test(descriptor.sha256 ?? "") && descriptor.checksumSha256 ===
      checksumFromHex(descriptor.sha256) &&
    Number.isSafeInteger(descriptor.bytes) && descriptor.bytes > 0 &&
    descriptor.bytes <= (template ? 1024 * 1024 : MAX_OBJECT_BYTES), code);
  const body = asBytes(value.body,
    template ? 1024 * 1024 : MAX_OBJECT_BYTES, code);
  requireCondition(body.length === descriptor.bytes &&
    sha256(body) === descriptor.sha256 &&
    base64Sha256(body) === descriptor.checksumSha256, code);
  return Object.freeze({ body, descriptor: Object.freeze({ ...descriptor }) });
}

function acceptRequest(request, command) {
  const code = "RELEASE_PROVIDER_READBACK_REQUEST_REJECTED";
  const acceptedCommand = validatePrepareCommand(command, command?.namespaceArn);
  const accountId = command.namespaceArn.split(":")[4];
  requireCondition(exactKeys(request, [
    "accountId", "artifactBucket", "artifacts", "capabilities",
    "changeSetName", "changeSetType", "cloudFormationRoleArn",
    "commandSha256", "createResourceInventory", "intentId",
    "parameterBindings", "region", "schemaVersion", "stackName", "template"
  ]) && request.schemaVersion === "prooftoact.prepare-provider-request.v1" &&
    request.accountId === accountId && ACCOUNT_ID.test(accountId) &&
    request.commandSha256 === command.commandSha256 &&
    request.region === REGION && UUID.test(request.intentId ?? "") &&
    request.stackName === command.stackName &&
    request.changeSetName === command.changeSetName &&
    request.changeSetType === "CREATE" &&
    canonicalJson(request.capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    request.cloudFormationRoleArn ===
      `arn:aws:iam::${accountId}:role/ProofToActGate2CloudFormation` &&
    typeof request.artifactBucket === "string" &&
    request.artifactBucket.length >= 3 && request.artifactBucket.length <= 63 &&
    /^(?!xn--)(?!.*\.\.)(?!\d{1,3}(?:\.\d{1,3}){3}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u
      .test(request.artifactBucket),
  code);
  requireCondition(Array.isArray(request.artifacts) &&
    request.artifacts.length === 6, code);
  const artifacts = request.artifacts.map((entry) =>
    acceptObject(entry, request.artifactBucket, acceptedCommand, false));
  requireCondition(artifacts.map(({ descriptor }) => descriptor.name)
    .join("\n") === ARTIFACT_NAMES.join("\n") &&
    command.artifactManifestSha256 === canonicalDigest({
      artifactBucket: request.artifactBucket,
      artifacts: artifacts.map(({ descriptor }) => descriptor)
    }), code);
  const template = acceptObject(request.template, request.artifactBucket,
    acceptedCommand, true);
  requireCondition(Array.isArray(request.parameterBindings) &&
    request.parameterBindings.length === 45 &&
    request.parameterBindings.every((entry) => exactKeys(entry, [
      "ParameterKey", "Source", "Value"
    ]) && ["LITERAL", "OBJECT_VERSION"].includes(entry.Source) &&
      typeof entry.Value === "string" && entry.Value.length > 0) &&
    request.parameterBindings.map(({ ParameterKey }) => ParameterKey)
      .join("\n") === PARAMETER_KEYS.join("\n") &&
    request.parameterBindings.filter(({ Source }) =>
      Source === "OBJECT_VERSION").length === 6 &&
    canonicalDigest(request.parameterBindings) ===
      command.parameterManifestSha256, code);
  const byKey = Object.fromEntries(request.parameterBindings.map((entry) =>
    [entry.ParameterKey, entry]));
  for (const artifact of artifacts) {
    const prefix = artifact.descriptor.name[0].toUpperCase() +
      artifact.descriptor.name.slice(1);
    requireCondition(byKey[`${prefix}ArtifactVersion`]?.Source ===
      "OBJECT_VERSION" && byKey[`${prefix}ArtifactVersion`]?.Value ===
      artifact.descriptor.name && byKey[`${prefix}ArtifactKey`]?.Source ===
      "LITERAL" && byKey[`${prefix}ArtifactKey`]?.Value ===
      artifact.descriptor.s3Key && byKey[`${prefix}ArtifactDigest`]?.Source ===
      "LITERAL" && byKey[`${prefix}ArtifactDigest`]?.Value ===
      artifact.descriptor.sha256 &&
      byKey[`${prefix}ArtifactCodeSha256`]?.Source === "LITERAL" &&
      byKey[`${prefix}ArtifactCodeSha256`]?.Value ===
      artifact.descriptor.codeSha256 &&
      byKey[`${prefix}SourceDigest`]?.Source === "LITERAL" &&
      byKey[`${prefix}SourceDigest`]?.Value ===
      artifact.descriptor.sourceSha256, code);
  }
  requireCondition(Array.isArray(request.createResourceInventory) &&
    request.createResourceInventory.length > 0 &&
    request.createResourceInventory.every((entry) => exactKeys(entry, [
      "logicalId", "type"
    ])) && canonicalDigest(request.createResourceInventory) ===
      command.resourceInventorySha256, code);
  return Object.freeze({ ...request, artifacts, command: acceptedCommand,
    template });
}

function metadataFor(descriptor, command, intentId) {
  return {
    "prooftoact-command-sha256": command.commandSha256,
    "prooftoact-intent-id": intentId,
    "prooftoact-kind": descriptor.kind,
    "prooftoact-name": descriptor.name,
    "prooftoact-sha256": descriptor.sha256
  };
}

async function readCurrentObject(provider, object, accepted) {
  const descriptor = object.descriptor;
  const common = {
    Bucket: descriptor.s3Bucket,
    ChecksumMode: "ENABLED",
    ExpectedBucketOwner: accepted.accountId,
    Key: descriptor.s3Key
  };
  const head = await provider.headObject(common);
  requireCondition(VERSION_ID.test(head?.VersionId ?? "") &&
    head.VersionId !== "null" &&
    head.DeleteMarker !== true && head.ContentLength === descriptor.bytes &&
    head.ChecksumSHA256 === descriptor.checksumSha256 &&
    head.ContentType === descriptor.contentType &&
    head.ServerSideEncryption === "AES256" && canonicalJson(head.Metadata) ===
      canonicalJson(metadataFor(descriptor, accepted.command,
        accepted.intentId)), "RELEASE_PROVIDER_READBACK_HEAD_REJECTED");
  const get = await provider.getObject({ ...common, VersionId: head.VersionId });
  requireCondition(get?.VersionId === head.VersionId &&
    get.DeleteMarker !== true && get.ContentLength === descriptor.bytes &&
    get.ChecksumSHA256 === descriptor.checksumSha256 &&
    get.ContentType === descriptor.contentType &&
    get.ServerSideEncryption === "AES256" && canonicalJson(get.Metadata) ===
      canonicalJson(metadataFor(descriptor, accepted.command,
        accepted.intentId)), "RELEASE_PROVIDER_READBACK_GET_REJECTED");
  const bytes = await responseBodyBytes(get.Body, descriptor.bytes,
    "RELEASE_PROVIDER_READBACK_BODY_REJECTED");
  requireCondition(sha256(bytes) === descriptor.sha256,
    "RELEASE_PROVIDER_READBACK_BODY_REJECTED");
  return Object.freeze({ descriptor, versionId: head.VersionId });
}

function resolvedParameters(bindings, objectVersions) {
  const versions = Object.fromEntries(objectVersions.filter(({ descriptor }) =>
    descriptor.kind === "LAMBDA_ZIP").map(({ descriptor, versionId }) =>
    [descriptor.name, versionId]));
  return bindings.map((entry) => ({
    ParameterKey: entry.ParameterKey,
    ParameterValue: entry.Source === "LITERAL" ? entry.Value :
      versions[entry.Value]
  }));
}

function templateUrl(accepted, objectVersions) {
  const template = objectVersions.find(({ descriptor }) =>
    descriptor.kind === "CLOUDFORMATION_TEMPLATE");
  const path = template.descriptor.s3Key.split("/").map(encodeURIComponent)
    .join("/");
  return `https://s3.us-east-1.amazonaws.com/${accepted.artifactBucket}/` +
    `${path}?versionId=${encodeURIComponent(template.versionId)}`;
}

function normalizeParameters(value, code) {
  requireCondition(Array.isArray(value) && value.length === 45 &&
    value.every((entry) => plainObject(entry) &&
      typeof entry.ParameterKey === "string" &&
      typeof entry.ParameterValue === "string" &&
      entry.UsePreviousValue !== true), code);
  return value.map(({ ParameterKey, ParameterValue }) => ({
    ParameterKey, ParameterValue
  })).sort((left, right) => left.ParameterKey.localeCompare(right.ParameterKey));
}

function normalizeChanges(value, code) {
  requireCondition(Array.isArray(value) && value.length > 0 &&
    value.length <= 128, code);
  return value.map((entry) => {
    const resource = entry?.ResourceChange;
    requireCondition(entry.Type === "Resource" && resource?.Action === "Add" &&
      /^[A-Za-z][A-Za-z0-9]{0,254}$/u.test(
        resource.LogicalResourceId ?? "") &&
      /^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$/u.test(
        resource.ResourceType ?? ""), code);
    return { logicalId: resource.LogicalResourceId,
      type: resource.ResourceType };
  }).sort((left, right) => left.logicalId.localeCompare(right.logicalId));
}

function validateOriginalTemplate(value, accepted) {
  const code = "RELEASE_PROVIDER_ORIGINAL_TEMPLATE_REJECTED";
  requireCondition(exactKeys(value, [
    "$metadata", "StagesAvailable", "TemplateBody"
  ]) && typeof value.TemplateBody === "string" &&
    Buffer.byteLength(value.TemplateBody, "utf8") > 0 &&
    Buffer.byteLength(value.TemplateBody, "utf8") <= 1024 * 1024 &&
    Array.isArray(value.StagesAvailable) &&
    value.StagesAvailable.length >= 1 && value.StagesAvailable.length <= 2 &&
    value.StagesAvailable.includes("Original") &&
    new Set(value.StagesAvailable).size === value.StagesAvailable.length &&
    value.StagesAvailable.every((stage) =>
      ["Original", "Processed"].includes(stage)), code);
  let observed;
  let expected;
  try {
    observed = JSON.parse(value.TemplateBody);
    expected = JSON.parse(accepted.template.body.toString("utf8"));
  } catch (cause) {
    throw new Error(code, { cause });
  }
  requireCondition(plainObject(observed) && plainObject(expected) &&
    canonicalJson(observed) === canonicalJson(expected) &&
    sha256(accepted.template.body) === REVIEWED_GATE2_TEMPLATE_SHA256,
  code);
  return Object.freeze({
    canonicalSha256: canonicalDigest(observed),
    providerRequestId: providerRequestId(value.$metadata?.requestId, code),
    stage: "Original"
  });
}

function errorCode(error) {
  const value = typeof error?.message === "string" ? error.message : "UNKNOWN";
  return value.replace(/[^A-Z0-9_]/giu, "_").toUpperCase().slice(0, 96);
}

function currentObservedAt(clock) {
  const code = "RELEASE_PROVIDER_READBACK_CLOCK_REJECTED";
  const value = clock();
  requireCondition(Number.isSafeInteger(value) && value >= 0, code);
  return new Date(value).toISOString();
}

function readbackWithClock({ clock, transport }) {
  const provider = exactTransport(transport);
  requireCondition(typeof clock === "function",
    "RELEASE_PROVIDER_READBACK_CLOCK_REJECTED");
  return Object.freeze({
    async readback({ permit, readerPhaseRuntimeIdentitySha256, request }) {
      let accepted;
      try {
        requireCondition(plainObject(permit) &&
          permit.schemaVersion === "prooftoact.prepare-provider-permit.v1" &&
          permit.status === "EXACT_DURABLE_INTENT_CONFIRMED" &&
          permit.readOnly === true && permit.stronglyConsistent === true &&
          HEX_64.test(permit.permitSha256 ?? "") &&
          permit.permitSha256 === canonicalDigest((({ permitSha256: _, ...rest }) =>
            rest)(permit)) && HEX_64.test(readerPhaseRuntimeIdentitySha256 ?? ""),
        "RELEASE_PROVIDER_READBACK_PERMIT_REJECTED");
        accepted = acceptRequest(request, permit.command);
        requireCondition(accepted.intentId === permit.intent.intentId,
          "RELEASE_PROVIDER_READBACK_INTENT_REJECTED");
        const objects = [];
        for (const object of [...accepted.artifacts, accepted.template]) {
          objects.push(await readCurrentObject(provider, object, accepted));
        }
        const parameters = resolvedParameters(accepted.parameterBindings, objects);
        const binding = {
          commandSha256: accepted.command.commandSha256,
          intentId: accepted.intentId,
          objectVersions: objects.map(({ descriptor, versionId }) => ({
            name: descriptor.name, s3Key: descriptor.s3Key,
            sha256: descriptor.sha256, versionId
          })),
          parameters,
          templateUrl: templateUrl(accepted, objects)
        };
        const resolvedBindingSha256 = canonicalDigest(binding);
        const changeSet = await provider.describeChangeSet({
          ChangeSetName: accepted.changeSetName,
          IncludePropertyValues: true,
          StackName: accepted.stackName
        });
        const account = accepted.accountId;
        requireCondition(changeSet.ChangeSetName === accepted.changeSetName &&
          changeSet.StackName === accepted.stackName &&
          changeSet.ChangeSetType === "CREATE" &&
          changeSet.Status === "CREATE_COMPLETE" &&
          changeSet.ExecutionStatus === "AVAILABLE" &&
          changeSet.IncludeNestedStacks === false &&
          changeSet.RoleARN === accepted.cloudFormationRoleArn &&
          changeSet.Description ===
            `ProofToAct PREPARE ${resolvedBindingSha256}` &&
          canonicalJson(changeSet.Capabilities) ===
            canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
          new RegExp(`^arn:aws:cloudformation:us-east-1:${account}:changeSet/` +
            `${accepted.changeSetName}/[0-9a-f-]{36}$`, "u")
            .test(changeSet.ChangeSetId ?? "") &&
          new RegExp(`^arn:aws:cloudformation:us-east-1:${account}:stack/` +
            `${accepted.stackName}/[0-9a-f-]{36}$`, "u")
            .test(changeSet.StackId ?? "") &&
          canonicalJson(normalizeParameters(changeSet.Parameters,
            "RELEASE_PROVIDER_CHANGE_SET_PARAMETERS_REJECTED")) ===
            canonicalJson(parameters) &&
          changeSet.NextToken === undefined &&
          canonicalJson(normalizeChanges(changeSet.Changes,
            "RELEASE_PROVIDER_CHANGE_SET_CHANGES_REJECTED")) ===
            canonicalJson(accepted.createResourceInventory),
        "RELEASE_PROVIDER_CHANGE_SET_READBACK_REJECTED");
        const stackId = changeSet.StackId;
        const [stacks, events, resources, originalTemplate] = await Promise.all([
          provider.describeStacks({ StackName: stackId }),
          provider.describeStackEvents({ StackName: stackId }),
          provider.describeStackResources({ StackName: stackId }),
          provider.getTemplate({
            ChangeSetName: changeSet.ChangeSetId,
            StackName: stackId,
            TemplateStage: "Original"
          })
        ]);
        const templateEvidence = validateOriginalTemplate(originalTemplate,
          accepted);
        requireCondition(Array.isArray(stacks?.Stacks) &&
          stacks.Stacks.length === 1 && stacks.Stacks[0].StackId === stackId &&
          stacks.Stacks[0].StackName === accepted.stackName &&
          stacks.Stacks[0].StackStatus === "REVIEW_IN_PROGRESS" &&
          stacks.Stacks[0].EnableTerminationProtection !== true &&
          stacks.NextToken === undefined &&
          canonicalJson(normalizeParameters(stacks.Stacks[0].Parameters,
            "RELEASE_PROVIDER_STACK_PARAMETERS_REJECTED")) ===
          canonicalJson(parameters) && events?.NextToken === undefined &&
          Array.isArray(events?.StackEvents) &&
          resources?.NextToken === undefined &&
          Array.isArray(resources?.StackResources) &&
          resources.StackResources.length === 0,
        "RELEASE_PROVIDER_STACK_READBACK_REJECTED");
        const providerId = providerRequestId(
          changeSet?.$metadata?.requestId,
          "RELEASE_PROVIDER_READBACK_REQUEST_ID_REJECTED"
        );
        const normalizedEvidence = {
          changeSet: {
            capabilities: changeSet.Capabilities,
            changeSetArn: changeSet.ChangeSetId,
            changeSetName: changeSet.ChangeSetName,
            changeSetType: changeSet.ChangeSetType,
            changes: normalizeChanges(changeSet.Changes,
              "RELEASE_PROVIDER_CHANGE_SET_CHANGES_REJECTED"),
            description: changeSet.Description,
            executionStatus: changeSet.ExecutionStatus,
            parameters,
            roleArn: changeSet.RoleARN,
            stackId,
            stackName: changeSet.StackName,
            status: changeSet.Status
          },
          commandSha256: accepted.command.commandSha256,
          eventCount: events.StackEvents.length,
          originalTemplate: templateEvidence,
          objectVersions: binding.objectVersions,
          resolvedBindingSha256,
          resourceSummaryCount: resources.StackResources.length,
          stackStatus: stacks.Stacks[0].StackStatus
        };
        const preparedRelease = {
          changeSetArn: changeSet.ChangeSetId,
          changeSetName: accepted.changeSetName,
          changeSetSha256: canonicalDigest(normalizedEvidence),
          changeSetType: "CREATE",
          stackId,
          stackName: accepted.stackName
        };
        const observedAt = currentObservedAt(clock);
        const receipt = {
          schemaVersion: READBACK_SCHEMA,
          status: "CONFIRMED_APPLIED",
          commandSha256: accepted.command.commandSha256,
          fresh: true,
          independentOfDispatcher: true,
          intentSha256: canonicalDigest(permit.intent),
          observedAt,
          operationIdentitySha256: accepted.command.operationIdentitySha256,
          preparedRelease,
          providerNativeIdempotencyTokenSha256:
            sha256(Buffer.from(accepted.intentId, "utf8")),
          providerReceiptSha256: canonicalDigest(normalizedEvidence),
          providerRequestId: providerId,
          readOnly: true,
          readerPhaseRuntimeIdentitySha256
        };
        return Object.freeze(receipt);
      } catch (cause) {
        const command = accepted?.command ?? permit?.command;
        requireCondition(command && HEX_64.test(command.commandSha256 ?? "") &&
          HEX_64.test(command.operationIdentitySha256 ?? "") &&
          permit?.intent && UUID.test(permit.intent.intentId ?? "") &&
          HEX_64.test(readerPhaseRuntimeIdentitySha256 ?? ""),
        "RELEASE_PROVIDER_READBACK_INPUT_REJECTED");
        const observedAt = currentObservedAt(clock);
        return Object.freeze({
          schemaVersion: READBACK_SCHEMA,
          status: "UNKNOWN",
          commandSha256: command.commandSha256,
          fresh: true,
          independentOfDispatcher: true,
          intentSha256: canonicalDigest(permit.intent),
          observedAt,
          operationIdentitySha256: command.operationIdentitySha256,
          preparedRelease: null,
          providerNativeIdempotencyTokenSha256:
            sha256(Buffer.from(permit.intent.intentId, "utf8")),
          providerReceiptSha256: canonicalDigest({
            errorCode: errorCode(cause),
            observedAt,
            operationIdentitySha256: command.operationIdentitySha256,
            status: "UNKNOWN"
          }),
          providerRequestId: null,
          readOnly: true,
          readerPhaseRuntimeIdentitySha256
        });
      }
    }
  });
}

export function createPrepareReadback(configuration) {
  requireCondition(exactKeys(configuration, ["transport"]),
    "RELEASE_PROVIDER_READBACK_CONFIGURATION_REJECTED");
  return readbackWithClock({ clock: Date.now,
    transport: configuration.transport });
}

export function exactStackInput(input) {
  requireCondition(exactKeys(input, ["StackName"]) &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(input.StackName ?? ""), "RELEASE_PROVIDER_STACK_INPUT_REJECTED");
  return input;
}

export function exactS3ReadInput(input, versionRequired) {
  const expected = ["Bucket", "ChecksumMode", "ExpectedBucketOwner", "Key",
    ...(versionRequired ? ["VersionId"] : [])];
  requireCondition(exactKeys(input, expected) && input.ChecksumMode === "ENABLED" &&
    ACCOUNT_ID.test(input.ExpectedBucketOwner ?? "") &&
    (!versionRequired || VERSION_ID.test(input.VersionId ?? "") &&
      input.VersionId !== "null"),
  "RELEASE_PROVIDER_READBACK_S3_INPUT_REJECTED");
  return input;
}

export const __test = Object.freeze({
  acceptRequest,
  currentObservedAt,
  exactS3ReadInput,
  exactStackInput,
  normalizeChanges,
  normalizeParameters,
  resolvedParameters,
  templateUrl
});
