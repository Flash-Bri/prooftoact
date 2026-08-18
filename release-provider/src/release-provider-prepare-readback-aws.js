import { CloudFormationClient } from
  "@aws-sdk/client-cloudformation/dist-es/CloudFormationClient.js";
import { DescribeChangeSetCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeChangeSetCommand.js";
import { DescribeStackEventsCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeStackEventsCommand.js";
import { DescribeStackResourcesCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeStackResourcesCommand.js";
import { DescribeStacksCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeStacksCommand.js";
import { GetTemplateCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/GetTemplateCommand.js";
import { S3Client } from "@aws-sdk/client-s3/dist-es/S3Client.js";
import { GetObjectCommand } from
  "@aws-sdk/client-s3/dist-es/commands/GetObjectCommand.js";
import { HeadObjectCommand } from
  "@aws-sdk/client-s3/dist-es/commands/HeadObjectCommand.js";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import {
  exactKeys,
  fixedSdkOptions,
  requireCondition
} from "./release-provider-common.js";
import {
  exactS3ReadInput,
  exactStackInput
} from "./release-provider-prepare-readback.js";

export async function createAwsPrepareReadbackTransport({ credentials }) {
  const requestHandler = new NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 20_000
  });
  const cloudformation = new CloudFormationClient({
    ...fixedSdkOptions(
      "https://cloudformation.us-east-1.amazonaws.com", credentials),
    requestHandler
  });
  const s3 = new S3Client({
    ...fixedSdkOptions("https://s3.us-east-1.amazonaws.com", credentials),
    forcePathStyle: false,
    requestHandler
  });
  return Object.freeze({
    async describeChangeSet(input) {
      requireCondition(exactKeys(input, [
        "ChangeSetName", "IncludePropertyValues", "StackName"
      ]) && input.IncludePropertyValues === true &&
        input.StackName === "prooftoact-gate2" &&
        /^prooftoact-release-[a-z0-9-]{1,64}$/u.test(
          input.ChangeSetName ?? ""),
      "RELEASE_PROVIDER_DESCRIBE_CHANGE_SET_INPUT_REJECTED");
      return cloudformation.send(new DescribeChangeSetCommand(input));
    },
    async describeStackEvents(input) {
      return cloudformation.send(new DescribeStackEventsCommand(
        exactStackInput(input)));
    },
    async describeStackResources(input) {
      return cloudformation.send(new DescribeStackResourcesCommand(
        exactStackInput(input)));
    },
    async describeStacks(input) {
      return cloudformation.send(new DescribeStacksCommand(exactStackInput(input)));
    },
    async getTemplate(input) {
      const code = "RELEASE_PROVIDER_GET_TEMPLATE_INPUT_REJECTED";
      requireCondition(exactKeys(input, [
        "ChangeSetName", "StackName", "TemplateStage"
      ]) && input.TemplateStage === "Original" &&
        /^arn:aws:cloudformation:us-east-1:[0-9]{12}:changeSet\/prooftoact-release-[a-z0-9-]{1,64}\/[0-9a-f-]{36}$/u
          .test(input.ChangeSetName ?? "") &&
        /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
          .test(input.StackName ?? ""), code);
      return cloudformation.send(new GetTemplateCommand(input));
    },
    async getObject(input) {
      return s3.send(new GetObjectCommand(exactS3ReadInput(input, true)));
    },
    async headObject(input) {
      return s3.send(new HeadObjectCommand(exactS3ReadInput(input, false)));
    },
  });
}
