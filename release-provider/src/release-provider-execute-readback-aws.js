import { CloudFormationClient } from
  "@aws-sdk/client-cloudformation/dist-es/CloudFormationClient.js";
import { DescribeChangeSetCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeChangeSetCommand.js";
import { DescribeStackEventsCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeStackEventsCommand.js";
import { DescribeStacksCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeStacksCommand.js";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { fixedSdkOptions } from "./release-provider-common.js";
import {
  exactExecuteReadbackChangeSetInput,
  exactExecuteReadbackEventsInput,
  exactExecuteReadbackStackInput
} from "./release-provider-execute-readback.js";

export async function createAwsExecuteReadbackTransport({ credentials }) {
  const requestHandler = new NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 20_000
  });
  const cloudformation = new CloudFormationClient({
    ...fixedSdkOptions(
      "https://cloudformation.us-east-1.amazonaws.com", credentials),
    requestHandler
  });
  return Object.freeze({
    async describeChangeSet(input) {
      return cloudformation.send(new DescribeChangeSetCommand(
        exactExecuteReadbackChangeSetInput(input)));
    },
    async describeStackEvents(input) {
      return cloudformation.send(new DescribeStackEventsCommand(
        exactExecuteReadbackEventsInput(input)));
    },
    async describeStacks(input) {
      return cloudformation.send(new DescribeStacksCommand(
        exactExecuteReadbackStackInput(input)));
    }
  });
}
