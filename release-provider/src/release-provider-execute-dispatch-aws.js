import { CloudFormationClient } from
  "@aws-sdk/client-cloudformation/dist-es/CloudFormationClient.js";
import { DescribeChangeSetCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeChangeSetCommand.js";
import { DescribeStacksCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/DescribeStacksCommand.js";
import { ExecuteChangeSetCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/ExecuteChangeSetCommand.js";
import { UpdateTerminationProtectionCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/UpdateTerminationProtectionCommand.js";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { fixedSdkOptions } from "./release-provider-common.js";
import {
  exactDescribeChangeSetInput,
  exactExecuteChangeSetInput,
  exactExecuteStackInput,
  exactTerminationProtectionInput
} from "./release-provider-execute-dispatcher.js";

export async function createAwsExecuteDispatcherTransport({ credentials }) {
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
        exactDescribeChangeSetInput(input)));
    },
    async describeStacks(input) {
      return cloudformation.send(new DescribeStacksCommand(
        exactExecuteStackInput(input)));
    },
    async executeChangeSet(input) {
      return cloudformation.send(new ExecuteChangeSetCommand(
        exactExecuteChangeSetInput(input)));
    },
    async updateTerminationProtection(input) {
      return cloudformation.send(new UpdateTerminationProtectionCommand(
        exactTerminationProtectionInput(input)));
    }
  });
}
