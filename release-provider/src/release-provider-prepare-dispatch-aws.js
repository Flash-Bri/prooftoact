import { CloudFormationClient } from
  "@aws-sdk/client-cloudformation/dist-es/CloudFormationClient.js";
import { CreateChangeSetCommand } from
  "@aws-sdk/client-cloudformation/dist-es/commands/CreateChangeSetCommand.js";
import { S3Client } from "@aws-sdk/client-s3/dist-es/S3Client.js";
import { GetObjectCommand } from
  "@aws-sdk/client-s3/dist-es/commands/GetObjectCommand.js";
import { HeadObjectCommand } from
  "@aws-sdk/client-s3/dist-es/commands/HeadObjectCommand.js";
import { PutObjectCommand } from
  "@aws-sdk/client-s3/dist-es/commands/PutObjectCommand.js";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { fixedSdkOptions } from "./release-provider-common.js";
import {
  exactChangeSetInput,
  exactObjectInput,
  exactReadInput
} from "./release-provider-prepare-dispatcher.js";

export async function createAwsPrepareDispatcherTransport({ credentials }) {
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
    async createChangeSet(input) {
      return cloudformation.send(new CreateChangeSetCommand(
        exactChangeSetInput(input)));
    },
    async getObject(input) {
      return s3.send(new GetObjectCommand(exactReadInput(input, false)));
    },
    async headObject(input) {
      return s3.send(new HeadObjectCommand(exactReadInput(input, true)));
    },
    async putObject(input) {
      return s3.send(new PutObjectCommand(exactObjectInput(input, true)));
    }
  });
}
