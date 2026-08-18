import { DynamoDBClient } from
  "@aws-sdk/client-dynamodb/dist-es/DynamoDBClient.js";
import { DescribeTableCommand } from
  "@aws-sdk/client-dynamodb/dist-es/commands/DescribeTableCommand.js";
import { GetItemCommand } from
  "@aws-sdk/client-dynamodb/dist-es/commands/GetItemCommand.js";
import { ListTagsOfResourceCommand } from
  "@aws-sdk/client-dynamodb/dist-es/commands/ListTagsOfResourceCommand.js";
import { STSClient } from "@aws-sdk/client-sts/dist-es/STSClient.js";
import { GetCallerIdentityCommand } from
  "@aws-sdk/client-sts/dist-es/commands/GetCallerIdentityCommand.js";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import {
  TABLE_NAME,
  exactKeys,
  fixedSdkOptions,
  requireCondition
} from "./release-provider-common.js";

export async function createAwsPreparePermitTransport({
  credentials,
  tableArn
}) {
  const match = /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u
    .exec(tableArn ?? "");
  requireCondition(match, "RELEASE_PROVIDER_TABLE_ARN_REJECTED");
  const requestHandler = new NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 10_000
  });
  const dynamodb = new DynamoDBClient({
    ...fixedSdkOptions("https://dynamodb.us-east-1.amazonaws.com", credentials),
    requestHandler
  });
  const sts = new STSClient({
    ...fixedSdkOptions("https://sts.us-east-1.amazonaws.com", credentials),
    requestHandler
  });
  return Object.freeze({
    async describeTable(input) {
      requireCondition(exactKeys(input, ["TableName"]) &&
        input.TableName === TABLE_NAME, "RELEASE_PROVIDER_DDB_INPUT_REJECTED");
      return dynamodb.send(new DescribeTableCommand(input));
    },
    async getCallerIdentity() {
      return sts.send(new GetCallerIdentityCommand({}));
    },
    async getIntentItem(input) {
      requireCondition(exactKeys(input, [
        "ConsistentRead", "Key", "ReturnConsumedCapacity", "TableName"
      ]) && input.ConsistentRead === true && input.TableName === TABLE_NAME &&
        input.ReturnConsumedCapacity === "NONE" &&
        exactKeys(input.Key, ["pk"]) && exactKeys(input.Key.pk, ["S"]) &&
        /^EFFECT#[0-9a-f]{64}$/u.test(input.Key.pk.S ?? ""),
      "RELEASE_PROVIDER_DDB_STRONG_READ_REJECTED");
      return dynamodb.send(new GetItemCommand(input));
    },
    async listTags(input) {
      requireCondition(exactKeys(input, ["ResourceArn"]) &&
        input.ResourceArn === tableArn,
      "RELEASE_PROVIDER_DDB_INPUT_REJECTED");
      return dynamodb.send(new ListTagsOfResourceCommand(input));
    }
  });
}
