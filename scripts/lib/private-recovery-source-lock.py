#!/usr/bin/env python3
import base64
import json
import re
import sys
import time
import urllib.parse


AUDIENCE = "prooftoact-private-recovery-source-lock-v1"
REPOSITORY = "Flash-Bri/prooftoact"
REPOSITORY_ID = "1317716765"
REPOSITORY_OWNER = "Flash-Bri"
REPOSITORY_OWNER_ID = "252500266"
SUBJECT_PREFIX = "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:"
LANES = {
    "deploy": (
        "aws-private-recovery-deploy",
        "ProofToAct Private Recovery Deploy",
        "prooftoact-private-recovery-deploy.yml",
        "prooftoact-sealed-private-recovery-deploy.yml",
    ),
    "evidence": (
        "aws-private-recovery-evidence",
        "ProofToAct Private Recovery Evidence",
        "prooftoact-private-recovery-evidence.yml",
        "prooftoact-sealed-private-recovery-evidence.yml",
    ),
    "query": (
        "aws-private-recovery-query",
        "ProofToAct Private Recovery Query",
        "prooftoact-private-recovery-query.yml",
        "prooftoact-sealed-private-recovery-query.yml",
    ),
    "secret-seal": (
        "aws-private-recovery-deploy",
        "ProofToAct Private Recovery Secret Seal",
        "prooftoact-private-recovery-secret-seal.yml",
        "prooftoact-sealed-private-recovery-secret-seal.yml",
    ),
    "teardown": (
        "aws-private-recovery-teardown",
        "ProofToAct Private Recovery Teardown",
        "prooftoact-private-recovery-teardown.yml",
        "prooftoact-sealed-private-recovery-teardown.yml",
    ),
}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
GITHUB_TOKEN_HOST = re.compile(
    r"^(?:pipelines|run-actions-[0-9]+-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"
    r"\.actions\.githubusercontent\.com$"
)
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$")
SAFE_JTI = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class Rejected(Exception):
    pass


def reject():
    raise Rejected()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            reject()
        result[key] = value
    return result


def strict_json(raw, maximum):
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        reject()
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, Rejected):
        reject()


def decode_base64url(segment, maximum):
    if (
        not isinstance(segment, str)
        or not segment
        or len(segment) > maximum
        or BASE64URL.fullmatch(segment) is None
        or len(segment) % 4 == 1
    ):
        reject()
    padded = segment + ("=" * ((4 - (len(segment) % 4)) % 4))
    try:
        decoded = base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeEncodeError):
        reject()
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != segment:
        reject()
    return decoded


def validate_audience(value):
    if value != AUDIENCE:
        reject()


def validate_endpoint(audience, value):
    validate_audience(audience)
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        reject()
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        reject()
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or host is None
        or GITHUB_TOKEN_HOST.fullmatch(host) is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not parsed.path
        or len(parsed.path) > 1536
        or SAFE_PATH.fullmatch(parsed.path) is None
        or "//" in parsed.path
    ):
        reject()
    if any(part in ("", ".", "..") for part in parsed.path.split("/")[1:]):
        reject()
    for index, character in enumerate(parsed.path):
        if character == "%" and (
            index + 2 >= len(parsed.path)
            or re.fullmatch(r"[0-9A-Fa-f]{2}", parsed.path[index + 1:index + 3])
            is None
        ):
            reject()
    try:
        query = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True
        )
    except ValueError:
        reject()
    if query != [("api-version", "2.0")]:
        reject()
    return value + "&audience=" + urllib.parse.quote(audience, safe="")


def validate_token_response(audience, lane, expected_commit, expected_tree, raw):
    validate_audience(audience)
    if lane not in LANES:
        reject()
    if HEX_40.fullmatch(expected_commit or "") is None:
        reject()
    if HEX_40.fullmatch(expected_tree or "") is None:
        reject()
    environment, workflow, caller_file, sealed_file = LANES[lane]
    response = strict_json(raw, 32768)
    if not isinstance(response, dict) or set(response) != {"value"}:
        reject()
    token = response["value"]
    if not isinstance(token, str) or not 1 <= len(token) <= 24576:
        reject()
    parts = token.split(".")
    if len(parts) != 3:
        reject()
    header = strict_json(decode_base64url(parts[0], 4096), 3072)
    payload = strict_json(decode_base64url(parts[1], 24576), 16384)
    decode_base64url(parts[2], 16384)
    if (
        not isinstance(header, dict)
        or set(header) != {"alg", "kid", "typ"}
        or header.get("alg") != "RS256"
        or header.get("typ") != "JWT"
        or not isinstance(header.get("kid"), str)
        or not 1 <= len(header["kid"]) <= 256
        or not isinstance(payload, dict)
    ):
        reject()
    workflow_prefix = "Flash-Bri/prooftoact/.github/workflows/"
    required_strings = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": AUDIENCE,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "repository_owner": REPOSITORY_OWNER,
        "repository_owner_id": REPOSITORY_OWNER_ID,
        "repository_visibility": "public",
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "environment": environment,
        "sub": SUBJECT_PREFIX + environment,
        "workflow": workflow,
        "workflow_ref": workflow_prefix + caller_file + "@refs/heads/main",
        "event_name": "workflow_dispatch",
        "runner_environment": "github-hosted",
        "job_workflow_ref": workflow_prefix + sealed_file + "@" + expected_commit,
        "job_workflow_sha": expected_commit,
    }
    for name, expected in required_strings.items():
        if payload.get(name) != expected or not isinstance(payload.get(name), str):
            reject()
    if "ref_protected" in payload and payload.get("ref_protected") != "true":
        reject()
    caller_sha = payload.get("sha")
    if (
        not isinstance(caller_sha, str)
        or HEX_40.fullmatch(caller_sha) is None
        or payload.get("workflow_sha") != caller_sha
    ):
        reject()
    now = int(time.time())
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    exp = payload.get("exp")
    if (
        isinstance(iat, bool)
        or not isinstance(iat, int)
        or isinstance(nbf, bool)
        or not isinstance(nbf, int)
        or isinstance(exp, bool)
        or not isinstance(exp, int)
        or iat < now - 600
        or iat > now + 60
        or nbf > now + 60
        or exp <= now
        or exp > now + 600
        or exp <= iat
    ):
        reject()
    jti = payload.get("jti")
    if not isinstance(jti, str) or SAFE_JTI.fullmatch(jti) is None:
        reject()
    for name, value in payload.items():
        if not isinstance(name, str) or isinstance(value, (dict, list)):
            reject()
    return "SOURCE_LOCKED:" + lane + ":" + expected_commit + ":" + expected_tree


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--validate-endpoint":
        output = validate_endpoint(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 6 and sys.argv[1] == "--validate-token":
        raw = sys.stdin.buffer.read(32769)
        output = validate_token_response(
            sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], raw
        )
    else:
        reject()
    sys.stdout.write(output + "\n")


try:
    main()
except (Rejected, BrokenPipeError):
    sys.stderr.write("PRIVATE_RECOVERY_SOURCE_LOCK_REJECTED\n")
    raise SystemExit(1)
