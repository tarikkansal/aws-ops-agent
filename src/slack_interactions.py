"""
Handles Slack "Approve" / "Reject" button clicks for tier2_approval actions.

Exposed via API Gateway as the Slack app's Interactivity Request URL.
Every request is signature-verified against Slack's signing secret before
anything else happens - an unverified request is dropped, full stop.
"""

import os
import json
import time
import hmac
import hashlib
import urllib.parse
import urllib.request
import boto3

SLACK_SIGNING_SECRET_ARN = os.environ["SLACK_SIGNING_SECRET_ARN"]
ACTIONS_TABLE_NAME = os.environ["ACTIONS_TABLE_NAME"]
EXECUTOR_FUNCTION_NAME = os.environ["EXECUTOR_FUNCTION_NAME"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
ALLOWED_SLACK_USER_IDS = {u.strip() for u in os.environ.get("ALLOWED_SLACK_USER_IDS", "").split(",") if u.strip()}

secrets = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
lambda_client = boto3.client("lambda", region_name=AWS_REGION)
table = dynamodb.Table(ACTIONS_TABLE_NAME)

_signing_secret_cache = None


def get_signing_secret():
    global _signing_secret_cache
    if _signing_secret_cache is None:
        _signing_secret_cache = secrets.get_secret_value(SecretId=SLACK_SIGNING_SECRET_ARN)["SecretString"]
    return _signing_secret_cache


def verify_slack_signature(headers, raw_body):
    """Slack's documented HMAC verification. Returns False on anything
    unexpected - missing headers, stale timestamp, bad signature."""
    timestamp = headers.get("x-slack-request-timestamp")
    signature = headers.get("x-slack-signature")
    if not timestamp or not signature:
        return False

    # Reject requests older than 5 minutes - prevents replay of a captured request.
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    signing_secret = get_signing_secret()
    basestring = f"v0:{timestamp}:{raw_body}"
    computed = "v0=" + hmac.new(
        signing_secret.encode(), basestring.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def update_slack_message(response_url, text):
    payload = {"replace_original": "true", "text": text}
    req = urllib.request.Request(
        response_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10)


def handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw_body = event.get("body", "")
    if event.get("isBase64Encoded"):
        import base64
        raw_body = base64.b64decode(raw_body).decode("utf-8")

    if not verify_slack_signature(headers, raw_body):
        return {"statusCode": 401, "body": "invalid signature"}

    form = urllib.parse.parse_qs(raw_body)
    payload = json.loads(form["payload"][0])

    action = payload["actions"][0]
    decision = action["value"]  # "approve:<action_id>" or "reject:<action_id>"
    verb, action_id = decision.split(":", 1)
    user = payload["user"]["username"]
    user_id = payload["user"]["id"]
    response_url = payload["response_url"]

    item = table.get_item(Key={"action_id": action_id}).get("Item")
    if not item:
        update_slack_message(response_url, f"Couldn't find action `{action_id}` - it may have expired.")
        return {"statusCode": 200, "body": ""}

    if item.get("status") not in ("proposed",):
        update_slack_message(response_url, f"Action already {item.get('status')} - no change made.")
        return {"statusCode": 200, "body": ""}

    # Manual slash-command proposals: only the allowlist can confirm/cancel,
    # and the confirm window expires - a stale button shouldn't fire later.
    if item.get("tier") == "manual":
        if user_id not in ALLOWED_SLACK_USER_IDS:
            update_slack_message(response_url, f"@{user} isn't allowlisted to confirm manual commands.")
            return {"statusCode": 200, "body": ""}
        expires_at = item.get("expires_at")
        if expires_at and time.time() > float(expires_at):
            table.update_item(
                Key={"action_id": action_id},
                UpdateExpression="SET #s = :s",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":s": "expired"},
            )
            update_slack_message(response_url, "This confirmation window expired - re-run the command if still needed.")
            return {"statusCode": 200, "body": ""}

    if verb == "reject":
        table.update_item(
            Key={"action_id": action_id},
            UpdateExpression="SET #s = :s, decided_by = :u",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "rejected", ":u": user},
        )
        update_slack_message(response_url, f"Rejected by @{user}: {item.get('action_type')} on {item.get('resource')}")
        return {"statusCode": 200, "body": ""}

    # Approved - invoke the executor synchronously so we can report the real outcome.
    invoke_payload = {
        "action_id": action_id,
        "action_type": item["action_type"],
        "params": json.loads(item["params"]),
        "approved_by": f"slack:{user}",
    }
    resp = lambda_client.invoke(
        FunctionName=EXECUTOR_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(invoke_payload).encode("utf-8"),
    )
    result = json.loads(resp["Payload"].read())
    # resp["StatusCode"] is the Lambda INVOCATION status - it's 200 as long as
    # the function ran at all, even if the function's own logic returned a
    # failure. The real outcome is inside result["statusCode"], which is what
    # executor.py's handler actually returns (200 on success, 400/403/500 on
    # refusal or failure). Checking the wrong one is what caused this to
    # report "executed" for an AWS call that actually failed.
    ok = resp.get("StatusCode") == 200 and not result.get("errorMessage") and result.get("statusCode") == 200
    result_body = json.loads(result.get("body", "{}")) if isinstance(result.get("body"), str) else result.get("body", {})

    if ok:
        update_slack_message(response_url, f"Approved by @{user} and executed: {item.get('action_type')} on {item.get('resource')}")
    else:
        error_detail = result_body.get("error", result.get("errorMessage", "unknown error"))
        update_slack_message(response_url, f"Approved by @{user} but execution FAILED: {item.get('action_type')} on {item.get('resource')} - {error_detail}")

    return {"statusCode": 200, "body": ""}
