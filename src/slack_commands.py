"""
Handles the /aws slash command - lets a small allowlist of people type
commands like "stop-ec2 i-0123456789" directly. Reuses the exact same
DynamoDB proposal + Approve/Reject button flow as agent-proposed actions
(slack_interactions.py handles the click either way) - this file's only job
is: verify the request is really from Slack, check the caller is allowlisted,
parse the text into a whitelisted action_type + params, and post a
60-second-expiring confirm button.

Nothing in this file executes anything directly - execution only happens
after the confirm click, through the same executor Lambda as everything else.
"""

import os
import json
import time
import hmac
import hashlib
import uuid
import urllib.parse
import urllib.request
import boto3
from datetime import datetime, timezone

from actions import validate_action

SLACK_SIGNING_SECRET_ARN = os.environ["SLACK_SIGNING_SECRET_ARN"]
ACTIONS_TABLE_NAME = os.environ["ACTIONS_TABLE_NAME"]
DIGEST_FUNCTION_NAME = os.environ.get("DIGEST_FUNCTION_NAME", "aws-ops-agent-digest")
ALLOWED_SLACK_USER_IDS = {u.strip() for u in os.environ.get("ALLOWED_SLACK_USER_IDS", "").split(",") if u.strip()}
CONFIRM_WINDOW_SECONDS = 60

secrets = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"))
lambda_client = boto3.client("lambda", region_name=os.environ.get("AWS_REGION", "us-east-1"))
table = dynamodb.Table(ACTIONS_TABLE_NAME)

_signing_secret_cache = None


def get_signing_secret():
    global _signing_secret_cache
    if _signing_secret_cache is None:
        _signing_secret_cache = secrets.get_secret_value(SecretId=SLACK_SIGNING_SECRET_ARN)["SecretString"]
    return _signing_secret_cache


def verify_slack_signature(headers, raw_body):
    timestamp = headers.get("x-slack-request-timestamp")
    signature = headers.get("x-slack-signature")
    if not timestamp or not signature:
        return False
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False
    basestring = f"v0:{timestamp}:{raw_body}"
    computed = "v0=" + hmac.new(
        get_signing_secret().encode(), basestring.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


# Short command name -> (action_type, positional param names)
# Keep this in sync with actions.ACTION_REGISTRY - it's a display-friendly
# alias layer on top of the same whitelist, not a separate set of powers.
COMMAND_MAP = {
    "start-rds": ("rds_start_instance", ["instance_id"]),
    "stop-rds": ("rds_stop_instance", ["instance_id"]),
    "start-ec2": ("ec2_start_instance", ["instance_id"]),
    "stop-ec2": ("ec2_stop_instance", ["instance_id"]),
    "invalidate-cdn": ("cloudfront_create_invalidation", ["distribution_id", "paths"]),
}

HELP_TEXT = (
    "Usage: `/aws <command> <args>`\n"
    "Status: `digest` or `status` — pull a full AWS check-in into Slack now\n"
    "Actions: `start-rds <id>`, `stop-rds <id>`, `start-ec2 <id>`, `stop-ec2 <id>`, "
    "`invalidate-cdn <distribution_id> <comma,separated,paths>`\n"
    "IAM, KMS, VPC, and account/org settings are never available here - those stay manual by design."
)


def trigger_digest(response_url, user_name):
    """Kick off a full daily-mode digest asynchronously. Slack needs a response
    within 3s; the digest Lambda posts the table to the webhook when done."""
    try:
        lambda_client.invoke(
            FunctionName=DIGEST_FUNCTION_NAME,
            InvocationType="Event",  # async - don't wait for Bedrock
            Payload=json.dumps({"mode": "daily", "triggered_by": f"slack:@{user_name}"}).encode("utf-8"),
        )
        text = (
            f"Pulling a fresh AWS check-in now (requested by @{user_name}). "
            "The full table will post here in about 30–60 seconds."
        )
    except Exception as e:
        text = f"Couldn't start the digest: {e}"

    payload = {"response_type": "in_channel", "text": text}
    req = urllib.request.Request(
        response_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10)


def parse_command_text(text):
    """Returns (action_type, params, resource_label) or (None, None, error_message).
    Special case: action_type == '__digest__' means trigger a status report."""
    parts = text.strip().split()
    if not parts:
        return None, None, HELP_TEXT

    cmd, args = parts[0].lower(), parts[1:]
    if cmd in {"digest", "status", "check", "report"}:
        return "__digest__", {}, "digest"

    if cmd not in COMMAND_MAP:
        return None, None, f"Unknown command `{cmd}`.\n{HELP_TEXT}"

    action_type, param_names = COMMAND_MAP[cmd]
    if len(args) < len(param_names):
        return None, None, f"`{cmd}` needs: {', '.join(param_names)}\n{HELP_TEXT}"

    params = {}
    for name, value in zip(param_names, args):
        params[name] = value.split(",") if name == "paths" else value

    resource_label = args[0]
    return action_type, params, resource_label


def post_confirm_buttons(response_url, action_id, action_type, resource, user_name):
    payload = {
        "response_type": "in_channel",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"@{user_name} requested: `{action_type}` on *{resource}*\nConfirm within {CONFIRM_WINDOW_SECONDS}s:"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "Confirm"}, "style": "primary",
                 "value": f"approve:{action_id}", "action_id": "approve_action"},
                {"type": "button", "text": {"type": "plain_text", "text": "Cancel"}, "style": "danger",
                 "value": f"reject:{action_id}", "action_id": "reject_action"},
            ]},
        ],
    }
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
    user_id = form.get("user_id", [""])[0]
    user_name = form.get("user_name", ["unknown"])[0]
    text = form.get("text", [""])[0]
    response_url = form.get("response_url", [""])[0]

    if user_id not in ALLOWED_SLACK_USER_IDS:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"response_type": "ephemeral", "text": "You're not on the allowlist for this command."}),
        }

    action_type, params, error_or_label = parse_command_text(text)
    if action_type is None:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"response_type": "ephemeral", "text": error_or_label}),
        }

    if action_type == "__digest__":
        trigger_digest(response_url, user_name)
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": ""}

    ok, err = validate_action(action_type, params)
    if not ok:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"response_type": "ephemeral", "text": f"Invalid: {err}"}),
        }

    action_id = str(uuid.uuid4())
    now = time.time()
    table.put_item(Item={
        "action_id": action_id,
        "action_type": action_type,
        "resource": error_or_label,
        "params": json.dumps(params),
        "tier": "manual",
        "status": "proposed",
        "reason": f"Manual command from @{user_name}",
        "proposed_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": int(now + CONFIRM_WINDOW_SECONDS),
        "requested_by": user_id,
    })

    # Acknowledge immediately (Slack needs a response within 3s), then post
    # the real confirm buttons via response_url.
    post_confirm_buttons(response_url, action_id, action_type, error_or_label, user_name)

    return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": ""}
