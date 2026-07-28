"""
Handles Teams approval magic-link clicks (GET requests from Action.OpenUrl
buttons in an Adaptive Card). Verifies the HMAC signature + expiry embedded
in the URL, then executes through the same executor Lambda Slack uses -
there's exactly one execution path in this whole system, regardless of
which chat platform triggered it.
"""

import os
import json
import boto3

from notifiers import verify_magic_link

ACTIONS_TABLE_NAME = os.environ["ACTIONS_TABLE_NAME"]
EXECUTOR_FUNCTION_NAME = os.environ["EXECUTOR_FUNCTION_NAME"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
lambda_client = boto3.client("lambda", region_name=AWS_REGION)
table = dynamodb.Table(ACTIONS_TABLE_NAME)


def html_response(title, message, ok=True):
    color = "#2e7d32" if ok else "#c62828"
    body = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:-apple-system,sans-serif;max-width:480px;margin:80px auto;text-align:center;color:#222}}
h1{{color:{color}}}</style></head><body><h1>{title}</h1><p>{message}</p></body></html>"""
    return {"statusCode": 200, "headers": {"Content-Type": "text/html"}, "body": body}


def handler(event, context):
    params = event.get("queryStringParameters") or {}
    action_id = params.get("id")
    decision = params.get("decision")
    expires = params.get("expires")
    sig = params.get("sig")

    if not all([action_id, decision, expires, sig]) or decision not in ("approve", "reject"):
        return html_response("Invalid link", "This approval link is missing required information.", ok=False)

    if not verify_magic_link(action_id, decision, expires, sig):
        return html_response("Link expired or invalid", "This approval link has expired or isn't valid. Ask the agent to re-propose the action if it's still needed.", ok=False)

    item = table.get_item(Key={"action_id": action_id}).get("Item")
    if not item:
        return html_response("Not found", f"Couldn't find action `{action_id}` - it may have already been handled.", ok=False)

    if item.get("status") != "proposed":
        return html_response("Already handled", f"This action was already marked '{item.get('status')}' - no change made.", ok=True)

    if decision == "reject":
        table.update_item(
            Key={"action_id": action_id},
            UpdateExpression="SET #s = :s, decided_by = :u",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "rejected", ":u": "teams-magic-link"},
        )
        return html_response("Rejected", f"{item.get('action_type')} on {item.get('resource')} was rejected. Nothing was changed.")

    resp = lambda_client.invoke(
        FunctionName=EXECUTOR_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps({
            "action_id": action_id,
            "action_type": item["action_type"],
            "params": json.loads(item["params"]),
            "approved_by": "teams-magic-link",
        }).encode("utf-8"),
    )
    result = json.loads(resp["Payload"].read())
    ok = resp.get("StatusCode") == 200 and result.get("statusCode") == 200

    if ok:
        return html_response("Approved and executed", f"{item.get('action_type')} on {item.get('resource')} completed successfully.")
    else:
        return html_response("Approved, but execution failed", f"{item.get('action_type')} on {item.get('resource')} - {result}", ok=False)
