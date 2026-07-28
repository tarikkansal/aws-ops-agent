"""
Executor Lambda - the only component in this system with write credentials.

Invoked directly (not via Slack) for tier1_auto actions, and via
slack_interactions.py after an approval click for tier2_approval actions.

Deliberately dumb: no LLM call here, no free-form reasoning. It validates
action_type against the registry, assumes the narrowly-scoped write role,
executes, and logs the outcome. If action_type isn't in the registry, it
refuses - full stop, no interpretation.
"""

import os
import json
import time
import boto3
from datetime import datetime, timezone

from actions import ACTION_REGISTRY, validate_action

EXECUTOR_ROLE_ARN = os.environ["EXECUTOR_ROLE_ARN"]
ACTIONS_TABLE_NAME = os.environ["ACTIONS_TABLE_NAME"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

sts = boto3.client("sts")
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(ACTIONS_TABLE_NAME)


def assume_executor_role():
    resp = sts.assume_role(
        RoleArn=EXECUTOR_ROLE_ARN,
        RoleSessionName="aws-ops-agent-executor",
        ExternalId="aws-ops-agent-executor",
    )
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=AWS_REGION,
    )


def log_action(action_id, **fields):
    fields["action_id"] = action_id
    fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    update_expr = "SET " + ", ".join(f"#{k} = :{k}" for k in fields if k != "action_id")
    table.update_item(
        Key={"action_id": action_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={f"#{k}": k for k in fields if k != "action_id"},
        ExpressionAttributeValues={f":{k}": v for k, v in fields.items() if k != "action_id"},
    )


def handler(event, context):
    """
    event = {
        "action_id": "uuid",       # for logging/audit
        "action_type": "rds_stop_instance",
        "params": {"instance_id": "..."},
        "approved_by": "slack:U12345" | "auto"
    }
    """
    action_id = event.get("action_id", f"manual-{int(time.time())}")
    action_type = event.get("action_type")
    params = event.get("params", {})
    params.setdefault("timestamp", str(int(time.time())))
    approved_by = event.get("approved_by", "unknown")

    ok, err = validate_action(action_type, params)
    if not ok:
        log_action(action_id, status="rejected_invalid", error=err)
        return {"statusCode": 400, "body": json.dumps({"error": err})}

    classify_fn, execute_fn, _ = ACTION_REGISTRY[action_type]

    try:
        session = assume_executor_role()
    except Exception as e:
        log_action(action_id, status="failed", error=f"could not assume executor role: {e}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}

    # Re-check tier at execution time against the live resource - never trust
    # a tier decided earlier, in case tags changed between proposal and click.
    try:
        actual_tier = classify_fn(session, params)
    except Exception as e:
        log_action(action_id, status="failed", error=f"tier classification failed: {e}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}

    if actual_tier == "tier2_approval" and approved_by == "auto":
        # Someone/something tried to auto-execute a prod-tagged resource.
        # Hard stop - this should never happen if the digest logic is correct,
        # but the executor is the last line of defense, not the digest.
        log_action(action_id, status="blocked", error="tier2 action attempted without approval")
        return {"statusCode": 403, "body": json.dumps({"error": "tier2 action requires approval"})}

    log_action(action_id, status="executing", action_type=action_type, params=params, approved_by=approved_by)

    try:
        result = execute_fn(session, params)
        log_action(action_id, status="executed", result=result)
        return {"statusCode": 200, "body": json.dumps({"result": result})}
    except Exception as e:
        log_action(action_id, status="failed", error=str(e))
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
