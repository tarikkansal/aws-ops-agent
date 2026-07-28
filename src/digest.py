"""
AWS Ops Agent - digest Lambda.

Collects a full inventory + cost breakdown across your AWS account, asks
Claude (via Bedrock, forced tool-use for guaranteed structured output) to
summarize it in plain English for a non-technical reader, executes
whitelisted low-risk actions automatically, and posts a real status table
to Slack and/or Microsoft Teams (see notifiers.py) for anything else.

Everything company-specific is configuration (env vars set at deploy time
via the setup wizard), not hardcoded - this file has no knowledge of any
particular organization.
"""

import os
import json
import uuid
import boto3
from datetime import datetime, timedelta, timezone

from actions import ACTION_REGISTRY, validate_action
import notifiers

DEFAULT_MODE = os.environ.get("MODE", "hourly")
SPOKE_ROLE_ARNS = [a.strip() for a in os.environ.get("SPOKE_ROLE_ARNS", "").split(",") if a.strip()]
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
ACTIONS_TABLE_NAME = os.environ["ACTIONS_TABLE_NAME"]
EXECUTOR_FUNCTION_NAME = os.environ["EXECUTOR_FUNCTION_NAME"]

# --- Configuration set by the setup wizard - no org-specific values live in code ---
COMPANY_NAME = os.environ.get("COMPANY_NAME", "")  # optional, used only in the Slack header
EXPECTED_BUCKET_PREFIX = os.environ.get("EXPECTED_BUCKET_PREFIX", "")  # optional; empty = skip the check
BILLING_ALARM_NAME_FILTER = os.environ.get("BILLING_ALARM_NAME_FILTER", "")  # optional CloudWatch alarm name/prefix
BILLING_SNS_TOPIC_NAME_FILTER = os.environ.get("BILLING_SNS_TOPIC_NAME_FILTER", "")  # optional SNS topic name/prefix

sts = boto3.client("sts")
bedrock = boto3.client("bedrock-runtime", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
lambda_client = boto3.client("lambda", region_name=AWS_REGION)
actions_table = dynamodb.Table(ACTIONS_TABLE_NAME)


def assume_role(role_arn):
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="aws-ops-agent-collector",
        ExternalId="aws-ops-agent",
    )
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def collect_account(role_arn, mode):
    """Pull signals from a single AWS account. Every call is wrapped so one
    broken/unpermitted API doesn't take down the whole digest - failures are
    recorded per-signal in `errors` instead."""
    account_id = role_arn.split(":")[4]
    session = assume_role(role_arn)
    out = {"account_id": account_id, "errors": []}

    try:
        cw = session.client("cloudwatch", region_name=AWS_REGION)
        alarms = cw.describe_alarms(StateValue="ALARM", MaxRecords=50)
        out["cloudwatch_alarms"] = [
            {"name": a["AlarmName"], "metric": a.get("MetricName"), "reason": a.get("StateReason")}
            for a in alarms.get("MetricAlarms", [])
        ]
    except Exception as e:
        out["errors"].append(f"cloudwatch_alarms: {e}")

    try:
        ce = session.client("ce", region_name="us-east-1")
        lookback_days = 1 if mode == "hourly" else 7
        start = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
        end = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        anomalies = ce.get_anomalies(DateInterval={"StartDate": start, "EndDate": end})
        out["cost_anomalies"] = [
            {"service": a.get("DimensionValue"), "impact_usd": a.get("Impact", {}).get("TotalImpact")}
            for a in anomalies.get("Anomalies", [])
        ]
    except Exception as e:
        out["errors"].append(f"cost_anomalies: {e}")

    if mode == "daily":
        try:
            co = session.client("compute-optimizer", region_name=AWS_REGION)
            ec2_recs = co.get_ec2_instance_recommendations()
            out["rightsizing_recommendations"] = [
                {"instance_arn": r.get("instanceArn"), "finding": r.get("finding")}
                for r in ec2_recs.get("instanceRecommendations", [])
                if r.get("finding") not in (None, "OPTIMIZED")
            ]
        except Exception as e:
            out["errors"].append(f"compute_optimizer: {e}")

    try:
        ec2 = session.client("ec2", region_name=AWS_REGION)
        instances = ec2.describe_instances()
        states = {}
        for r in instances.get("Reservations", []):
            for i in r.get("Instances", []):
                states[i["State"]["Name"]] = states.get(i["State"]["Name"], 0) + 1
        out["ec2_inventory"] = states
    except Exception as e:
        out["errors"].append(f"ec2_inventory: {e}")

    try:
        rds = session.client("rds", region_name=AWS_REGION)
        dbs = rds.describe_db_instances()
        out["rds_inventory"] = [
            {"id": d["DBInstanceIdentifier"], "status": d["DBInstanceStatus"], "engine": d.get("Engine")}
            for d in dbs.get("DBInstances", [])
        ]
    except Exception as e:
        out["errors"].append(f"rds_inventory: {e}")

    try:
        s3 = session.client("s3", region_name=AWS_REGION)
        buckets = s3.list_buckets()
        out["s3_inventory"] = {
            "bucket_count": len(buckets.get("Buckets", [])),
            "bucket_names": [b["Name"] for b in buckets.get("Buckets", [])],
        }
    except Exception as e:
        out["errors"].append(f"s3_inventory: {e}")

    try:
        ses = session.client("sesv2", region_name=AWS_REGION)
        account = ses.get_account()
        out["ses_inventory"] = {
            "sending_enabled": account.get("SendingEnabled"),
            "max_send_rate": account.get("SendQuota", {}).get("MaxSendRate"),
            "sent_last_24h": account.get("SendQuota", {}).get("SentLast24Hours"),
        }
    except Exception as e:
        out["errors"].append(f"ses_inventory: {e}")

    try:
        cf = session.client("cloudfront", region_name="us-east-1")
        dists = cf.list_distributions()
        items = dists.get("DistributionList", {}).get("Items", [])
        out["cloudfront_inventory"] = [
            {"id": d["Id"], "domain": d.get("DomainName"), "status": d["Status"], "enabled": d["Enabled"]}
            for d in items
        ]
    except Exception as e:
        out["errors"].append(f"cloudfront_inventory: {e}")

    try:
        transfer = session.client("transfer", region_name=AWS_REGION)
        servers = transfer.list_servers()
        out["transfer_inventory"] = [
            {"id": s["ServerId"], "state": s["State"], "user_count": s.get("UserCount", 0)}
            for s in servers.get("Servers", [])
        ]
    except Exception as e:
        out["errors"].append(f"transfer_inventory: {e}")

    try:
        cognito = session.client("cognito-idp", region_name=AWS_REGION)
        pools = cognito.list_user_pools(MaxResults=20)
        pool_info = []
        for p in pools.get("UserPools", []):
            try:
                detail = cognito.describe_user_pool(UserPoolId=p["Id"])["UserPool"]
                pool_info.append({"name": p["Name"], "id": p["Id"], "estimated_users": detail.get("EstimatedNumberOfUsers", 0)})
            except Exception:
                pool_info.append({"name": p["Name"], "id": p["Id"], "estimated_users": "unknown"})
        out["cognito_inventory"] = pool_info
    except Exception as e:
        out["errors"].append(f"cognito_inventory: {e}")

    try:
        sm = session.client("secretsmanager", region_name=AWS_REGION)
        secrets_list = sm.list_secrets(MaxResults=50)
        out["secrets_inventory"] = [{"name": s["Name"]} for s in secrets_list.get("SecretList", [])]
    except Exception as e:
        out["errors"].append(f"secrets_inventory: {e}")

    try:
        acm = session.client("acm", region_name="us-east-1")
        certs = acm.list_certificates(CertificateStatuses=["ISSUED", "PENDING_VALIDATION", "EXPIRED", "VALIDATION_TIMED_OUT"])
        out["acm_inventory"] = [{"domain": c.get("DomainName"), "status": c.get("Status")} for c in certs.get("CertificateSummaryList", [])]
    except Exception as e:
        out["errors"].append(f"acm_inventory: {e}")

    try:
        cw = session.client("cloudwatch", region_name=AWS_REGION)
        prefix = BILLING_ALARM_NAME_FILTER or "billing"
        billing_alarms = cw.describe_alarms(AlarmNamePrefix=prefix) if BILLING_ALARM_NAME_FILTER else {"MetricAlarms": []}
        out["billing_alarm_inventory"] = [{"name": a["AlarmName"], "state": a["StateValue"]} for a in billing_alarms.get("MetricAlarms", [])]
    except Exception as e:
        out["errors"].append(f"billing_alarm_inventory: {e}")

    try:
        sns = session.client("sns", region_name=AWS_REGION)
        topics = sns.list_topics()
        matches = [t["TopicArn"] for t in topics.get("Topics", []) if BILLING_SNS_TOPIC_NAME_FILTER and BILLING_SNS_TOPIC_NAME_FILTER in t["TopicArn"]]
        topic_info = []
        for arn in matches:
            attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
            topic_info.append({"arn": arn, "subscription_count": attrs.get("SubscriptionsConfirmed", "0")})
        out["sns_billing_inventory"] = topic_info
    except Exception as e:
        out["errors"].append(f"sns_billing_inventory: {e}")

    try:
        iam_client = session.client("iam")
        summary = iam_client.get_account_summary()["SummaryMap"]
        out["iam_inventory"] = {"users": summary.get("Users", 0), "roles": summary.get("Roles", 0)}
    except Exception as e:
        out["errors"].append(f"iam_inventory: {e}")

    try:
        r53 = session.client("route53")
        zones = r53.list_hosted_zones()
        out["route53_inventory"] = [{"name": z["Name"]} for z in zones.get("HostedZones", [])]
    except Exception as e:
        out["errors"].append(f"route53_inventory: {e}")

    try:
        health = session.client("health", region_name="us-east-1")
        events = health.describe_events(filter={"eventStatusCodes": ["open", "upcoming"]})
        out["health_events"] = [{"service": e.get("service"), "type": e.get("eventTypeCode")} for e in events.get("events", [])]
    except Exception as e:
        out["errors"].append(f"health_events: {e}")

    try:
        ce = session.client("ce", region_name="us-east-1")
        month_start = datetime.now(timezone.utc).strftime("%Y-%m-01")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        usage_data = ce.get_cost_and_usage(
            TimePeriod={"Start": month_start, "End": today},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            Filter={"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Usage"]}},
        )
        groups = usage_data.get("ResultsByTime", [{}])[0].get("Groups", [])
        out["cost_by_service"] = sorted(
            [{"service": g["Keys"][0], "amount_usd": round(float(g["Metrics"]["UnblendedCost"]["Amount"]), 2)} for g in groups],
            key=lambda x: -x["amount_usd"],
        )[:10]
        out["cost_gross_usage_total"] = round(sum(g["amount_usd"] for g in out["cost_by_service"]), 2)

        credit_data = ce.get_cost_and_usage(
            TimePeriod={"Start": month_start, "End": today},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            Filter={"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Credit"]}},
        )
        credit_amount = float(credit_data.get("ResultsByTime", [{}])[0].get("Total", {}).get("UnblendedCost", {}).get("Amount", 0))
        out["cost_credits_applied"] = round(credit_amount, 2)
        out["cost_net_total"] = round(out["cost_gross_usage_total"] + out["cost_credits_applied"], 2)
    except Exception as e:
        out["errors"].append(f"cost_by_service: {e}")

    return out


def ask_claude_for_digest(collected, mode):
    """Returns a dict with opening_line, service_status, and proposed_actions
    via forced Bedrock tool-use - guaranteed valid structured JSON, no
    string/marker parsing that could silently truncate or fail."""

    whitelist_desc = "\n".join(f"  - {name}: requires params {info[2]}" for name, info in ACTION_REGISTRY.items())
    bucket_rule = (
        f"If any bucket name doesn't start with '{EXPECTED_BUCKET_PREFIX}', severity WARNING and "
        f"name it specifically in the note (e.g. an unexpected bucket)."
        if EXPECTED_BUCKET_PREFIX else
        "Just name the actual bucket names - no naming-convention check is configured."
    )

    system_prompt = (
        "You are summarizing AWS account activity for a NON-TECHNICAL business owner - "
        "not an engineer. Avoid jargon (don't say 'CloudWatch alarm', say 'a warning light'; "
        "don't say 'ALARM state', say 'needs attention'). Be SPECIFIC, not generic: always name "
        "the actual resource (bucket names, the RDS instance ID, the CloudFront domain) rather than "
        "just a count, wherever that data is available. Keep each note under 20 words.\n\n"
        "CRITICAL RULE about stopped resources: if an RDS instance or EC2 instance shows status "
        "'stopped', that is very likely INTENTIONAL - someone paused it deliberately to save cost. "
        "A stopped resource is NOT a problem to fix. Mark its severity OK (not WARNING), and NEVER "
        "propose starting it back up (rds_start_instance / ec2_start_instance) just because it's "
        "stopped. Only propose STOP actions for resources that are running and look idle or wasteful "
        "- never propose START actions preemptively, on any run.\n\n"
        "You may propose follow-up actions ONLY from this exact whitelist - never anything else:\n"
        f"{whitelist_desc}\n\n"
        "Call the submit_digest tool exactly once with your findings - do not output any text outside "
        "the tool call. It takes three fields:\n\n"
        "1. opening_line: one friendly opening line (max 15 words).\n\n"
        "2. service_status: an array covering EVERY service present in the collected data. Each item "
        "has \"service\" (plain name, e.g. 'File storage (S3)'), \"status\" (a real, meaningful state "
        "word specific to that service - e.g. 'Running', 'Stopped', 'Available', 'Disabled', 'Active', "
        "'Sending', 'Healthy' - NEVER the generic word 'OK'), \"severity\" (OK|WARNING|ERROR, internal "
        "urgency only, never shown), and \"note\" (specific, names real resources, under 20 words). "
        "Always include ALL of these rows:\n"
        "  - \"Servers (EC2)\": status names the real state; name any running instance IDs.\n"
        "  - \"Databases (RDS)\": status is 'Available' or 'Stopped'; name the instance identifier(s) "
        "and engine. If stopped, severity OK, and note that storage costs continue even while stopped.\n"
        f"  - \"File storage (S3)\": status 'Active'; name the actual bucket names. {bucket_rule}\n"
        "  - \"Email sending (SES)\": status 'Sending'/'Sandbox'/'Disabled'; mention volume.\n"
        "  - \"Content delivery (CDN)\": status 'Active'/'Deployed'; name the CloudFront domain(s).\n"
        "  - \"User auth (Cognito)\": status 'Active' or 'None configured'; name the pool and user count.\n"
        "  - \"Secrets (Secrets Manager)\": status 'Stored' or 'None'; name the secret name(s).\n"
        "  - \"File transfer (SFTP)\": if transfer_inventory is empty, status 'Disabled', severity OK. "
        "If a server exists and is ONLINE with 0 users, status 'Idle', severity WARNING (billing with "
        "no users). Otherwise status 'Active', severity OK. Name the server ID and user count.\n"
        "  - \"SSL certificate (ACM)\": status is the real certificate status; name the domain.\n"
        "  - \"Billing alerts\": status 'Configured' or 'Not configured'; severity WARNING only if "
        "billing_alarm_inventory/sns_billing_inventory data was actually collected and empty - if no "
        "filter is configured at all, just say 'Not configured' at severity OK.\n"
        "  - \"Access control (IAM)\": status 'Configured'; mention user/role counts. Severity OK, "
        "visibility only.\n"
        "  - \"Domains (Route 53)\": status 'Configured' or 'None configured'; name any hosted zones. "
        "Severity OK, visibility only.\n"
        "  - \"AWS service health\": status 'Healthy' or 'Incident'; note any open AWS Health events.\n"
        "  - \"Monthly costs\": ALWAYS PUT THIS ROW LAST. status 'Tracked'; severity OK unless spend "
        "looks unusual. Dollar totals are shown in separate columns, so don't repeat them - instead, "
        "in the note, mention if credits are offsetting the bill and name the top 2-3 services by "
        "spend.\n\n"
        "3. proposed_actions: an array of any suggested actions, each with \"action_type\" (one of "
        "the whitelist names above), \"resource\" (human-readable name), \"params\" (exact params "
        "required by that action_type), and \"reason\" (plain English, max 12 words). Empty array if "
        "none apply - never propose an action_type outside the whitelist."
    )

    user_prompt = f"Mode: {mode}\n\nCollected signals:\n{json.dumps(collected, indent=2, default=str)}"

    submit_digest_tool = {
        "name": "submit_digest",
        "description": "Submit the completed AWS status digest for this run.",
        "input_schema": {
            "type": "object",
            "required": ["opening_line", "service_status", "proposed_actions"],
            "properties": {
                "opening_line": {"type": "string"},
                "service_status": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["service", "status", "severity", "note"],
                        "properties": {
                            "service": {"type": "string"},
                            "status": {"type": "string"},
                            "severity": {"type": "string", "enum": ["OK", "WARNING", "ERROR"]},
                            "note": {"type": "string"},
                        },
                    },
                },
                "proposed_actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["action_type", "resource", "params", "reason"],
                        "properties": {
                            "action_type": {"type": "string"},
                            "resource": {"type": "string"},
                            "params": {"type": "object"},
                            "reason": {"type": "string"},
                        },
                    },
                },
            },
        },
    }

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
        "tools": [submit_digest_tool],
        "tool_choice": {"type": "tool", "name": "submit_digest"},
    }

    resp = bedrock.invoke_model(modelId=BEDROCK_MODEL_ID, body=json.dumps(body))
    payload = json.loads(resp["body"].read())

    for block in payload.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "submit_digest":
            return block.get("input", {})

    print(f"NO_TOOL_USE_IN_RESPONSE: {json.dumps(payload)}")
    return {"opening_line": "Digest generation failed this run - check logs", "service_status": [], "proposed_actions": []}


STATUS_WORD = {"OK": "OK", "WARNING": "NEEDS ATTENTION", "ERROR": "PROBLEM"}  # fallback only


def rich_text_cell(text, bold=False):
    return {"type": "rich_text", "elements": [{"type": "rich_text_section", "elements": [{"type": "text", "text": text, "style": {"bold": True} if bold else {}}]}]}


def raw_cell(text):
    return {"type": "raw_text", "text": text}


# Universal, service-level descriptions - true for any AWS account, not
# specific to any company. This is what makes the product genuinely
# self-serve: nobody has to write per-org copy for this column.
SERVICE_PURPOSE = {
    "Servers (EC2)": "Virtual servers / general compute",
    "Databases (RDS)": "Managed relational database",
    "File storage (S3)": "Object / file storage",
    "Email sending (SES)": "Transactional or marketing email",
    "Content delivery (CDN)": "Content delivery network (CloudFront)",
    "User auth (Cognito)": "User authentication and identity management",
    "Secrets (Secrets Manager)": "Stores application secrets and credentials",
    "File transfer (SFTP)": "Hosted SFTP/FTP file transfer",
    "SSL certificate (ACM)": "SSL/TLS certificate management",
    "Billing alerts": "Cost threshold alarm and notification",
    "Access control (IAM)": "Account users, roles, and permissions",
    "Domains (Route 53)": "DNS and domain management",
    "AWS service health": "AWS-wide incidents affecting this account",
    "Monthly costs": "Overall account spend",
}

COST_SERVICE_MAP = {
    "Servers (EC2)": ["Elastic Compute Cloud"],
    "Databases (RDS)": ["Relational Database Service"],
    "File storage (S3)": ["Simple Storage Service"],
    "Email sending (SES)": ["Simple Email Service"],
    "Content delivery (CDN)": ["CloudFront"],
    "User auth (Cognito)": ["Cognito"],
    "Secrets (Secrets Manager)": ["Secrets Manager"],
    "File transfer (SFTP)": ["Transfer Family"],
    "SSL certificate (ACM)": ["Certificate Manager"],
    "Domains (Route 53)": ["Route 53"],
}


def compute_cost_columns(collected):
    account = (collected.get("accounts") or [{}])[0]
    cost_by_service = account.get("cost_by_service", [])
    gross_total = account.get("cost_gross_usage_total")
    days_elapsed = max(datetime.now(timezone.utc).day, 1)

    columns = {}
    for row_name, keywords in COST_SERVICE_MAP.items():
        mtd = sum(c["amount_usd"] for c in cost_by_service if any(k.lower() in c.get("service", "").lower() for k in keywords))
        columns[row_name] = {"mtd": round(mtd, 2), "per_day": round(mtd / days_elapsed, 2)}

    if gross_total is not None:
        columns["Monthly costs"] = {"mtd": gross_total, "per_day": round(gross_total / days_elapsed, 2)}

    return columns


def format_dollar_cell(cost_columns, row_name, key):
    entry = cost_columns.get(row_name)
    if not entry or entry.get(key) is None:
        return "-"
    return f"${entry[key]:.2f}"


def build_status_table_block(service_status, cost_columns):
    if not service_status:
        return None

    header_row = [
        rich_text_cell("Service", bold=True),
        rich_text_cell("Status", bold=True),
        rich_text_cell("Cost/Day", bold=True),
        rich_text_cell("Cost MTD", bold=True),
        rich_text_cell("What it's for", bold=True),
        rich_text_cell("Notes", bold=True),
    ]
    rows = [header_row]
    for s in service_status:
        row_name = s.get("service", "Unknown")
        rows.append([
            raw_cell(row_name),
            raw_cell(s.get("status", "")),
            raw_cell(format_dollar_cell(cost_columns, row_name, "per_day")),
            raw_cell(format_dollar_cell(cost_columns, row_name, "mtd")),
            raw_cell(SERVICE_PURPOSE.get(row_name, "-")),
            raw_cell(s.get("note", "")),
        ])

    return {"type": "table", "rows": rows}


def order_with_costs_last(service_status):
    costs = [s for s in service_status if "cost" in s.get("service", "").lower()]
    others = [s for s in service_status if "cost" not in s.get("service", "").lower()]
    for c in costs:
        note = c.get("note", "")
        if "lag" not in note.lower() and "delay" not in note.lower():
            c["note"] = f"{note} (cost data can lag 24-48h behind the AWS Billing page)"
    return others + costs


def overall_emoji(service_status):
    statuses = {s.get("severity", "").upper() for s in service_status}
    if "ERROR" in statuses:
        return "🔴"
    if "WARNING" in statuses:
        return "🟡"
    return "🟢"


def post_approval_request(action_id, action_type, resource, reason):
    notifiers.post_approval_request(action_id, action_type, resource, reason)


def post_digest_notification(opening_line, emoji, service_status, cost_columns, table_block, action_results, mode):
    notifiers.post_digest(
        opening_line, emoji, service_status, cost_columns, table_block, action_results, mode,
        COMPANY_NAME, format_dollar_fn=format_dollar_cell, purpose_map=SERVICE_PURPOSE,
    )



def get_read_session_for_account(role_arn):
    return assume_role(role_arn)


def dispatch_proposed_actions(proposed_actions, spoke_role_arns):
    """Structural rule enforced in code: the automated digest never proposes
    turning something back on - starting a stopped resource must always come
    from an explicit human /aws command, never model inference."""
    AUTOMATION_BLOCKED_ACTIONS = {"rds_start_instance", "ec2_start_instance"}

    results = []
    read_session = get_read_session_for_account(spoke_role_arns[0]) if spoke_role_arns else None

    for proposed in proposed_actions:
        action_type = proposed.get("action_type")
        params = proposed.get("params", {})
        resource = proposed.get("resource", "unknown resource")
        reason = proposed.get("reason", "")

        if action_type in AUTOMATION_BLOCKED_ACTIONS:
            results.append(f"Skipped: automated proposal to '{action_type}' on {resource} - starting a stopped resource requires an explicit /aws command.")
            continue

        ok, err = validate_action(action_type, params)
        if not ok:
            results.append(f"Skipped invalid proposal ({action_type}): {err}")
            continue

        action_id = str(uuid.uuid4())
        classify_fn, _, _ = ACTION_REGISTRY[action_type]
        try:
            tier = classify_fn(read_session, params) if read_session else "tier2_approval"
        except Exception as e:
            results.append(f"Could not classify tier for {action_type} on {resource}: {e}")
            continue

        actions_table.put_item(Item={
            "action_id": action_id, "action_type": action_type, "resource": resource,
            "params": json.dumps(params), "tier": tier, "status": "proposed", "reason": reason,
            "proposed_at": datetime.now(timezone.utc).isoformat(),
        })

        if tier == "tier1_auto":
            resp = lambda_client.invoke(
                FunctionName=EXECUTOR_FUNCTION_NAME, InvocationType="RequestResponse",
                Payload=json.dumps({"action_id": action_id, "action_type": action_type, "params": params, "approved_by": "auto"}).encode("utf-8"),
            )
            body = json.loads(resp["Payload"].read())
            if resp.get("StatusCode") == 200 and body.get("statusCode") == 200:
                results.append(f"Auto-executed: {action_type} on {resource} ({reason})")
            else:
                results.append(f"Auto-exec FAILED: {action_type} on {resource} - {body}")
        else:
            post_approval_request(action_id, action_type, resource, reason)
            results.append(f"Pending approval in Slack: {action_type} on {resource} ({reason})")

    return results


def handler(event, context):
    if not SPOKE_ROLE_ARNS:
        raise RuntimeError("SPOKE_ROLE_ARNS env var is empty - set at least one account role ARN")

    mode = (event or {}).get("mode", DEFAULT_MODE)

    collected = {"mode": mode, "generated_at": datetime.now(timezone.utc).isoformat(), "accounts": []}
    for role_arn in SPOKE_ROLE_ARNS:
        collected["accounts"].append(collect_account(role_arn, mode))

    result = ask_claude_for_digest(collected, mode)
    opening_line = result.get("opening_line", "")
    service_status = order_with_costs_last(result.get("service_status", []))
    proposed_actions = result.get("proposed_actions", [])

    action_results = dispatch_proposed_actions(proposed_actions, SPOKE_ROLE_ARNS) if proposed_actions else []

    has_warning_or_error = any(s.get("severity", "").upper() != "OK" for s in service_status)
    should_post = mode == "daily" or has_warning_or_error or bool(action_results)

    if should_post:
        emoji = overall_emoji(service_status)
        cost_columns = compute_cost_columns(collected)
        table_block = build_status_table_block(service_status, cost_columns)
        post_digest_notification(opening_line, emoji, service_status, cost_columns, table_block, action_results, mode)
        posted = True
    else:
        posted = False

    return {"statusCode": 200, "body": json.dumps({"posted": posted, "mode": mode, "actions_proposed": len(proposed_actions)})}
