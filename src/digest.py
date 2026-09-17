"""
AWS Ops Agent - Phase 2 (read-only digest + whitelisted actions)

Triggered on two schedules via EventBridge Scheduler:
  MODE=hourly  -> lightweight scan, posts to Slack only if something notable is found
  MODE=daily   -> full digest, always posts

Flow: assume role into each spoke account -> collect signals -> ask Claude (Bedrock)
to correlate + summarize + propose actions from the whitelist -> tier1 actions
execute immediately via the executor Lambda, tier2 actions post to Slack with
Approve/Reject buttons and wait for a human click.

Claude never calls AWS directly and never decides tier - it only proposes an
action_type + params from actions.ACTION_REGISTRY. Tier is decided in code by
checking the live resource's tags (see actions.py).
"""

import os
import json
import uuid
import boto3
from datetime import datetime, timedelta, timezone

from actions import ACTION_REGISTRY, validate_action
import notifiers

DEFAULT_MODE = os.environ.get("MODE", "hourly")  # fallback for manual/local invokes
SPOKE_ROLE_ARNS = [a.strip() for a in os.environ.get("SPOKE_ROLE_ARNS", "").split(",") if a.strip()]
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
ACTIONS_TABLE_NAME = os.environ["ACTIONS_TABLE_NAME"]
EXECUTOR_FUNCTION_NAME = os.environ["EXECUTOR_FUNCTION_NAME"]

# --- Configuration set by the setup wizard - no org-specific values live in code ---
COMPANY_NAME = os.environ.get("COMPANY_NAME", "")  # optional, used only in the message header
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
    """Pull signals from a single spoke account. Never raises - failures are
    recorded per-signal so one broken API call doesn't kill the whole digest."""
    account_id = role_arn.split(":")[4]
    session = assume_role(role_arn)
    out = {"account_id": account_id, "errors": []}

    # --- CloudWatch alarms currently in ALARM state ---
    # Target-tracking Auto Scaling "AlarmLow" (CPU under target) fires almost
    # continuously on quiet apps - that is NORMAL, not an outage. We still
    # collect them, but tag them so the digest doesn't yellow-alert the owner
    # or invent bogus remediations (e.g. CloudFront invalidations).
    try:
        cw = session.client("cloudwatch", region_name=AWS_REGION)
        alarms = cw.describe_alarms(StateValue="ALARM", MaxRecords=50)
        parsed = []
        for a in alarms.get("MetricAlarms", []):
            name = a.get("AlarmName", "")
            dims = {d["Name"]: d["Value"] for d in a.get("Dimensions", [])}
            is_scale_low = (
                "AlarmLow" in name
                or name.startswith("TargetTracking-")
                and "Low" in name
            )
            parsed.append({
                "name": name,
                "metric": a.get("MetricName"),
                "namespace": a.get("Namespace"),
                "dimensions": dims,
                "reason": a.get("StateReason"),
                "since": a.get("StateUpdatedTimestamp").isoformat() if a.get("StateUpdatedTimestamp") else None,
                "kind": "scale_low" if is_scale_low else "actionable",
            })
        out["cloudwatch_alarms"] = parsed
        out["alarm_summary"] = {
            "actionable": [a for a in parsed if a["kind"] == "actionable"],
            "scale_low": [a for a in parsed if a["kind"] == "scale_low"],
        }
    except Exception as e:
        out["errors"].append(f"cloudwatch_alarms: {e}")

    # --- Cost anomalies (last 24h for hourly, 7d for daily) ---
    try:
        ce = session.client("ce", region_name="us-east-1")  # Cost Explorer is us-east-1 only
        lookback_days = 1 if mode == "hourly" else 7
        start = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
        end = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        anomalies = ce.get_anomalies(DateInterval={"StartDate": start, "EndDate": end})
        out["cost_anomalies"] = [
            {
                "service": a.get("DimensionValue"),
                "impact_usd": a.get("Impact", {}).get("TotalImpact"),
                "start": a.get("AnomalyStartDate"),
            }
            for a in anomalies.get("Anomalies", [])
        ]
    except Exception as e:
        out["errors"].append(f"cost_anomalies: {e}")

    # --- Compute Optimizer recommendations (daily only - doesn't change hourly) ---
    if mode == "daily":
        try:
            co = session.client("compute-optimizer", region_name=AWS_REGION)
            ec2_recs = co.get_ec2_instance_recommendations()
            out["rightsizing_recommendations"] = [
                {
                    "instance_arn": r.get("instanceArn"),
                    "finding": r.get("finding"),
                }
                for r in ec2_recs.get("instanceRecommendations", [])
                if r.get("finding") not in (None, "OPTIMIZED")
            ]
        except Exception as e:
            out["errors"].append(f"compute_optimizer: {e}")

    # --- AWS Health events (requires Business/Enterprise support for full account-level events) ---
    try:
        health = session.client("health", region_name="us-east-1")
        events = health.describe_events(
            filter={"eventStatusCodes": ["open", "upcoming"]}
        )
        out["health_events"] = [
            {"service": e.get("service"), "type": e.get("eventTypeCode")}
            for e in events.get("events", [])
        ]
    except Exception as e:
        out["errors"].append(f"health_events: {e}")

    # --- Service inventory: what's actually running, service by service.
    # This is what powers the "every service you use" table - independent of
    # whether anything is wrong with it. ---
    try:
        ec2 = session.client("ec2", region_name=AWS_REGION)
        instances = ec2.describe_instances()
        states = {}
        for r in instances.get("Reservations", []):
            for i in r.get("Instances", []):
                states[i["State"]["Name"]] = states.get(i["State"]["Name"], 0) + 1
        out["ec2_inventory"] = states  # e.g. {"running": 2, "stopped": 1}
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
        all_names = [b["Name"] for b in buckets.get("Buckets", [])]
        # SAM CLI auto-creates a deployment-artifact bucket per account/region
        # (aws-sam-cli-managed-default-...) - it's tooling infra this project
        # itself relies on, not an unexpected customer resource, so exclude
        # it here rather than having Claude flag it as a WARNING every run.
        visible_names = [n for n in all_names if not n.startswith("aws-sam-cli-managed-")]
        out["s3_inventory"] = {
            "bucket_count": len(visible_names),
            "bucket_names": visible_names,
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
            "production_access": not account.get("Details", {}).get("SuppressionAttributes") is None,
        }
    except Exception as e:
        out["errors"].append(f"ses_inventory: {e}")

    try:
        cf = session.client("cloudfront", region_name="us-east-1")  # CloudFront API is global/us-east-1
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
                pool_info.append({
                    "name": p["Name"],
                    "id": p["Id"],
                    "estimated_users": detail.get("EstimatedNumberOfUsers", 0),
                })
            except Exception:
                pool_info.append({"name": p["Name"], "id": p["Id"], "estimated_users": "unknown"})
        out["cognito_inventory"] = pool_info
    except Exception as e:
        out["errors"].append(f"cognito_inventory: {e}")

    try:
        sm = session.client("secretsmanager", region_name=AWS_REGION)
        secrets = sm.list_secrets(MaxResults=50)
        out["secrets_inventory"] = [
            {"name": s["Name"], "last_changed": str(s.get("LastChangedDate", ""))}
            for s in secrets.get("SecretList", [])
        ]
    except Exception as e:
        out["errors"].append(f"secrets_inventory: {e}")

    try:
        acm = session.client("acm", region_name="us-east-1")  # ACM certs for CloudFront must be us-east-1
        certs = acm.list_certificates(CertificateStatuses=["ISSUED", "PENDING_VALIDATION", "EXPIRED", "VALIDATION_TIMED_OUT"])
        cert_info = []
        for c in certs.get("CertificateSummaryList", []):
            cert_info.append({"domain": c.get("DomainName"), "status": c.get("Status")})
        out["acm_inventory"] = cert_info
    except Exception as e:
        out["errors"].append(f"acm_inventory: {e}")

    try:
        cw = session.client("cloudwatch", region_name=AWS_REGION)
        billing_alarms = cw.describe_alarms(AlarmNamePrefix=BILLING_ALARM_NAME_FILTER) if BILLING_ALARM_NAME_FILTER else {"MetricAlarms": []}
        out["billing_alarm_inventory"] = [
            {"name": a["AlarmName"], "state": a["StateValue"]}
            for a in billing_alarms.get("MetricAlarms", [])
        ]
    except Exception as e:
        out["errors"].append(f"billing_alarm_inventory: {e}")

    try:
        sns = session.client("sns", region_name=AWS_REGION)
        topics = sns.list_topics()
        billing_topics = [t["TopicArn"] for t in topics.get("Topics", []) if BILLING_SNS_TOPIC_NAME_FILTER and BILLING_SNS_TOPIC_NAME_FILTER in t["TopicArn"]]
        topic_info = []
        for arn in billing_topics:
            attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
            topic_info.append({"arn": arn, "subscription_count": attrs.get("SubscriptionsConfirmed", "0")})
        out["sns_billing_inventory"] = topic_info
    except Exception as e:
        out["errors"].append(f"sns_billing_inventory: {e}")

    try:
        iam_client = session.client("iam")  # IAM is a global service, no region needed
        summary = iam_client.get_account_summary()["SummaryMap"]
        out["iam_inventory"] = {"users": summary.get("Users", 0), "roles": summary.get("Roles", 0)}
    except Exception as e:
        out["errors"].append(f"iam_inventory: {e}")

    try:
        r53 = session.client("route53")  # Route 53 is a global service, no region needed
        zones = r53.list_hosted_zones()
        out["route53_inventory"] = [{"name": z["Name"], "id": z["Id"]} for z in zones.get("HostedZones", [])]
    except Exception as e:
        out["errors"].append(f"route53_inventory: {e}")

    # --- App Runner / ECS / Lambda: compute platforms that come and go.
    # Collected every run so the digest table picks them up without a code
    # change the next time you stand one up (or tear one down). ---
    try:
        apprunner = session.client("apprunner", region_name=AWS_REGION)
        services = apprunner.list_services().get("ServiceSummaryList", [])
        out["apprunner_inventory"] = [
            {
                "name": s.get("ServiceName"),
                "arn": s.get("ServiceArn"),
                "status": s.get("Status"),
                "url": s.get("ServiceUrl"),
            }
            for s in services
        ]
    except Exception as e:
        out["errors"].append(f"apprunner_inventory: {e}")

    try:
        ecs = session.client("ecs", region_name=AWS_REGION)
        cluster_arns = ecs.list_clusters().get("clusterArns", [])
        clusters = []
        if cluster_arns:
            desc = ecs.describe_clusters(clusters=cluster_arns).get("clusters", [])
            for c in desc:
                cluster_name = c.get("clusterName") or c.get("clusterArn")
                service_arns = []
                try:
                    service_arns = ecs.list_services(cluster=c["clusterArn"]).get("serviceArns", [])
                except Exception:
                    pass
                service_summaries = []
                if service_arns:
                    try:
                        for svc in ecs.describe_services(
                            cluster=c["clusterArn"], services=service_arns[:10]
                        ).get("services", []):
                            service_summaries.append({
                                "name": svc.get("serviceName"),
                                "status": svc.get("status"),
                                "desired": svc.get("desiredCount"),
                                "running": svc.get("runningCount"),
                            })
                    except Exception:
                        pass
                clusters.append({
                    "name": cluster_name,
                    "status": c.get("status"),
                    "active_services": c.get("activeServicesCount", 0),
                    "running_tasks": c.get("runningTasksCount", 0),
                    "services": service_summaries,
                })
        out["ecs_inventory"] = clusters
    except Exception as e:
        out["errors"].append(f"ecs_inventory: {e}")

    try:
        lam = session.client("lambda", region_name=AWS_REGION)
        functions = []
        marker = None
        while True:
            kwargs = {"MaxItems": 50}
            if marker:
                kwargs["Marker"] = marker
            page = lam.list_functions(**kwargs)
            for f in page.get("Functions", []):
                # Skip this agent's own Lambdas so the digest doesn't treat
                # ops tooling as product compute.
                name = f.get("FunctionName", "")
                if name.startswith("aws-ops-agent-"):
                    continue
                functions.append({
                    "name": name,
                    "runtime": f.get("Runtime"),
                    "last_modified": f.get("LastModified"),
                })
            marker = page.get("NextMarker")
            if not marker:
                break
        out["lambda_inventory"] = {
            "function_count": len(functions),
            "functions": functions[:25],  # cap detail; count stays accurate
        }
    except Exception as e:
        out["errors"].append(f"lambda_inventory: {e}")

    # --- Real month-to-date cost breakdown by service (not just anomalies) -
    # this is what lets the digest say "S3 cost $2.40 this month" instead of
    # only flagging when something looks unusual. ---
    try:
        ce = session.client("ce", region_name="us-east-1")
        month_start = datetime.now(timezone.utc).strftime("%Y-%m-01")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Gross usage cost, BEFORE credits - this is "what we actually spent"
        # in the everyday sense. Filtering to RECORD_TYPE=Usage excludes
        # Credit/Refund/Tax line items, which otherwise net real usage down
        # to a misleading $0.00 on accounts with promotional or free-tier credits.
        usage_data = ce.get_cost_and_usage(
            TimePeriod={"Start": month_start, "End": today},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            Filter={"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Usage"]}},
        )
        groups = usage_data.get("ResultsByTime", [{}])[0].get("Groups", [])
        out["cost_by_service"] = sorted(
            [
                {"service": g["Keys"][0], "amount_usd": round(float(g["Metrics"]["UnblendedCost"]["Amount"]), 2)}
                for g in groups
                if float(g["Metrics"]["UnblendedCost"]["Amount"]) >= 0.01
            ],
            key=lambda x: -x["amount_usd"],
        )[:25]  # enough to surface new services without flooding the prompt
        out["cost_gross_usage_total"] = round(sum(g["amount_usd"] for g in out["cost_by_service"]), 2)

        # Credits applied this month, shown separately so nothing gets
        # silently netted away - real usage stays visible even when credits
        # bring the net bill to $0.
        credit_data = ce.get_cost_and_usage(
            TimePeriod={"Start": month_start, "End": today},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            Filter={"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Credit"]}},
        )
        credit_amount = float(
            credit_data.get("ResultsByTime", [{}])[0].get("Total", {}).get("UnblendedCost", {}).get("Amount", 0)
        )
        out["cost_credits_applied"] = round(credit_amount, 2)  # negative number = credit applied
        out["cost_net_total"] = round(out["cost_gross_usage_total"] + out["cost_credits_applied"], 2)
    except Exception as e:
        out["errors"].append(f"cost_by_service: {e}")

    return out


def ask_claude_for_digest(collected, mode):
    """Send the raw collected signals to Claude on Bedrock and get back a dict with
    opening_line, service_status, and proposed_actions - via forced tool-use, so the
    response is guaranteed valid structured JSON with no string/marker parsing.

    Claude may ONLY propose action_type values from the whitelist below - it
    never gets to invent an AWS API call. Tier (auto vs approval) is decided
    later in code by checking the real resource's tags, not by anything Claude says."""

    whitelist_desc = "\n".join(
        f"  - {name}: requires params {info[2]}" for name, info in ACTION_REGISTRY.items()
    )
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
        "just a count, wherever that data is available in the collected signals. Keep each note "
        "under 20 words.\n\n"
        "CRITICAL RULE about stopped resources: if an RDS instance or EC2 instance shows status "
        "'stopped', that is very likely INTENTIONAL - someone paused it deliberately to save cost "
        "(e.g. during a break, off-hours, or between work sessions). A stopped resource is NOT a "
        "problem to fix. Mark its status OK (not WARNING), and NEVER propose starting it back up "
        "(rds_start_instance / ec2_start_instance) just because it's stopped - only propose starting "
        "something if the person explicitly asks for it elsewhere in this conversation, which you "
        "won't see here. Only propose STOP actions for resources that are running and look idle or "
        "wasteful - never propose START actions preemptively. This applies every single run, not just "
        "the first time you see it stopped - do not re-propose starting it on a later check.\n\n"
        "CRITICAL RULE about CloudWatch alarms: use alarm_summary. Actionable alarms (kind=actionable) "
        "are real problems - severity WARNING/ERROR on the matching service row, and the note MUST "
        "name the alarm. Scale-low alarms (kind=scale_low, usually TargetTracking *AlarmLow* for low "
        "CPU) mean the service is QUIET / underutilized - that is NORMAL for a small app, severity "
        "stays OK, and the note can mention 'scale-low (quiet CPU) - expected when traffic is light'. "
        "NEVER treat scale_low alone as 'warnings that need review'. NEVER propose "
        "cloudfront_create_invalidation (or any CDN action) because of CPU/scale alarms - those are "
        "unrelated.\n\n"
        "CRITICAL RULE about the opening line: it must match the table. If you say 'N warnings', "
        "exactly N service rows must have severity WARNING/ERROR and their notes must say what "
        "those warnings are. If the only alarms are scale_low, opening should be healthy "
        "(e.g. 'Everything looks healthy today.').\n\n"
        "You may propose follow-up actions ONLY from this exact whitelist - never anything else:\n"
        f"{whitelist_desc}\n\n"
        "Call the submit_digest tool exactly once with your findings - do not output any text outside "
        "the tool call. It takes three fields:\n\n"
        "1. opening_line: one friendly opening line (max 15 words) - e.g. 'Everything looks healthy "
        "today.' or '1 thing needs your attention.'\n\n"
        "2. service_status: an array covering services that EXIST in the collected data. "
        "ALWAYS include these compute rows even when empty so the owner can see they were checked: "
        "\"Containers (ECS)\", \"App hosting (App Runner)\", \"Functions (Lambda)\". "
        "Do NOT invent rows for other services with no inventory and $0 spend. DO include every "
        "other service that shows up in inventory OR has month-to-date usage cost > $0 in "
        "cost_by_service - including ones not listed below (e.g. VPC, CloudWatch). "
        "When a new service appears in the account, it MUST get a row. "
        "Each item has \"service\" (plain name), "
        "\"status\" (a real, meaningful state word specific to that service - e.g. 'Running', "
        "'Stopped', 'Available', 'Disabled', 'Active', 'Sending', 'Healthy', 'None' - NEVER the "
        "generic word 'OK'), \"severity\" (OK|WARNING|ERROR - for internal "
        "urgency only, never shown to the reader), and \"note\" (specific, names real resources, "
        "under 20 words). Prefer these exact display names when the matching inventory exists "
        "so cost columns can join correctly:\n"
        "  - \"Servers (EC2)\": status is 'Running' or 'None running' (or name the state, e.g. "
        "'Stopped'); name any running instance IDs.\n"
        "  - \"Databases (RDS)\": status is 'Available' or 'Stopped' (or the real DB status); name "
        "the actual instance identifier(s) and engine. If stopped, severity stays OK, and the note "
        "should say storage costs continue even while stopped (compute cost stops, storage cost "
        "doesn't) - do not treat this as a problem.\n"
        f"  - \"File storage (S3)\": status is 'Active'; name the actual bucket names. {bucket_rule}\n"
        "  - \"Email sending (SES)\": status is 'Sending' or 'Sandbox' or 'Disabled'; mention volume "
        "in the note.\n"
        "  - \"Content delivery (CDN)\": status is 'Active' or 'Deployed'; name the actual CloudFront "
        "domain name(s).\n"
        "  - \"User auth (Cognito)\": status is 'Active'; name the user pool and estimated user "
        "count.\n"
        "  - \"Secrets (Secrets Manager)\": status is 'Stored'; name the actual secret name(s).\n"
        "  - \"File transfer (SFTP)\": from transfer_inventory - if the list is empty, status "
        "'Disabled', severity OK, note 'Disabled - no active server.' If a server exists and is "
        "ONLINE, status 'Idle' and severity WARNING if user_count is 0 (idle but billing), else "
        "status 'Active' and severity OK, and name the server ID and user count.\n"
        "  - \"SSL certificate (ACM)\": status is the real certificate status (e.g. 'Valid', "
        "'Expired', 'Pending validation'); name the domain.\n"
        "  - \"Containers (ECS)\": ALWAYS include. From ecs_inventory - if empty, status 'None', "
        "note 'No ECS clusters.' If clusters/services exist, status 'Active'; name each "
        "cluster + service and running/desired counts. If alarm_summary.scale_low mentions those "
        "services, severity OK and note e.g. 'api-prod + api-prod-worker; scale-low (quiet CPU).'\n"
        "  - \"App hosting (App Runner)\": ALWAYS include. From apprunner_inventory - if empty, "
        "status 'None', note 'No App Runner services.' If services exist, use their real Status "
        "and name each service/URL.\n"
        "  - \"Functions (Lambda)\": ALWAYS include. From lambda_inventory - if function_count is 0, "
        "status 'None', note 'No product Lambdas.' Otherwise status 'Active'; note the count and "
        "name a few (ops-agent Lambdas are already filtered out).\n"
        "  - \"Billing alerts\": status is 'Configured' or 'Missing'; severity WARNING if missing, "
        "from billing_alarm_inventory and sns_billing_inventory.\n"
        "  - \"Access control (IAM)\": status is 'Configured'; from iam_inventory, mention the user "
        "and role counts in the note. Severity is usually OK, this is just for visibility.\n"
        "  - \"Domains (Route 53)\": status is 'Configured' or 'None configured'; from "
        "route53_inventory, name any hosted zones in the note. Severity is usually OK, this is just "
        "for visibility.\n"
        "  - \"AWS service health\": status is 'Healthy' or 'Incident'; note any open AWS Health "
        "events.\n"
        "  - For ANY other AWS service that appears in cost_by_service with amount_usd > 0 and "
        "is not already covered above (VPC, CloudWatch, KMS, etc.), add a row with a plain "
        "English name and a short note that it showed up on the bill.\n"
        "  - \"Monthly costs\": ALWAYS PUT THIS ROW LAST. status is 'Tracked'; severity OK unless "
        "spend looks unusual. The exact dollar totals are already shown in separate Cost/Day and "
        "Cost MTD columns, so don't repeat them here - instead, in the note, mention if credits are "
        "offsetting the bill (from cost_credits_applied and cost_net_total) and name the top 2-3 "
        "services by spend, e.g. 'Offset by $1.81 in credits (net $0.01). Top usage: RDS, VPC.'\n\n"
        "3. proposed_actions: an array of any suggested actions, each with \"action_type\" (one of "
        "the whitelist names above), \"resource\" (human-readable resource name), \"params\" (exact "
        "params required by that action_type), and \"reason\" (plain English, max 12 words). "
        "If no whitelisted action applies, use an empty array - "
        "do not propose an action_type that isn't in the whitelist."
    )

    user_prompt = f"Mode: {mode}\n\nCollected signals across accounts:\n{json.dumps(collected, indent=2, default=str)}"

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

    resp = bedrock.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        body=json.dumps(body),
    )
    payload = json.loads(resp["body"].read())

    for block in payload.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "submit_digest":
            return block.get("input", {})

    # Forced tool_choice should make this unreachable, but a model/API change
    # could still return a plain-text response - surface that as a visible
    # failure in Slack rather than silently producing a blank table.
    print(f"NO_TOOL_USE_IN_RESPONSE: {json.dumps(payload)}")
    return {
        "opening_line": "Digest generation failed this run - check logs",
        "service_status": [],
        "proposed_actions": [],
    }


def rich_text_cell(text, bold=False):
    """A single table cell as a Slack rich_text block - needed for bold
    header text, since raw_text cells don't support styling."""
    return {
        "type": "rich_text",
        "elements": [{
            "type": "rich_text_section",
            "elements": [{"type": "text", "text": text, "style": {"bold": True} if bold else {}}],
        }],
    }


def raw_cell(text):
    return {"type": "raw_text", "text": text}


# Maps our display row names to the substrings that show up in AWS's actual
# Cost Explorer service names - lets us join real dollar figures onto each
# row deterministically in code, instead of asking the LLM to compute or
# format currency (which is exactly the kind of thing that silently drifts).
COST_SERVICE_MAP = {
    "Servers (EC2)": ["Elastic Compute Cloud", "EC2"],
    "Databases (RDS)": ["Relational Database Service"],
    "File storage (S3)": ["Simple Storage Service"],
    "Email sending (SES)": ["Simple Email Service"],
    "Content delivery (CDN)": ["CloudFront"],
    "User auth (Cognito)": ["Cognito"],
    "Secrets (Secrets Manager)": ["Secrets Manager"],
    "File transfer (SFTP)": ["Transfer Family"],
    "SSL certificate (ACM)": ["Certificate Manager"],
    "Domains (Route 53)": ["Route 53"],
    "App hosting (App Runner)": ["App Runner"],
    "Containers (ECS)": ["Elastic Container Service", "Fargate", "EC2 Container Service"],
    "Servers (ECS)": ["Elastic Container Service", "Fargate", "EC2 Container Service"],  # alias if model mislabels
    "Functions (Lambda)": ["Lambda"],
    "Networking (VPC)": ["Virtual Private Cloud", "VPC"],
    "Monitoring (CloudWatch)": ["CloudWatch"],
}

# Fixed, factual "what this is for" text - supplied by the account owner, not
# generated by the model. Keeping this in code means it can never drift or
# be hallucinated, since it's context Claude has no way to verify on its own.
# Unknown / newly discovered services fall back to "-" in the table.
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
    "App hosting (App Runner)": "Fully managed container/web app hosting",
    "Containers (ECS)": "Container orchestration (Elastic Container Service)",
    "Servers (ECS)": "Container orchestration (Elastic Container Service)",
    "Functions (Lambda)": "Serverless compute functions",
    "Networking (VPC)": "Networking / data transfer around other services",
    "Monitoring (CloudWatch)": "Logs, metrics, and alarms",
    "Billing alerts": "Cost threshold alarm and notification",
    "Access control (IAM)": "Account users, roles, and permissions",
    "Domains (Route 53)": "DNS and domain management",
    "AWS service health": "AWS-wide incidents affecting this account",
    "Monthly costs": "Overall account spend",
}


def compute_cost_columns(collected):
    """Returns {row_name: {'mtd': float, 'per_day': float}} using the real
    gross-usage cost_by_service data collected earlier - not LLM math.

    Known rows use COST_SERVICE_MAP. For any other display name Claude invents
    for a newly discovered service, we fuzzy-match against Cost Explorer
    service names so App Runner / ECS / etc. still get real dollar columns."""
    account = (collected.get("accounts") or [{}])[0]
    cost_by_service = account.get("cost_by_service", [])
    gross_total = account.get("cost_gross_usage_total")
    days_elapsed = max(datetime.now(timezone.utc).day, 1)

    columns = {}
    for row_name, keywords in COST_SERVICE_MAP.items():
        mtd = sum(
            c["amount_usd"] for c in cost_by_service
            if any(k.lower() in c.get("service", "").lower() for k in keywords)
        )
        columns[row_name] = {"mtd": round(mtd, 2), "per_day": round(mtd / days_elapsed, 2)}

    if gross_total is not None:
        columns["Monthly costs"] = {"mtd": gross_total, "per_day": round(gross_total / days_elapsed, 2)}

    return columns


def cost_for_row(cost_columns, cost_by_service, row_name, key):
    """Look up Cost/Day or Cost MTD for a table row. Falls back to fuzzy
    matching cost_by_service when the row isn't in COST_SERVICE_MAP."""
    entry = cost_columns.get(row_name)
    if entry and entry.get(key) is not None:
        return f"${entry[key]:.2f}"

    days_elapsed = max(datetime.now(timezone.utc).day, 1)
    # Pull meaningful tokens from display names like "App hosting (App Runner)"
    tokens = [
        t for t in row_name.replace("(", " ").replace(")", " ").replace("-", " ").split()
        if len(t) > 2 and t.lower() not in {"the", "and", "for", "via"}
    ]
    if not tokens or not cost_by_service:
        return "-"
    mtd = sum(
        c["amount_usd"] for c in cost_by_service
        if any(t.lower() in c.get("service", "").lower() for t in tokens)
    )
    if mtd <= 0:
        return "-"
    value = mtd if key == "mtd" else mtd / days_elapsed
    return f"${round(value, 2):.2f}"



def build_status_table_block(service_status, cost_columns, cost_by_service=None):
    """Builds a real Slack Block Kit `table` block (native tables, launched
    May 2026) instead of a faked monospace code block - renders as an actual
    bordered table with a bold header row, matching Slack's own table UI.
    Cost/Day and Cost MTD columns are joined from real billing data in code,
    not parsed out of the LLM's prose note."""
    if not service_status:
        return None

    cost_by_service = cost_by_service or []
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
            raw_cell(cost_for_row(cost_columns, cost_by_service, row_name, "per_day")),
            raw_cell(cost_for_row(cost_columns, cost_by_service, row_name, "mtd")),
            raw_cell(SERVICE_PURPOSE.get(row_name, "-")),
            raw_cell(s.get("note", "")),
        ])

    return {"type": "table", "rows": rows}


def ensure_compute_rows(service_status, collected):
    """Guarantee App Runner / ECS / Lambda rows exist so empty platforms are
    visible as 'None' instead of silently missing from the table."""
    account = (collected.get("accounts") or [{}])[0]
    by_name = {s.get("service", ""): s for s in service_status}

    def upsert(name, status, note, severity="OK"):
        if name in by_name:
            return
        # Prefer canonical name; drop close aliases the model may have used
        aliases = {
            "Containers (ECS)": ["Servers (ECS)", "ECS"],
            "App hosting (App Runner)": ["App Runner"],
            "Functions (Lambda)": ["Lambda"],
        }
        for alias in aliases.get(name, []):
            if alias in by_name:
                by_name[alias]["service"] = name
                by_name[name] = by_name.pop(alias)
                return
        row = {"service": name, "status": status, "severity": severity, "note": note}
        service_status.append(row)
        by_name[name] = row

    ecs = account.get("ecs_inventory") or []
    if ecs:
        svc_bits = []
        for c in ecs:
            for s in c.get("services") or []:
                svc_bits.append(f"{s.get('name')} {s.get('running')}/{s.get('desired')}")
        note = f"{ecs[0].get('name')}: " + (", ".join(svc_bits) if svc_bits else "no services")
        upsert("Containers (ECS)", "Active", note[:120])
    else:
        upsert("Containers (ECS)", "None", "No ECS clusters.")

    appr = account.get("apprunner_inventory") or []
    if appr:
        names = ", ".join(s.get("name") or "?" for s in appr[:5])
        upsert("App hosting (App Runner)", appr[0].get("status") or "Active", names[:120])
    else:
        upsert("App hosting (App Runner)", "None", "No App Runner services.")

    lam = account.get("lambda_inventory") or {}
    count = lam.get("function_count", 0)
    if count:
        names = ", ".join(f.get("name") or "?" for f in (lam.get("functions") or [])[:5])
        upsert("Functions (Lambda)", "Active", f"{count} functions: {names}"[:120])
    else:
        upsert("Functions (Lambda)", "None", "No product Lambdas.")

    return service_status


def soften_scale_low_warnings(opening_line, service_status, collected):
    """If the only ALARM-state metrics are Auto Scaling AlarmLow (quiet CPU),
    don't yellow-banner the digest or leave 'N warnings' unmatched in the table."""
    account = (collected.get("accounts") or [{}])[0]
    summary = account.get("alarm_summary") or {}
    actionable = summary.get("actionable") or []
    scale_low = summary.get("scale_low") or []

    # Downgrade any model WARNING that only cites scale-low / underutilized CPU
    for s in service_status:
        note = (s.get("note") or "").lower()
        if s.get("severity", "").upper() == "WARNING" and (
            "scale-low" in note or "underutil" in note or "alarmlow" in note.replace(" ", "")
        ):
            if not actionable:
                s["severity"] = "OK"

    if actionable:
        return opening_line, service_status

    if scale_low:
        # Rewrite scare-openings when nothing is actually wrong
        lowered = (opening_line or "").lower()
        if any(w in lowered for w in ("warning", "attention", "firing", "issue", "problem")):
            names = []
            for a in scale_low:
                dims = a.get("dimensions") or {}
                names.append(dims.get("ServiceName") or dims.get("ClusterName") or a.get("name", "")[:40])
            named = ", ".join(n for n in names if n)[:80]
            opening_line = (
                f"Healthy — {len(scale_low)} quiet-CPU scale alarms ({named})."
                if named else
                f"Healthy — {len(scale_low)} quiet-CPU scale alarms (normal when idle)."
            )

    return opening_line, service_status


def order_with_costs_last(service_status):
    """Guarantees the Monthly costs row is always last, regardless of what
    order the model happened to output - a prompt instruction is a preference,
    not a guarantee, so this is enforced in code. Also appends an honest
    data-lag disclaimer in code (not left to the LLM to remember) - AWS Cost
    Explorer's API typically lags 24-48h behind the Billing console's
    near-real-time estimate, so a low number here could mean 'genuinely low
    spend' or 'today's charges haven't posted yet.' Silently showing $0.00
    without that context is actively misleading, not just imprecise."""
    costs = [s for s in service_status if "cost" in s.get("service", "").lower()]
    others = [s for s in service_status if "cost" not in s.get("service", "").lower()]
    for c in costs:
        note = c.get("note", "")
        if "lag" not in note.lower() and "delay" not in note.lower():
            c["note"] = f"{note} (cost data can lag 24-48h behind the AWS Billing page)"
    return others + costs


def overall_emoji(service_status):
    severities = {s.get("severity", "").upper() for s in service_status}
    if "ERROR" in severities:
        return "🔴"
    if "WARNING" in severities:
        return "🟡"
    return "🟢"


def get_read_session_for_account(role_arn):
    return assume_role(role_arn)


def dispatch_proposed_actions(proposed_actions, spoke_role_arns):
    """For each proposed action: validate against the whitelist, classify its
    real tier from live resource tags, then either execute immediately (tier1)
    or post a Slack approval prompt (tier2). Returns a list of result strings
    to fold into the digest message.

    Structural rule, enforced here in code (not just via prompt instruction):
    the AUTOMATED digest never gets to propose turning something back on.
    Starting a stopped resource is a decision to resume cost, and that should
    only ever happen via an explicit human action (the /aws slash command),
    never inferred by the model from a scheduled run. A prompt instruction is
    guidance the model can drift from over time; this filter makes it
    impossible regardless of what the model outputs."""
    AUTOMATION_BLOCKED_ACTIONS = {
        "rds_start_instance",
        "ec2_start_instance",
        # CDN invalidation must never be invented from unrelated alarms
        # (e.g. ECS scale-low). Manual /awsmanager invalidate-cdn still works.
        "cloudfront_create_invalidation",
    }

    results = []
    # Reuse the first spoke account's read session for tier classification -
    # fine for the single-account setup; multi-account needs per-resource routing,
    # which is a natural extension once you add more spoke accounts.
    read_session = get_read_session_for_account(spoke_role_arns[0]) if spoke_role_arns else None

    for proposed in proposed_actions:
        action_type = proposed.get("action_type")
        params = proposed.get("params", {})
        resource = proposed.get("resource", "unknown resource")
        reason = proposed.get("reason", "")

        if action_type in AUTOMATION_BLOCKED_ACTIONS:
            results.append(
                f"Skipped: the automated digest suggested '{action_type}' on {resource}, but starting "
                f"a stopped resource requires an explicit /aws command from you, not an automatic proposal."
            )
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
            "action_id": action_id,
            "action_type": action_type,
            "resource": resource,
            "params": json.dumps(params),
            "tier": tier,
            "status": "proposed",
            "reason": reason,
            "proposed_at": datetime.now(timezone.utc).isoformat(),
        })

        if tier == "tier1_auto":
            resp = lambda_client.invoke(
                FunctionName=EXECUTOR_FUNCTION_NAME,
                InvocationType="RequestResponse",
                Payload=json.dumps({
                    "action_id": action_id,
                    "action_type": action_type,
                    "params": params,
                    "approved_by": "auto",
                }).encode("utf-8"),
            )
            body = json.loads(resp["Payload"].read())
            if resp.get("StatusCode") == 200 and "error" not in body:
                results.append(f"Auto-executed: {action_type} on {resource} ({reason})")
            else:
                results.append(f"Auto-exec FAILED: {action_type} on {resource} - {body}")
        else:
            post_approval_request(action_id, action_type, resource, reason)
            results.append(f"Pending approval in Slack: {action_type} on {resource} ({reason})")

    return results


def post_approval_request(action_id, action_type, resource, reason):
    notifiers.post_approval_request(action_id, action_type, resource, reason)


def post_digest_notification(opening_line, emoji, service_status, cost_columns, table_block, action_results, mode, cost_by_service=None):
    cost_by_service = cost_by_service or []
    notifiers.post_digest(
        opening_line, emoji, service_status, cost_columns, table_block, action_results, mode,
        COMPANY_NAME,
        format_dollar_fn=lambda cc, rn, k: cost_for_row(cc, cost_by_service, rn, k),
        purpose_map=SERVICE_PURPOSE,
    )


def has_notable_content(digest_text):
    """No longer used for the post/skip decision (that's now driven by
    service_status directly) - kept only in case a future prompt regression
    needs a prose-based fallback check."""
    lowered = digest_text.lower()
    quiet_phrases = ["nothing notable", "no anomalies", "all clear", "no issues"]
    return not any(p in lowered for p in quiet_phrases)


def add_unmonitored_cost_services(service_status, collected, min_cost=0.01):
    """Additional deterministic safety net, on top of the prompt instruction
    and ensure_compute_rows: if a service is genuinely costing money and
    doesn't match anything in COST_SERVICE_MAP (and isn't already a row -
    e.g. the model followed instructions and added it itself), add a row for
    it in code. This never overrides what the model already did; it only
    fills a gap if the model's compliance with the 'add unknown paid
    services' prompt rule ever lapses - which, per tonight's build history,
    is exactly the kind of thing worth not trusting to the LLM alone."""
    account = (collected.get("accounts") or [{}])[0]
    cost_by_service = account.get("cost_by_service", [])
    days_elapsed = max(datetime.now(timezone.utc).day, 1)

    known_keywords = [kw.lower() for kws in COST_SERVICE_MAP.values() for kw in kws]
    existing_names = {s.get("service", "").lower() for s in service_status}
    extra_rows = []
    extra_cost_columns = {}

    for c in cost_by_service:
        aws_name = c.get("service", "")
        amount = c.get("amount_usd", 0)
        if amount < min_cost or not aws_name:
            continue
        if any(kw in aws_name.lower() for kw in known_keywords):
            continue  # has (or should have) a dedicated row already
        if aws_name.lower() in existing_names:
            continue  # model already added a row using the raw AWS service name

        display_name = f"{aws_name} (auto-detected)"
        if display_name.lower() in existing_names:
            continue

        extra_rows.append({
            "service": display_name,
            "status": "In use",
            "severity": "OK",
            "note": "Detected from billing data - no dedicated monitoring built for this service yet.",
        })
        extra_cost_columns[display_name] = {"mtd": amount, "per_day": round(amount / days_elapsed, 2)}

    return service_status + extra_rows, extra_cost_columns


def handler(event, context):
    if not SPOKE_ROLE_ARNS:
        raise RuntimeError("SPOKE_ROLE_ARNS env var is empty - set at least one spoke account role ARN")

    mode = (event or {}).get("mode", DEFAULT_MODE)

    collected = {"mode": mode, "generated_at": datetime.now(timezone.utc).isoformat(), "accounts": []}
    for role_arn in SPOKE_ROLE_ARNS:
        collected["accounts"].append(collect_account(role_arn, mode))

    result = ask_claude_for_digest(collected, mode)
    opening_line = result["opening_line"]
    service_status = result["service_status"]
    service_status = ensure_compute_rows(service_status, collected)
    opening_line, service_status = soften_scale_low_warnings(opening_line, service_status, collected)
    service_status, extra_cost_columns = add_unmonitored_cost_services(service_status, collected)
    service_status = order_with_costs_last(service_status)
    proposed_actions = result["proposed_actions"]

    action_results = dispatch_proposed_actions(proposed_actions, SPOKE_ROLE_ARNS) if proposed_actions else []

    has_warning_or_error = any(s.get("severity", "").upper() != "OK" for s in service_status)
    should_post = mode == "daily" or has_warning_or_error or bool(action_results)

    if should_post:
        emoji = overall_emoji(service_status)
        cost_columns = compute_cost_columns(collected)
        cost_columns.update(extra_cost_columns)
        account0 = (collected.get("accounts") or [{}])[0]
        cost_by_service = account0.get("cost_by_service", [])
        table_block = build_status_table_block(service_status, cost_columns, cost_by_service=cost_by_service)
        post_digest_notification(opening_line, emoji, service_status, cost_columns, table_block, action_results, mode, cost_by_service=cost_by_service)
        posted = True
    else:
        posted = False

    return {
        "statusCode": 200,
        "body": json.dumps({"posted": posted, "mode": mode, "actions_proposed": len(proposed_actions)}),
    }
