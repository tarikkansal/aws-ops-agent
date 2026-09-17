"""
Action registry for the AWS ops agent.

This is the single source of truth for what the agent is allowed to DO.
Claude only ever proposes an `action_type` from this registry's keys plus
params - it never gets to call an arbitrary boto3 method. The executor
Lambda refuses anything not listed here.

Tier is decided in code, by checking the actual resource's tags at execution
time - never by trusting whatever risk label the LLM produced in its digest.
That's deliberate: a model can be wrong or manipulated about risk; a tag
lookup against the real resource can't.
"""

import os
import boto3

TIER_AUTO = "tier1_auto"          # executes immediately, no approval
TIER_APPROVAL = "tier2_approval"  # requires a Slack approval click


def _get_ec2_tag(session, instance_id, key):
    ec2 = session.client("ec2")
    resp = ec2.describe_tags(Filters=[
        {"Name": "resource-id", "Values": [instance_id]},
        {"Name": "key", "Values": [key]},
    ])
    tags = resp.get("Tags", [])
    return tags[0]["Value"] if tags else None


def _get_rds_tag(session, instance_id, key):
    rds = session.client("rds")
    arn = f"arn:aws:rds:{session.region_name}:{session.client('sts').get_caller_identity()['Account']}:db:{instance_id}"
    resp = rds.list_tags_for_resource(ResourceName=arn)
    for t in resp.get("TagList", []):
        if t["Key"] == key:
            return t["Value"]
    return None


NON_PROD_ENVIRONMENTS = {"dev", "staging", "test", "sandbox"}


def rds_classify_tier(session, params):
    env = _get_rds_tag(session, params["instance_id"], "Environment")
    return TIER_AUTO if (env and env.lower() in NON_PROD_ENVIRONMENTS) else TIER_APPROVAL


def ec2_classify_tier(session, params):
    env = _get_ec2_tag(session, params["instance_id"], "Environment")
    return TIER_AUTO if (env and env.lower() in NON_PROD_ENVIRONMENTS) else TIER_APPROVAL


# Buckets matching this prefix are trusted enough for tier1 auto-execute
# lifecycle changes; anything else (tooling leftovers, unexpected buckets)
# requires approval. Same EXPECTED_BUCKET_PREFIX the setup wizard configures
# for digest.py's "unexpected bucket" flag - one setting, used consistently.
# Empty (unconfigured) means nothing gets auto-execute trust by default -
# safer to require approval until a real convention is set.
S3_AUTO_BUCKET_PREFIXES = tuple(
    p.strip().lower() for p in os.environ.get("EXPECTED_BUCKET_PREFIX", "").split(",") if p.strip()
)


def s3_classify_tier(session, params):
    bucket = (params.get("bucket") or "").strip().lower()
    if S3_AUTO_BUCKET_PREFIXES and any(bucket.startswith(prefix) for prefix in S3_AUTO_BUCKET_PREFIXES):
        return TIER_AUTO
    return TIER_APPROVAL


def cloudfront_classify_tier(session, params):
    # Cache invalidation is reversible but still user-visible (brief misses /
    # origin load). Always require Slack approval — digests previously
    # auto-invalidated CDN for unrelated ECS scale-low alarms.
    return TIER_APPROVAL


def rds_start_instance(session, params):
    rds = session.client("rds")
    rds.start_db_instance(DBInstanceIdentifier=params["instance_id"])
    return {"started": params["instance_id"]}


def rds_stop_instance(session, params):
    rds = session.client("rds")
    # Always snapshot before stopping anything non-trivial - cheap insurance.
    rds.create_db_snapshot(
        DBSnapshotIdentifier=f"{params['instance_id']}-agent-stop-{params.get('timestamp', 'na')}",
        DBInstanceIdentifier=params["instance_id"],
    )
    rds.stop_db_instance(DBInstanceIdentifier=params["instance_id"])
    return {"stopped": params["instance_id"], "snapshot_taken": True}


def ec2_start_instance(session, params):
    ec2 = session.client("ec2")
    ec2.start_instances(InstanceIds=[params["instance_id"]])
    return {"started": params["instance_id"]}


def ec2_stop_instance(session, params):
    ec2 = session.client("ec2")
    ec2.stop_instances(InstanceIds=[params["instance_id"]])
    return {"stopped": params["instance_id"]}


def _as_int(value, default=None):
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_lifecycle_rule(rule, index):
    """Map Claude's free-form rule dict into boto3 PutBucketLifecycleConfiguration shape."""
    if not isinstance(rule, dict):
        raise ValueError(f"lifecycle rule {index} must be an object")

    status_raw = rule.get("Status") or rule.get("status") or "Enabled"
    status = str(status_raw).strip().capitalize()
    if status not in ("Enabled", "Disabled"):
        status = "Enabled"

    rule_id = rule.get("ID") or rule.get("Id") or rule.get("id") or f"agent-rule-{index + 1}"

    normalized = {
        "ID": str(rule_id)[:255],
        "Status": status,
    }

    filt = rule.get("Filter") or rule.get("filter")
    if isinstance(filt, dict):
        normalized["Filter"] = filt
    elif isinstance(filt, str):
        normalized["Filter"] = {"Prefix": filt}
    elif "Prefix" in rule or "prefix" in rule:
        normalized["Filter"] = {"Prefix": rule.get("Prefix") or rule.get("prefix") or ""}
    else:
        # Required by newer S3 lifecycle APIs when no prefix/tag filter is set.
        normalized["Filter"] = {"Prefix": ""}

    # Expiration (current object versions)
    expiration_days = _as_int(
        rule.get("ExpirationDays")
        or rule.get("expiration_days")
        or (rule.get("Expiration") or {}).get("Days")
        or (rule.get("expiration") or {}).get("days")
        or (rule.get("expiration") or {}).get("Days")
    )
    if expiration_days is not None:
        normalized["Expiration"] = {"Days": expiration_days}
    elif isinstance(rule.get("Expiration"), dict):
        normalized["Expiration"] = rule["Expiration"]

    # Noncurrent version expiration
    noncurrent_days = _as_int(
        rule.get("NoncurrentVersionExpirationDays")
        or rule.get("noncurrent_version_expiration_days")
        or rule.get("NoncurrentDays")
        or rule.get("noncurrent_days")
        or (rule.get("NoncurrentVersionExpiration") or {}).get("NoncurrentDays")
        or (rule.get("noncurrent_version_expiration") or {}).get("noncurrent_days")
        or (rule.get("noncurrent_version_expiration") or {}).get("NoncurrentDays")
    )
    if noncurrent_days is not None:
        normalized["NoncurrentVersionExpiration"] = {"NoncurrentDays": noncurrent_days}
    elif isinstance(rule.get("NoncurrentVersionExpiration"), dict):
        normalized["NoncurrentVersionExpiration"] = rule["NoncurrentVersionExpiration"]

    abort_days = _as_int(
        rule.get("AbortIncompleteMultipartUploadDays")
        or rule.get("abort_incomplete_multipart_upload_days")
        or (rule.get("AbortIncompleteMultipartUpload") or {}).get("DaysAfterInitiation")
        or (rule.get("abort_incomplete_multipart_upload") or {}).get("days_after_initiation")
    )
    if abort_days is not None:
        normalized["AbortIncompleteMultipartUpload"] = {"DaysAfterInitiation": abort_days}
    elif isinstance(rule.get("AbortIncompleteMultipartUpload"), dict):
        normalized["AbortIncompleteMultipartUpload"] = rule["AbortIncompleteMultipartUpload"]

    return normalized


def normalize_lifecycle_configuration(lifecycle_rules):
    """Accept Claude's loose shapes and return {"Rules": [...]} for boto3."""
    if isinstance(lifecycle_rules, dict):
        rules = lifecycle_rules.get("Rules") or lifecycle_rules.get("rules")
        if rules is None:
            # Single rule object mistakenly passed as the whole config
            rules = [lifecycle_rules]
    elif isinstance(lifecycle_rules, list):
        rules = lifecycle_rules
    else:
        raise ValueError("lifecycle_rules must be a list of rules or {Rules: [...]}")

    if not rules:
        raise ValueError("lifecycle_rules must include at least one rule")

    return {
        "Rules": [_normalize_lifecycle_rule(rule, i) for i, rule in enumerate(rules)]
    }


def s3_apply_lifecycle_policy(session, params):
    s3 = session.client("s3")
    config = normalize_lifecycle_configuration(params["lifecycle_rules"])
    s3.put_bucket_lifecycle_configuration(
        Bucket=params["bucket"],
        LifecycleConfiguration=config,
    )
    return {"bucket": params["bucket"], "lifecycle_applied": True, "rules": len(config["Rules"])}


def cloudfront_create_invalidation(session, params):
    cf = session.client("cloudfront")
    resp = cf.create_invalidation(
        DistributionId=params["distribution_id"],
        InvalidationBatch={
            "Paths": {"Quantity": len(params["paths"]), "Items": params["paths"]},
            "CallerReference": params.get("timestamp", "agent"),
        },
    )
    return {"invalidation_id": resp["Invalidation"]["Id"]}


# action_type -> (classify_tier_fn, execute_fn, required_params)
ACTION_REGISTRY = {
    "rds_start_instance": (rds_classify_tier, rds_start_instance, ["instance_id"]),
    "rds_stop_instance": (rds_classify_tier, rds_stop_instance, ["instance_id"]),
    "ec2_start_instance": (ec2_classify_tier, ec2_start_instance, ["instance_id"]),
    "ec2_stop_instance": (ec2_classify_tier, ec2_stop_instance, ["instance_id"]),
    "s3_apply_lifecycle_policy": (s3_classify_tier, s3_apply_lifecycle_policy, ["bucket", "lifecycle_rules"]),
    "cloudfront_create_invalidation": (cloudfront_classify_tier, cloudfront_create_invalidation, ["distribution_id", "paths"]),
}


def validate_action(action_type, params):
    """Returns (ok, error_message). Never raises - callers check the bool."""
    if action_type not in ACTION_REGISTRY:
        return False, f"'{action_type}' is not in the whitelisted action registry"
    _, _, required = ACTION_REGISTRY[action_type]
    missing = [p for p in required if p not in params]
    if missing:
        return False, f"missing required params: {missing}"
    return True, None
