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


def s3_classify_tier(session, params):
    # Lifecycle/versioning/public-access-block changes are always tightening
    # or cost-saving moves in this registry - treated as tier 1 regardless of tags.
    return TIER_AUTO


def cloudfront_classify_tier(session, params):
    # Cache invalidation is fully reversible (cache just repopulates) - tier 1.
    return TIER_AUTO


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


def s3_apply_lifecycle_policy(session, params):
    s3 = session.client("s3")
    s3.put_bucket_lifecycle_configuration(
        Bucket=params["bucket"],
        LifecycleConfiguration=params["lifecycle_rules"],
    )
    return {"bucket": params["bucket"], "lifecycle_applied": True}


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
