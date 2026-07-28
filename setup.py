#!/usr/bin/env python3
"""
AWS Ops Agent - interactive setup wizard.

Asks you a short series of questions, then does everything else itself:
deploys the IAM roles, stores your Slack secrets, and runs `sam build` /
`sam deploy` with the right parameters. You never hand-edit a YAML file
or an env var.

Prerequisites (checked automatically, with guidance if missing):
  - AWS CLI configured with credentials for the account you want to monitor
  - SAM CLI installed
  - A Slack app already created (see README.md - this part can't be
    automated away without a much bigger OAuth distribution setup, but the
    wizard tells you exactly what to click)

Run: python3 setup.py
"""

import json
import os
import subprocess
import sys
import getpass

try:
    import boto3
except ImportError:
    print("This wizard needs boto3. Install it with: pip install boto3 --break-system-packages")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))


def run(cmd, capture=False):
    print(f"\n$ {' '.join(cmd)}")
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stderr)
        return result
    return subprocess.run(cmd)


def ask(prompt, default=None, required=True):
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"{prompt}{suffix}: ").strip()
        if not val and default is not None:
            return default
        if not val and not required:
            return ""
        if val:
            return val
        print("This one's required - try again.")


def ask_choice(prompt, choices):
    print(f"\n{prompt}")
    for i, (label, _) in enumerate(choices, 1):
        print(f"  {i}. {label}")
    while True:
        raw = input(f"Choose 1-{len(choices)}: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1][1]
        print("Not a valid choice - try again.")


def ask_secret(prompt):
    val = getpass.getpass(f"{prompt} (input hidden): ").strip()
    while not val:
        val = getpass.getpass(f"{prompt} (input hidden, required): ").strip()
    return val


def check_prerequisites():
    print("=== Checking prerequisites ===")
    aws_check = run(["aws", "--version"], capture=True)
    if aws_check.returncode != 0:
        print("AWS CLI not found. Install it first: https://aws.amazon.com/cli/")
        sys.exit(1)

    sam_check = run(["sam", "--version"], capture=True)
    if sam_check.returncode != 0:
        print("SAM CLI not found. Install it first: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html")
        sys.exit(1)

    identity_check = run(["aws", "sts", "get-caller-identity", "--output", "json"], capture=True)
    if identity_check.returncode != 0:
        print("AWS credentials aren't configured. Run `aws configure` first, then re-run this script.")
        sys.exit(1)

    identity = json.loads(identity_check.stdout)
    print(f"AWS identity confirmed: account {identity['Account']}, {identity['Arn']}")
    return identity["Account"]


def main():
    print("AWS Ops Agent - setup wizard\n")
    print("This will deploy an AWS monitoring agent into your account and connect")
    print("it to Slack. Nothing here touches any other account or organization.\n")

    account_id = check_prerequisites()

    print("\n=== Basic info ===")
    region = ask("AWS region to deploy into", default="us-east-1")
    company_name = ask("Company/product name (shown in Slack messages, optional)", default="", required=False)

    print("\n=== Digest cadence ===")
    frequent_expr, frequent_label = ask_choice("How often should the lightweight check run?", [
        ("Every hour", "rate(1 hour)"),
        ("Every 3 hours", "rate(3 hours)"),
        ("Every 6 hours", "rate(6 hours)"),
        ("Fixed clock hours: 12am/3am/6am/9am/12pm/3pm/6pm/9pm", "cron(0 0,3,6,9,12,15,18,21 * * ? *)"),
        ("Custom cron expression", "__custom__"),
    ])
    if frequent_expr == "__custom__":
        frequent_expr = ask("Enter EventBridge Scheduler expression (e.g. cron(0 */4 * * ? *))")

    daily_time = ask("What time should the full daily check-in post? (24h, e.g. 08:00)", default="08:00")
    hh, mm = daily_time.split(":")
    daily_expr = f"cron({int(mm)} {int(hh)} * * ? *)"

    timezone = ask("Timezone (IANA format, e.g. America/New_York, Europe/London, Asia/Kolkata)", default="UTC")

    print("\n=== Optional customization ===")
    bucket_prefix = ask("If your S3 buckets follow a naming convention (e.g. 'acme-'), enter the prefix to flag anything unexpected. Leave blank to skip", default="", required=False)
    billing_alarm_filter = ask("CloudWatch billing alarm name/prefix to check for (optional, leave blank to skip)", default="", required=False)
    billing_sns_filter = ask("SNS topic name/prefix for billing alerts (optional, leave blank to skip)", default="", required=False)

    bedrock_model = ask(
        "Bedrock model ID (check your account's available models first if unsure)",
        default="us.anthropic.claude-haiku-4-5-20251001-v1:0",
    )

    print("\n=== Where should notifications go? ===")
    channels = ask_choice("Which channel(s) should receive the digest?", [
        ("Slack only", ["slack"]),
        ("Microsoft Teams only", ["teams"]),
        ("Both", ["slack", "teams"]),
    ])

    print("\n=== Slack app (always needed - for /aws-ops commands and to sign approval links,")
    print("    even if your digest posts to Teams only) ===")
    print("  1. Go to https://api.slack.com/apps -> Create New App -> From scratch")
    if "slack" in channels:
        print("  2. Under 'Incoming Webhooks', activate it and add a webhook to your target channel")
    else:
        print("  2. You can skip 'Incoming Webhooks' entirely - not needed for Teams-only digests")
    print("  3. Under 'Basic Information', copy the 'Signing Secret'")
    print("  (Full walkthrough in README.md if you want the detailed version)\n")
    input("Press Enter once you've done this and have what you need ready...")

    slack_signing_secret = ask_secret("Paste your Slack signing secret")
    slack_webhook_url = ask_secret("Paste your Slack webhook URL") if "slack" in channels else ""

    teams_webhook_url = ""
    if "teams" in channels:
        print("\n=== Microsoft Teams setup ===")
        print("Office 365 Connector webhooks were retired by Microsoft - this uses the current")
        print("supported path, Power Automate Workflows:")
        print("  1. In Teams, go to the channel -> ... -> Workflows")
        print("  2. Search for 'Post to a channel when a webhook request is received' and add it")
        print("  3. When setting up the trigger, choose 'Use a sample payload to generate a schema'")
        print("     and paste this sample (matches exactly what this agent sends):")
        print('     {"adaptiveCard": {"type": "AdaptiveCard", "version": "1.5", "body": []}}')
        print("  4. Add a 'Post adaptive card in a channel' action, and set its Card field to the")
        print("     'adaptiveCard' value from the trigger's dynamic content")
        print("  5. Save the flow, then copy the generated HTTP POST URL")
        print("  (Full walkthrough with screenshots in README.md)\n")
        input("Press Enter once you've done this and have the workflow URL ready...")
        teams_webhook_url = ask_secret("Paste your Teams Workflow HTTP POST URL")

    allowed_users = ask("Slack user IDs allowed to run /aws-ops commands, comma-separated (e.g. U0123ABC,U0456DEF)", default="", required=False)

    # --- Store secrets ---
    print("\n=== Storing secrets in AWS Secrets Manager ===")
    secrets_client = boto3.client("secretsmanager", region_name=region)

    def upsert_secret(name, value):
        try:
            resp = secrets_client.create_secret(Name=name, SecretString=value)
        except secrets_client.exceptions.ResourceExistsException:
            secrets_client.put_secret_value(SecretId=name, SecretString=value)
            resp = secrets_client.describe_secret(SecretId=name)
        return resp["ARN"] if "ARN" in resp else secrets_client.describe_secret(SecretId=name)["ARN"]

    signing_arn = upsert_secret("aws-ops-agent/slack-signing-secret", slack_signing_secret)
    print(f"Stored. Signing secret ARN: {signing_arn}")

    webhook_arn = ""
    if slack_webhook_url:
        webhook_arn = upsert_secret("aws-ops-agent/slack-webhook", slack_webhook_url)
        print(f"Stored. Slack webhook secret ARN: {webhook_arn}")

    teams_webhook_arn = ""
    if teams_webhook_url:
        teams_webhook_arn = upsert_secret("aws-ops-agent/teams-webhook", teams_webhook_url)
        print(f"Stored. Teams webhook secret ARN: {teams_webhook_arn}")

    # --- Deploy IAM roles ---
    print("\n=== Deploying IAM roles ===")
    run([
        "aws", "cloudformation", "deploy",
        "--template-file", os.path.join(HERE, "iam", "spoke-account-role.yaml"),
        "--stack-name", "aws-ops-agent-role",
        "--parameter-overrides", f"OpsAccountId={account_id}",
        "--capabilities", "CAPABILITY_NAMED_IAM",
        "--region", region,
    ])
    run([
        "aws", "cloudformation", "deploy",
        "--template-file", os.path.join(HERE, "iam", "spoke-account-executor-role.yaml"),
        "--stack-name", "aws-ops-agent-executor-role",
        "--parameter-overrides", f"OpsAccountId={account_id}",
        "--capabilities", "CAPABILITY_NAMED_IAM",
        "--region", region,
    ])

    read_role_arn = f"arn:aws:iam::{account_id}:role/AwsOpsAgentReadOnly"
    executor_role_arn = f"arn:aws:iam::{account_id}:role/AwsOpsAgentExecutor"

    # --- Build and deploy the app ---
    print("\n=== Building and deploying the agent ===")
    run(["sam", "build"], capture=False)

    param_overrides = [
        f"SpokeRoleArns={read_role_arn}",
        f"NotificationChannels={','.join(channels)}",
        f"SlackWebhookSecretArn={webhook_arn}",
        f"SlackSigningSecretArn={signing_arn}",
        f"TeamsWebhookSecretArn={teams_webhook_arn}",
        f"ExecutorRoleArn={executor_role_arn}",
        f"AllowedSlackUserIds={allowed_users}",
        f"BedrockModelId={bedrock_model}",
        f"CompanyName={company_name}",
        f"ExpectedBucketPrefix={bucket_prefix}",
        f"BillingAlarmNameFilter={billing_alarm_filter}",
        f"BillingSnsTopicNameFilter={billing_sns_filter}",
        f"ScheduleExpression={frequent_expr}",
        f"DailyScheduleExpression={daily_expr}",
        f"ScheduleTimezone={timezone}",
    ]

    deploy_result = run([
        "sam", "deploy",
        "--stack-name", "aws-ops-agent",
        "--region", region,
        "--resolve-s3",
        "--no-confirm-changeset",
        "--capabilities", "CAPABILITY_NAMED_IAM",
        "--parameter-overrides", *param_overrides,
    ])

    if deploy_result.returncode != 0:
        print("\nDeploy failed - check the output above. Nothing was left half-configured that")
        print("you can't safely re-run: this script is idempotent, just fix the issue and re-run it.")
        sys.exit(1)

    # --- Get the interactivity/command URLs from the stack outputs ---
    outputs_result = run([
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", "aws-ops-agent",
        "--region", region,
        "--query", "Stacks[0].Outputs",
        "--output", "json",
    ], capture=True)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in json.loads(outputs_result.stdout)}

    channel_label = " and ".join(c.capitalize() for c in channels)
    print("\n" + "=" * 60)
    print(f"DONE. The agent is deployed and will start posting to {channel_label}")
    print("on the schedule you set.")
    print("=" * 60)
    print("\nTwo last manual steps in Slack (can't be automated - these are")
    print("Slack-side app configuration, not AWS - needed even for Teams-only")
    print("digests, since /aws-ops commands and approval-link signing always go through Slack):\n")
    print(f"1. In your Slack app -> Interactivity & Shortcuts -> turn it ON,")
    print(f"   set the Request URL to:\n   {outputs.get('SlackInteractionsUrl', '(see stack outputs)')}\n")
    print(f"2. In your Slack app -> Slash Commands -> Create New Command:")
    print(f"   Command: /aws-ops")
    print(f"   Request URL:\n   {outputs.get('SlackCommandUrl', '(see stack outputs)')}\n")
    print("Then reinstall the app in your workspace if Slack prompts you to")
    print("(it will, since you just added new permission scopes).\n")
    print("Test it any time with:")
    print(f'  aws lambda invoke --function-name aws-ops-agent-digest --payload \'{{"mode": "daily"}}\' --cli-binary-format raw-in-base64-out --region {region} out.json && cat out.json')


if __name__ == "__main__":
    main()
