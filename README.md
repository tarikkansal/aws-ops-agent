# AWS Ops Agent

An AI ops assistant that watches your AWS account, explains what's happening in plain English,
and posts a real status table to Slack and/or Microsoft Teams on a schedule — automatically
handling safe, reversible housekeeping, and asking for your approval before touching anything
riskier.

Built to replace the daily "someone manually checks the AWS console" habit, not to replace
human judgment on anything that matters.

## What it actually does

Every run, it collects real inventory and cost data across EC2, RDS, S3, SES, CloudFront,
Cognito, Secrets Manager, Transfer Family (SFTP), ACM, IAM, Route 53, billing alarms, and AWS
Health — then asks Claude to summarize it for a non-technical reader and posts a table like this
to Slack:

| Service | Status | Cost/Day | Cost MTD | What it's for | Notes |
|---|---|---|---|---|---|
| Databases (RDS) | Available | $0.21 | $3.60 | Managed relational database | `myapp-prod` (PostgreSQL) running normally |
| File storage (S3) | Active | $0.00 | $0.00 | Object / file storage | 4 buckets healthy |
| Monthly costs | Tracked | $1.14 | $19.40 | Overall account spend | Offset by credits (net -$0.01). Top usage: RDS, VPC |

It never invents numbers — every dollar figure and resource name comes from a real AWS API
call, not the model's guess.

## The safety model

This is the part that actually matters, so it's not an afterthought:

- **Tier 1 (auto-execute)**: reversible, low-risk actions — starting/stopping a resource tagged
  non-production, S3 lifecycle policies, CloudFront cache invalidation.
- **Tier 2 (Slack approval required)**: anything touching a production-tagged resource — posts
  Approve/Reject buttons, executes only after a human clicks.
- **Never available to the agent, at all, architecturally**: IAM, KMS, VPC network rules,
  Organizations/billing settings. These aren't just excluded by a prompt instruction — the
  executor's IAM role has no permissions for them, so there's no code path that could touch them
  even if the model tried.
- **The agent never proposes turning something back on.** If you stop a resource intentionally
  (during a break, off-hours, whatever), it's never auto-flagged as a problem and never
  auto-restarted. Starting something back up only happens via your own explicit `/aws-ops`
  command.
- Every action — proposed, approved, rejected, executed, or failed — is logged to DynamoDB with
  a full audit trail.

See [`src/actions.py`](src/actions.py) for the exact, complete whitelist of everything the agent
is capable of doing. If an action type isn't in that file, the agent cannot do it — there's no
fallback to a general-purpose AWS API call.

## Quickstart

```bash
git clone <this-repo>
cd aws-ops-agent
python3 setup.py
```

The wizard asks about a dozen questions (region, digest cadence, timezone, optional S3 naming
convention to flag, Slack details) and does everything else itself: deploys the IAM roles,
stores your Slack secrets, and runs `sam build && sam deploy`. You don't hand-edit any YAML,
`.env`, or config file.

**Prerequisites**, checked automatically with guidance if missing:
- AWS CLI configured with credentials for the account you want to monitor
- [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- Bedrock model access enabled in your account/region (Bedrock console → Model catalog)
- A Slack app (the wizard walks you through creating one — see below for the manual part)

### Notification channels

Choose Slack, Microsoft Teams, or both — the wizard asks. **A Slack app is always required**
even for a Teams-only setup, since it's what signs the `/aws-ops` command requests and the
Teams approval links. You don't need to set up Slack's Incoming Webhook feature if you're not
using Slack for the digest itself, just the app's Signing Secret.

#### Slack

1. [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**
2. If you want the digest in Slack: **Incoming Webhooks** → toggle on → **Add New Webhook to
   Workspace** → pick your channel
3. **Basic Information** → copy the **Signing Secret** (always needed)
4. Run the wizard, paste what it asks for
5. After deploy, the wizard gives you two URLs to paste into **Interactivity & Shortcuts** and
   **Slash Commands** in the same Slack app → reinstall the app when Slack prompts you

#### Microsoft Teams

Microsoft retired the old Office 365 Connector webhooks in 2026. This uses the current
supported path — **Power Automate Workflows** with **Adaptive Cards**:

1. In the Teams channel → **⋯** → **Workflows**
2. Search for **"Post to a channel when a webhook request is received"** and add it
3. In the trigger setup, choose **"Use a sample payload to generate a schema"** and paste:
   ```json
   {"adaptiveCard": {"type": "AdaptiveCard", "version": "1.5", "body": []}}
   ```
4. Add a **"Post adaptive card in a channel"** action, mapping its Card field to the
   `adaptiveCard` value from the trigger's dynamic content
5. Save, then copy the flow's generated HTTP POST URL — that's what the wizard asks for

**One honest limitation**: Slack's Approve/Reject buttons are real native interactive buttons —
click, done. Teams doesn't have an equivalent without registering a full Bot Framework app,
which is a materially bigger undertaking than a webhook (Azure AD registration, bot hosting, a
Teams app manifest). So Teams approvals use **one-click signed magic links** instead — an
Adaptive Card button that opens a URL, verifies a signature, executes the action, and shows a
confirmation page. Same one click for you; different mechanism under the hood. The `/aws-ops`
slash command is Slack-only for the same reason — full Teams commands need that same bot
registration.

## Manual commands

Once deployed, anyone on the allowlist can type things like:

```
/aws-ops stop-ec2 i-0123456789
/aws-ops start-rds mydb-instance
/aws-ops invalidate-cdn E1234ABCD /images/*
```

Each posts a 60-second confirm button before doing anything — catches typos before they become
outages.

## Cost to run

**Bedrock is the main line item.** Claude Haiku 4.5 on Bedrock runs roughly $1 per million input
tokens and $5 per million output tokens (check [current pricing](https://aws.amazon.com/bedrock/pricing/)
since this changes). Each digest run sends ~3,000-4,000 tokens of input (the prompt plus all the
collected AWS data) and generates ~1,000-1,500 tokens of output — about **$0.01 per run**.

At the default cadence (checks every 3 hours + one daily digest, ~9 runs/day):

```
9 runs/day × 30 days × ~$0.01/run ≈ $2-3/month
```

Everything else — Lambda invocations, DynamoDB on-demand, CloudWatch Logs — adds up to well
under a dollar a month at this scale. No fixed infrastructure cost; everything is serverless and
scales to zero between runs.

**This scales roughly linearly** with how often you check and how many accounts you monitor —
switching to hourly checks or adding a second AWS account both roughly multiply the Bedrock cost
accordingly, but you're still talking single-digit dollars for a small-to-medium setup.

## Architecture

```
EventBridge Scheduler → Digest Lambda → assumes read-only role → collects inventory/cost
                              ↓
                    Claude on Bedrock (forced structured output)
                              ↓
              Tier 1: executes directly     Tier 2: approval required
                              ↓                            ↓
                    Executor Lambda (assumes narrow write role)
                              ↑                            ↑
                Slack Interactions Lambda      Teams Actions Lambda (magic links)
                              ↑                            ↑
                         Slack buttons              Teams Adaptive Card buttons
                              ↓
                         DynamoDB audit log
```

## Extending it

The whitelist in `src/actions.py` is deliberately small to start. Adding a new action type means
adding one function with a tier-classification rule and the specific IAM permission it needs —
never widening what the executor's role can do beyond exactly that.

## License

MIT — use it, fork it, ship it under your own name. See [LICENSE](LICENSE).
