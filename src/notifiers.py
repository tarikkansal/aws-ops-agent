"""
Notification layer - sends the digest and approval requests to whichever
channel(s) are configured (Slack, Microsoft Teams, or both). digest.py never
talks to Slack or Teams directly; it calls the functions in this file.

Slack uses native Block Kit (table blocks + Interactivity for approve/reject
buttons - a real, immediate button click).

Teams uses Adaptive Cards delivered through a Power Automate Workflow
webhook (the old Office 365 Connector webhooks were retired by Microsoft in
May 2026). Teams approve/reject uses signed one-click magic links instead of
native interactive buttons, since true button interactivity in Teams needs a
registered Bot Framework app - a materially bigger scope than a webhook.
Functionally the same one click for the user; different mechanism under the
hood, documented here rather than silently glossed over.
"""

import os
import json
import hmac
import hashlib
import time
import urllib.request
import boto3

NOTIFICATION_CHANNELS = {c.strip().lower() for c in os.environ.get("NOTIFICATION_CHANNELS", "slack").split(",") if c.strip()}
SLACK_WEBHOOK_SECRET_ARN = os.environ.get("SLACK_WEBHOOK_SECRET_ARN", "")
TEAMS_WEBHOOK_SECRET_ARN = os.environ.get("TEAMS_WEBHOOK_SECRET_ARN", "")
TEAMS_ACTIONS_URL = os.environ.get("TEAMS_ACTIONS_URL", "")  # base URL of the magic-link endpoint
LINK_SIGNING_SECRET_ARN = os.environ.get("SLACK_SIGNING_SECRET_ARN", "")  # reused to sign Teams magic links

secrets = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION", "us-east-1"))
_secret_cache = {}


def _get_secret(arn):
    if not arn:
        return None
    if arn not in _secret_cache:
        _secret_cache[arn] = secrets.get_secret_value(SecretId=arn)["SecretString"]
    return _secret_cache[arn]


def _post_json(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)


def sign_magic_link(action_id, decision, expires_at):
    """HMAC-signs a Teams approval magic link so it can't be forged or
    replayed after expiry - same signing secret used for Slack's request
    verification, repurposed here since it's already a securely-stored,
    per-deployment secret."""
    secret = _get_secret(LINK_SIGNING_SECRET_ARN) or ""
    message = f"{action_id}:{decision}:{expires_at}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_magic_link(action_id, decision, expires_at, signature):
    if int(time.time()) > int(expires_at):
        return False
    expected = sign_magic_link(action_id, decision, expires_at)
    return hmac.compare_digest(expected, signature)


# ---------- Slack ----------

def _slack_status_table_text(table_block):
    return table_block  # already Slack Block Kit table block, passed straight through


def post_slack_digest(header, opening_line, emoji, table_block, action_results):
    webhook_url = _get_secret(SLACK_WEBHOOK_SECRET_ARN)
    if not webhook_url:
        return
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{emoji} {opening_line}"}},
    ]
    if table_block:
        blocks.append(table_block)
    if action_results:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*What changed:*\n" + "\n".join(f"- {r}" for r in action_results)}})
    _post_json(webhook_url, {"blocks": blocks})


def post_slack_approval(action_id, action_type, resource, reason):
    webhook_url = _get_secret(SLACK_WEBHOOK_SECRET_ARN)
    if not webhook_url:
        return
    payload = {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Approval needed:* `{action_type}` on *{resource}*\n{reason}"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "Approve"}, "style": "primary", "value": f"approve:{action_id}", "action_id": "approve_action"},
                {"type": "button", "text": {"type": "plain_text", "text": "Reject"}, "style": "danger", "value": f"reject:{action_id}", "action_id": "reject_action"},
            ]},
        ]
    }
    _post_json(webhook_url, payload)


# ---------- Microsoft Teams (Adaptive Cards via Power Automate Workflow) ----------

def _service_status_to_adaptive_table(service_status, cost_columns, format_dollar_fn, purpose_map):
    columns = [{"width": 2}, {"width": 1}, {"width": 1}, {"width": 1}, {"width": 2}, {"width": 3}]
    header_cells = [
        {"type": "TableCell", "items": [{"type": "TextBlock", "text": t, "weight": "Bolder", "wrap": True}]}
        for t in ["Service", "Status", "Cost/Day", "Cost MTD", "What it's for", "Notes"]
    ]
    rows = [{"type": "TableRow", "cells": header_cells}]
    for s in service_status:
        row_name = s.get("service", "Unknown")
        cells = [
            row_name,
            s.get("status", ""),
            format_dollar_fn(cost_columns, row_name, "per_day"),
            format_dollar_fn(cost_columns, row_name, "mtd"),
            purpose_map.get(row_name, "-"),
            s.get("note", ""),
        ]
        rows.append({"type": "TableRow", "cells": [
            {"type": "TableCell", "items": [{"type": "TextBlock", "text": str(c), "wrap": True}]} for c in cells
        ]})
    return {"type": "Table", "columns": columns, "rows": rows, "firstRowAsHeaders": True}


def post_teams_digest(header, opening_line, emoji, service_status, cost_columns, action_results, format_dollar_fn, purpose_map):
    webhook_url = _get_secret(TEAMS_WEBHOOK_SECRET_ARN)
    if not webhook_url:
        return
    body = [
        {"type": "TextBlock", "text": header, "weight": "Bolder", "size": "Medium"},
        {"type": "TextBlock", "text": f"{emoji} {opening_line}", "wrap": True},
    ]
    if service_status:
        body.append(_service_status_to_adaptive_table(service_status, cost_columns, format_dollar_fn, purpose_map))
    if action_results:
        body.append({"type": "TextBlock", "text": "**What changed:**\n" + "\n".join(f"- {r}" for r in action_results), "wrap": True})

    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.5",
        "body": body,
    }
    # Sent as {"adaptiveCard": {...}} - the Power Automate flow's trigger schema
    # (set up via "generate from sample payload") maps this straight into a
    # "Post adaptive card" action. See README for the exact flow setup.
    _post_json(webhook_url, {"adaptiveCard": card})


def post_teams_approval(action_id, action_type, resource, reason):
    webhook_url = _get_secret(TEAMS_WEBHOOK_SECRET_ARN)
    if not webhook_url or not TEAMS_ACTIONS_URL:
        return
    expires_at = int(time.time()) + 600  # 10 minutes - longer than Slack's 60s since there's an extra browser hop
    approve_sig = sign_magic_link(action_id, "approve", expires_at)
    reject_sig = sign_magic_link(action_id, "reject", expires_at)
    approve_url = f"{TEAMS_ACTIONS_URL}?id={action_id}&decision=approve&expires={expires_at}&sig={approve_sig}"
    reject_url = f"{TEAMS_ACTIONS_URL}?id={action_id}&decision=reject&expires={expires_at}&sig={reject_sig}"

    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.5",
        "body": [
            {"type": "TextBlock", "text": "Approval needed", "weight": "Bolder"},
            {"type": "TextBlock", "text": f"**{action_type}** on **{resource}**\n{reason}", "wrap": True},
        ],
        "actions": [
            {"type": "Action.OpenUrl", "title": "Approve", "url": approve_url},
            {"type": "Action.OpenUrl", "title": "Reject", "url": reject_url},
        ],
    }
    _post_json(webhook_url, {"adaptiveCard": card})


# ---------- Dispatch ----------

def post_digest(opening_line, emoji, service_status, cost_columns, table_block, action_results, mode, company_name, format_dollar_fn=None, purpose_map=None):
    label = f"{company_name} " if company_name else ""
    header = f"Your {label}AWS check-in - today" if mode == "daily" else f"{label}AWS update"
    if "slack" in NOTIFICATION_CHANNELS:
        post_slack_digest(header.strip(), opening_line, emoji, table_block, action_results)
    if "teams" in NOTIFICATION_CHANNELS:
        post_teams_digest(header.strip(), opening_line, emoji, service_status, cost_columns, action_results, format_dollar_fn, purpose_map)


def post_approval_request(action_id, action_type, resource, reason):
    if "slack" in NOTIFICATION_CHANNELS:
        post_slack_approval(action_id, action_type, resource, reason)
    if "teams" in NOTIFICATION_CHANNELS:
        post_teams_approval(action_id, action_type, resource, reason)
