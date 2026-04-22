"""
Slack-triggered EC2 start/stop/status Lambda.

Security features:
  - HMAC signature verification (Slack signing secret)
  - Replay-attack protection (5-min timestamp window)
  - Constant-time signature comparison
  - Strict command allow-list
  - Slack workspace + channel + user allow-lists
  - Safe form-data parsing (urllib.parse, not naive split)
  - No secrets logged; structured logging only
  - Fails closed on any validation error
  - Ephemeral error responses (visible only to invoker)

Behavior:
  - State-aware start/stop: checks current state before acting
  - Idempotent: tells user if instance is already in desired/transitional state
"""

import hashlib
import hmac
import json
import logging
import os
import time
from urllib.parse import parse_qs

import boto3
from botocore.exceptions import ClientError

# --- Logging (never log secrets or full request bodies) -------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Config (fail fast at cold start if missing) --------------------------
REGION           = os.environ["AWS_REGION_NAME"]
INSTANCE_ID      = os.environ["INSTANCE_ID"]
SIGNING_SECRET   = os.environ["SLACK_SIGNING_SECRET"].encode()

# Comma-separated allow-lists. Leave unset to disable that check.
ALLOWED_TEAM_IDS    = set(filter(None, os.environ.get("ALLOWED_TEAM_IDS", "").split(",")))
ALLOWED_CHANNEL_IDS = set(filter(None, os.environ.get("ALLOWED_CHANNEL_IDS", "").split(",")))
ALLOWED_USER_IDS    = set(filter(None, os.environ.get("ALLOWED_USER_IDS", "").split(",")))

ALLOWED_COMMANDS = {"start", "stop", "status"}
MAX_BODY_BYTES   = 4096          # Slack payloads are small; reject anything larger
REPLAY_WINDOW_S  = 60 * 5        # 5 minutes, per Slack docs

# Human-friendly state emoji
STATE_EMOJI = {
    "running":       ":large_green_circle:",
    "stopped":       ":red_circle:",
    "pending":       ":hourglass_flowing_sand:",
    "stopping":      ":hourglass_flowing_sand:",
    "shutting-down": ":hourglass_flowing_sand:",
    "terminated":    ":skull:",
}

ec2 = boto3.client("ec2", region_name=REGION)


# --- Helpers --------------------------------------------------------------
def _resp(text: str, status: int = 200, ephemeral: bool = True) -> dict:
    """Slack-formatted response. Ephemeral = only the invoker sees it."""
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "response_type": "ephemeral" if ephemeral else "in_channel",
            "text": text,
        }),
    }


def _headers_lower(event: dict) -> dict:
    """Lambda Function URL headers are already lowercased, but normalize anyway."""
    return {k.lower(): v for k, v in (event.get("headers") or {}).items()}


def _verify_slack_signature(headers: dict, raw_body: str) -> bool:
    """Constant-time HMAC-SHA256 verification per Slack's signing spec."""
    ts  = headers.get("x-slack-request-timestamp", "")
    sig = headers.get("x-slack-signature", "")
    if not ts or not sig:
        return False
    try:
        if abs(time.time() - int(ts)) > REPLAY_WINDOW_S:
            return False
    except ValueError:
        return False

    basestring = f"v0:{ts}:{raw_body}".encode()
    expected   = "v0=" + hmac.new(SIGNING_SECRET, basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def _parse_form(raw_body: str) -> dict:
    """Safely parse application/x-www-form-urlencoded body into a flat dict."""
    parsed = parse_qs(raw_body, keep_blank_values=True, strict_parsing=False)
    return {k: v[0] for k, v in parsed.items()}


def _get_instance_state() -> str:
    """Return current instance state: running | stopped | pending | stopping | etc."""
    resp = ec2.describe_instances(InstanceIds=[INSTANCE_ID])
    return resp["Reservations"][0]["Instances"][0]["State"]["Name"]


def _emoji(state: str) -> str:
    return STATE_EMOJI.get(state, ":grey_question:")


# --- Command handlers -----------------------------------------------------
def _handle_start(user_id: str) -> dict:
    state = _get_instance_state()

    if state == "running":
        return _resp(
            f":large_green_circle: `{INSTANCE_ID}` is *already running* — no action taken.",
        )
    if state == "pending":
        return _resp(
            f":hourglass_flowing_sand: `{INSTANCE_ID}` is *already starting up* — please wait.",
        )
    if state == "stopping":
        return _resp(
            f":warning: `{INSTANCE_ID}` is currently *stopping*. Wait until it's fully stopped before starting it again.",
        )
    if state == "terminated":
        return _resp(
            f":skull: `{INSTANCE_ID}` is *terminated* and cannot be started.",
        )
    if state != "stopped":
        return _resp(
            f":warning: `{INSTANCE_ID}` is in state *{state}*. Cannot start right now.",
        )

    # state == "stopped" → actually start it
    ec2.start_instances(InstanceIds=[INSTANCE_ID])
    return _resp(
        f":white_check_mark: Starting `{INSTANCE_ID}` (requested by <@{user_id}>)",
        ephemeral=False,
    )


def _handle_stop(user_id: str) -> dict:
    state = _get_instance_state()

    if state == "stopped":
        return _resp(
            f":red_circle: `{INSTANCE_ID}` is *already stopped* — no action taken.",
        )
    if state == "stopping":
        return _resp(
            f":hourglass_flowing_sand: `{INSTANCE_ID}` is *already stopping* — please wait.",
        )
    if state == "pending":
        return _resp(
            f":warning: `{INSTANCE_ID}` is currently *starting up*. Wait until it's running before stopping it.",
        )
    if state == "terminated":
        return _resp(
            f":skull: `{INSTANCE_ID}` is *terminated*.",
        )
    if state != "running":
        return _resp(
            f":warning: `{INSTANCE_ID}` is in state *{state}*. Cannot stop right now.",
        )

    # state == "running" → actually stop it
    ec2.stop_instances(InstanceIds=[INSTANCE_ID])
    return _resp(
        f":octagonal_sign: Stopping `{INSTANCE_ID}` (requested by <@{user_id}>)",
        ephemeral=False,
    )


def _handle_status() -> dict:
    state = _get_instance_state()
    return _resp(
        f"{_emoji(state)} `{INSTANCE_ID}` is *{state}*",
        ephemeral=False,
    )


# --- Handler --------------------------------------------------------------
def lambda_handler(event, context):
    # 1. Size guard (cheap DoS protection)
    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64
        try:
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        except Exception:
            return _resp(":x: Bad request.", 400)

    if len(raw_body.encode("utf-8")) > MAX_BODY_BYTES:
        return _resp(":x: Request too large.", 413)

    # 2. Slack signature verification (MUST use raw body)
    headers = _headers_lower(event)
    if not _verify_slack_signature(headers, raw_body):
        logger.warning("Slack signature verification failed")
        return _resp(":x: Unauthorized.", 401)

    # 3. Parse Slack payload
    form = _parse_form(raw_body)
    team_id    = form.get("team_id", "")
    channel_id = form.get("channel_id", "")
    user_id    = form.get("user_id", "")
    user_name  = form.get("user_name", "unknown")
    command    = form.get("command", "")
    text       = form.get("text", "").strip().lower()

    # 4. Authorization allow-lists (fail closed if configured)
    if ALLOWED_TEAM_IDS and team_id not in ALLOWED_TEAM_IDS:
        logger.warning("Blocked team_id=%s user=%s", team_id, user_id)
        return _resp(":no_entry: This workspace is not authorized.", 403)
    if ALLOWED_CHANNEL_IDS and channel_id not in ALLOWED_CHANNEL_IDS:
        return _resp(":no_entry: This command cannot be used in this channel.", 403)
    if ALLOWED_USER_IDS and user_id not in ALLOWED_USER_IDS:
        logger.warning("Blocked user=%s (%s)", user_id, user_name)
        return _resp(":no_entry: You are not authorized to run this command.", 403)

    # 5. Strict command allow-list
    if text not in ALLOWED_COMMANDS:
        return _resp(
            f"Usage: `{command or '/ec2'} start` | `stop` | `status`",
        )

    # 6. Execute — audit log before the call
    logger.info(
        "ec2_action user=%s user_id=%s channel=%s action=%s instance=%s",
        user_name, user_id, channel_id, text, INSTANCE_ID,
    )

    try:
        if text == "start":
            return _handle_start(user_id)
        if text == "stop":
            return _handle_stop(user_id)
        return _handle_status()

    except ClientError as e:
        logger.error("EC2 API error: %s", e, exc_info=True)
        code = e.response.get("Error", {}).get("Code", "Unknown")
        return _resp(f":x: AWS error (`{code}`). Check CloudWatch logs.", 500)
    except Exception:
        logger.exception("Unhandled error")
        return _resp(":x: Internal error.", 500)