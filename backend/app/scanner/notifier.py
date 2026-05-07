import json
import logging
import smtplib
from email.message import EmailMessage

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger("vulnscan.notifier")


def _get_session():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def send_slack_notification(config: dict, message) -> bool:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        logger.error("Slack integration missing webhook_url")
        return False

    if isinstance(message, dict):
        payload = message
        payload.setdefault("text", "VulnScan notification")
    else:
        payload = {"text": str(message)}

    try:
        session = _get_session()
        resp = session.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error("Failed to send Slack notification: %s", e)
        return False


def send_teams_notification(config: dict, message) -> bool:
    """Send notification to Microsoft Teams via Incoming Webhook."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        logger.error("Teams integration missing webhook_url")
        return False

    # Teams Adaptive Card format
    if isinstance(message, dict) and "type" in message:
        # Already an Adaptive Card payload
        payload = message
    elif isinstance(message, dict):
        # Build Adaptive Card from structured data
        facts = []
        for k, v in message.items():
            if k not in ("title", "text", "blocks"):
                facts.append({"title": str(k), "value": str(v)})

        payload = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": message.get("title", "VulnScan Notification"),
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": message.get("text", str(message)),
                            "wrap": True,
                        },
                    ] + ([{
                        "type": "FactSet",
                        "facts": facts,
                    }] if facts else []),
                },
            }],
        }
    else:
        # Simple text message
        payload = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [{
                        "type": "TextBlock",
                        "text": str(message),
                        "wrap": True,
                    }],
                },
            }],
        }

    try:
        session = _get_session()
        resp = session.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error("Failed to send Teams notification: %s", e)
        return False


def send_webhook_notification(config: dict, payload: dict) -> bool:
    url = config.get("url")
    if not url:
        logger.error("Webhook integration missing url")
        return False

    secret = config.get("secret", "")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"

    try:
        session = _get_session()
        resp = session.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error("Failed to send Webhook notification: %s", e)
        return False


def send_email_notification(config: dict, subject: str, body: str) -> bool:
    smtp_host = config.get("smtp_host")
    smtp_port = config.get("smtp_port", 587)
    smtp_user = config.get("smtp_user")
    smtp_pass = config.get("smtp_pass")
    from_email = config.get("from_email", "vulnscan@noreply.local")
    to_email = config.get("to_email")

    if not all([smtp_host, to_email]):
        logger.error("Email integration missing smtp_host or to_email")
        return False

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        if smtp_pass:
            # Assume TLS
            with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            # Unauthenticated open relay
            with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as server:
                server.send_message(msg)
        return True
    except Exception as e:
        logger.error("Failed to send Email notification: %s", e)
        return False


def dispatch_test_notification(provider: str, config: dict) -> bool:
    if provider == "slack":
        return send_slack_notification(config, "Test notification from VulnScan Platform!")
    elif provider == "teams":
        return send_teams_notification(config, "Test notification from VulnScan Platform!")
    elif provider == "webhook":
        return send_webhook_notification(config, {"event": "test", "message": "Test notification from VulnScan Platform!"})
    elif provider == "email":
        return send_email_notification(config, "VulnScan Test", "This is a test notification from the VulnScan Platform.")

    logger.error("Unknown integration provider: %s", provider)
    return False


def should_notify(prefs: dict, event_types: list[str], provider: str) -> bool:
    """Check if any of the given event_types is enabled for this provider in preferences.

    Maps 'teams' provider to 'slack' preference channel since the UI only
    exposes email/slack/webhook and Teams uses the Slack column.
    """
    channel = "slack" if provider == "teams" else provider
    for event_type in event_types:
        event_prefs = prefs.get(event_type)
        if event_prefs and event_prefs.get(channel, False):
            return True
    return False
