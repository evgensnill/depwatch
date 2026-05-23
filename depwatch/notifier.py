"""Notifier module: decides when and how to send alerts based on scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from depwatch.alerts import AlertConfig, format_alert_message, send_email_alert
from depwatch.config import DepwatchConfig
from depwatch.reporter import PackageReport


@dataclass
class NotificationResult:
    """Outcome of a notification attempt."""

    sent: bool
    reason: str
    recipients: List[str] = field(default_factory=list)


def should_notify(reports: List[PackageReport], config: DepwatchConfig) -> bool:
    """Return True if at least one package needs attention and email is configured."""
    if not config.has_email_config():
        return False
    return any(r.needs_attention() for r in reports)


def notify(reports: List[PackageReport], config: DepwatchConfig) -> NotificationResult:
    """Send an alert email when packages need attention.

    Returns a NotificationResult describing what happened.
    """
    if not config.has_email_config():
        return NotificationResult(sent=False, reason="email not configured")

    if not any(r.needs_attention() for r in reports):
        return NotificationResult(sent=False, reason="no packages need attention")

    alert_cfg = AlertConfig(
        smtp_host=config.smtp_host,
        smtp_port=config.smtp_port,
        sender=config.smtp_sender,
        recipients=config.recipients,
    )

    statuses = [r.status for r in reports]
    body = format_alert_message(statuses)
    send_email_alert(alert_cfg, body)

    return NotificationResult(
        sent=True,
        reason="alert dispatched",
        recipients=list(config.recipients),
    )
