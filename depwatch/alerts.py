"""Alert system for depwatch — sends notifications about outdated or vulnerable packages."""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, field
from typing import List, Optional

from depwatch.checker import PackageStatus

logger = logging.getLogger(__name__)


@dataclass
class AlertConfig:
    """Configuration for sending email alerts."""
    smtp_host: str
    smtp_port: int = 587
    sender_email: str = ""
    recipient_emails: List[str] = field(default_factory=list)
    username: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True


def format_alert_message(statuses: List[PackageStatus]) -> str:
    """Format a list of PackageStatus objects into a human-readable alert message."""
    outdated = [s for s in statuses if s.latest_version and s.current_version != s.latest_version]
    vulnerable = [s for s in statuses if s.is_vulnerable]

    lines = ["depwatch Dependency Alert\n", "=" * 40]

    if vulnerable:
        lines.append("\n⚠️  VULNERABLE PACKAGES:")
        for pkg in vulnerable:
            lines.append(f"  - {pkg.name} {pkg.current_version}: {pkg.vulnerability_info or 'Known vulnerability'}")

    if outdated:
        lines.append("\n📦 OUTDATED PACKAGES:")
        for pkg in outdated:
            lines.append(f"  - {pkg.name}: {pkg.current_version} → {pkg.latest_version}")

    if not vulnerable and not outdated:
        lines.append("\n✅ All packages are up-to-date and secure.")

    lines.append("\n" + "=" * 40)
    return "\n".join(lines)


def send_email_alert(config: AlertConfig, statuses: List[PackageStatus]) -> bool:
    """Send an email alert with the dependency report. Returns True on success."""
    if not config.recipient_emails:
        logger.warning("No recipient emails configured; skipping alert.")
        return False

    body = format_alert_message(statuses)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "depwatch: Dependency Alert"
    msg["From"] = config.sender_email
    msg["To"] = ", ".join(config.recipient_emails)
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port) as server:
            if config.use_tls:
                server.starttls()
            if config.username and config.password:
                server.login(config.username, config.password)
            server.sendmail(config.sender_email, config.recipient_emails, msg.as_string())
        logger.info("Alert email sent to %s", config.recipient_emails)
        return True
    except smtplib.SMTPException as exc:
        logger.error("Failed to send alert email: %s", exc)
        return False
