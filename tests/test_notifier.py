"""Tests for depwatch.notifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from depwatch.notifier import NotificationResult, notify, should_notify
from depwatch.reporter import PackageReport
from depwatch.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(has_email: bool = True):
    cfg = MagicMock()
    cfg.has_email_config.return_value = has_email
    cfg.smtp_host = "smtp.example.com"
    cfg.smtp_port = 587
    cfg.smtp_sender = "bot@example.com"
    cfg.recipients = ["dev@example.com"]
    return cfg


def _make_report(outdated: bool = False, vulns=None):
    from depwatch.checker import PackageStatus

    status = PackageStatus(
        name="requests",
        installed="2.27.0",
        latest="2.31.0" if outdated else "2.27.0",
        vulnerabilities=vulns or [],
    )
    return PackageReport(status=status)


# ---------------------------------------------------------------------------
# should_notify
# ---------------------------------------------------------------------------

class TestShouldNotify:
    def test_false_when_email_not_configured(self):
        cfg = _make_config(has_email=False)
        report = _make_report(outdated=True)
        assert should_notify([report], cfg) is False

    def test_false_when_no_packages_need_attention(self):
        cfg = _make_config()
        report = _make_report(outdated=False)
        assert should_notify([report], cfg) is False

    def test_true_when_outdated_and_email_configured(self):
        cfg = _make_config()
        report = _make_report(outdated=True)
        assert should_notify([report], cfg) is True

    def test_true_when_vulnerable_and_email_configured(self):
        cfg = _make_config()
        vuln = Vulnerability(id="CVE-2023-0001", summary="bug", severity="HIGH")
        report = _make_report(vulns=[vuln])
        assert should_notify([report], cfg) is True


# ---------------------------------------------------------------------------
# notify
# ---------------------------------------------------------------------------

class TestNotify:
    def test_returns_not_sent_when_no_email_config(self):
        cfg = _make_config(has_email=False)
        result = notify([_make_report(outdated=True)], cfg)
        assert result.sent is False
        assert "email" in result.reason

    def test_returns_not_sent_when_nothing_needs_attention(self):
        cfg = _make_config()
        result = notify([_make_report(outdated=False)], cfg)
        assert result.sent is False
        assert "attention" in result.reason

    @patch("depwatch.notifier.send_email_alert")
    @patch("depwatch.notifier.format_alert_message", return_value="body text")
    def test_sends_email_and_returns_sent(self, mock_fmt, mock_send):
        cfg = _make_config()
        report = _make_report(outdated=True)
        result = notify([report], cfg)

        assert result.sent is True
        assert result.recipients == ["dev@example.com"]
        mock_send.assert_called_once()
        mock_fmt.assert_called_once()

    @patch("depwatch.notifier.send_email_alert")
    @patch("depwatch.notifier.format_alert_message", return_value="body")
    def test_notification_result_reason_on_success(self, _fmt, _send):
        cfg = _make_config()
        result = notify([_make_report(outdated=True)], cfg)
        assert "dispatched" in result.reason
