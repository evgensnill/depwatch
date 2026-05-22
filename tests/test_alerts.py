"""Tests for depwatch.alerts module."""

import unittest
from unittest.mock import patch, MagicMock

from depwatch.alerts import AlertConfig, format_alert_message, send_email_alert
from depwatch.checker import PackageStatus


def _make_status(name, current, latest=None, vulnerable=False, vuln_info=None):
    return PackageStatus(
        name=name,
        current_version=current,
        latest_version=latest,
        is_vulnerable=vulnerable,
        vulnerability_info=vuln_info,
    )


class TestFormatAlertMessage(unittest.TestCase):
    def test_all_up_to_date(self):
        statuses = [_make_status("requests", "2.28.0", "2.28.0")]
        msg = format_alert_message(statuses)
        self.assertIn("up-to-date", msg)
        self.assertNotIn("OUTDATED", msg)
        self.assertNotIn("VULNERABLE", msg)

    def test_outdated_package_listed(self):
        statuses = [_make_status("flask", "2.0.0", "3.0.1")]
        msg = format_alert_message(statuses)
        self.assertIn("OUTDATED", msg)
        self.assertIn("flask", msg)
        self.assertIn("2.0.0", msg)
        self.assertIn("3.0.1", msg)

    def test_vulnerable_package_listed(self):
        statuses = [_make_status("pillow", "9.0.0", vulnerable=True, vuln_info="CVE-2023-1234")]
        msg = format_alert_message(statuses)
        self.assertIn("VULNERABLE", msg)
        self.assertIn("pillow", msg)
        self.assertIn("CVE-2023-1234", msg)

    def test_multiple_packages(self):
        statuses = [
            _make_status("requests", "2.28.0", "2.28.0"),
            _make_status("flask", "2.0.0", "3.0.1"),
            _make_status("pillow", "9.0.0", vulnerable=True),
        ]
        msg = format_alert_message(statuses)
        self.assertIn("OUTDATED", msg)
        self.assertIn("VULNERABLE", msg)

    def test_returns_string(self):
        msg = format_alert_message([])
        self.assertIsInstance(msg, str)


class TestSendEmailAlert(unittest.TestCase):
    def _make_config(self):
        return AlertConfig(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender_email="alerts@example.com",
            recipient_emails=["dev@example.com"],
            username="user",
            password="pass",
        )

    def test_returns_false_with_no_recipients(self):
        config = AlertConfig(smtp_host="smtp.example.com", recipient_emails=[])
        result = send_email_alert(config, [])
        self.assertFalse(result)

    @patch("depwatch.alerts.smtplib.SMTP")
    def test_returns_true_on_success(self, mock_smtp):
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        config = self._make_config()
        statuses = [_make_status("flask", "2.0.0", "3.0.1")]
        result = send_email_alert(config, statuses)
        self.assertTrue(result)
        mock_server.sendmail.assert_called_once()

    @patch("depwatch.alerts.smtplib.SMTP", side_effect=Exception("connection refused"))
    def test_returns_false_on_smtp_error(self, _mock_smtp):
        config = self._make_config()
        result = send_email_alert(config, [])
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
