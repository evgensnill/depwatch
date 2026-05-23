"""Unit tests for the NotificationResult dataclass."""

from __future__ import annotations

from depwatch.notifier import NotificationResult


class TestNotificationResult:
    def test_defaults_empty_recipients(self):
        result = NotificationResult(sent=False, reason="no config")
        assert result.recipients == []

    def test_sent_true_stores_recipients(self):
        result = NotificationResult(
            sent=True,
            reason="ok",
            recipients=["a@b.com", "c@d.com"],
        )
        assert len(result.recipients) == 2
        assert "a@b.com" in result.recipients

    def test_sent_flag_is_preserved(self):
        r_sent = NotificationResult(sent=True, reason="ok")
        r_not_sent = NotificationResult(sent=False, reason="skip")
        assert r_sent.sent is True
        assert r_not_sent.sent is False

    def test_reason_is_preserved(self):
        result = NotificationResult(sent=False, reason="email not configured")
        assert result.reason == "email not configured"

    def test_recipients_are_independent_between_instances(self):
        r1 = NotificationResult(sent=True, reason="ok", recipients=["x@y.com"])
        r2 = NotificationResult(sent=False, reason="skip")
        r2.recipients.append("z@w.com")
        assert r1.recipients == ["x@y.com"]
