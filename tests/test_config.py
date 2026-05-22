"""Tests for depwatch.config."""

from __future__ import annotations

import json
import pytest

from depwatch.config import DepwatchConfig, load_config


# ---------------------------------------------------------------------------
# DepwatchConfig unit tests
# ---------------------------------------------------------------------------

class TestDepwatchConfig:
    def test_defaults(self):
        cfg = DepwatchConfig()
        assert cfg.smtp_host == "localhost"
        assert cfg.smtp_port == 587
        assert cfg.alert_recipients == []
        assert cfg.check_vulnerabilities is True
        assert cfg.schedule_interval == 86400

    def test_has_email_config_false_when_no_recipients(self):
        cfg = DepwatchConfig(smtp_host="mail.example.com", alert_recipients=[])
        assert cfg.has_email_config is False

    def test_has_email_config_true_when_host_and_recipients(self):
        cfg = DepwatchConfig(
            smtp_host="mail.example.com",
            alert_recipients=["ops@example.com"],
        )
        assert cfg.has_email_config is True

    def test_has_email_config_false_when_no_host(self):
        cfg = DepwatchConfig(smtp_host="", alert_recipients=["ops@example.com"])
        assert cfg.has_email_config is False


# ---------------------------------------------------------------------------
# load_config tests
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_returns_defaults_when_file_missing(self, tmp_path):
        cfg = load_config(str(tmp_path / "nonexistent.json"))
        assert isinstance(cfg, DepwatchConfig)
        assert cfg.smtp_port == 587

    def test_loads_values_from_file(self, tmp_path):
        config_file = tmp_path / ".depwatch.json"
        config_file.write_text(
            json.dumps({
                "smtp_host": "smtp.example.com",
                "smtp_port": 465,
                "alert_recipients": ["alice@example.com"],
                "check_vulnerabilities": False,
            }),
            encoding="utf-8",
        )
        cfg = load_config(str(config_file))
        assert cfg.smtp_host == "smtp.example.com"
        assert cfg.smtp_port == 465
        assert cfg.alert_recipients == ["alice@example.com"]
        assert cfg.check_vulnerabilities is False

    def test_ignores_unknown_keys(self, tmp_path):
        config_file = tmp_path / ".depwatch.json"
        config_file.write_text(
            json.dumps({"smtp_port": 25, "unknown_key": "ignored"}),
            encoding="utf-8",
        )
        cfg = load_config(str(config_file))
        assert cfg.smtp_port == 25
        assert not hasattr(cfg, "unknown_key")

    def test_raises_on_non_object_json(self, tmp_path):
        config_file = tmp_path / ".depwatch.json"
        config_file.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
        with pytest.raises(ValueError, match="JSON object"):
            load_config(str(config_file))

    def test_env_var_used_as_default_path(self, tmp_path, monkeypatch):
        config_file = tmp_path / "custom.json"
        config_file.write_text(json.dumps({"smtp_port": 2525}), encoding="utf-8")
        monkeypatch.setenv("DEPWATCH_CONFIG", str(config_file))
        cfg = load_config()
        assert cfg.smtp_port == 2525
