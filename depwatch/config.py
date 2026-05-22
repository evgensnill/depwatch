"""Configuration loading and validation for depwatch."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


DEFAULT_CONFIG_FILENAME = ".depwatch.json"


@dataclass
class DepwatchConfig:
    """Top-level depwatch configuration."""

    # Email alert settings
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_recipients: List[str] = field(default_factory=list)
    alert_sender: str = "depwatch@localhost"

    # Scanning behaviour
    check_vulnerabilities: bool = True
    ignore_packages: List[str] = field(default_factory=list)

    # Scheduler settings (seconds)
    schedule_interval: int = 86400  # 24 hours

    @property
    def has_email_config(self) -> bool:
        """Return True when enough email settings are present to send alerts."""
        return bool(self.smtp_host and self.alert_recipients)


def load_config(path: Optional[str] = None) -> DepwatchConfig:
    """Load configuration from *path* or the default config file.

    Falls back to an all-defaults :class:`DepwatchConfig` when no file is
    found.
    """
    if path is None:
        path = os.environ.get("DEPWATCH_CONFIG", DEFAULT_CONFIG_FILENAME)

    config_path = Path(path)
    if not config_path.exists():
        return DepwatchConfig()

    with config_path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"Config file {path!r} must contain a JSON object.")

    known_fields = DepwatchConfig.__dataclass_fields__.keys()  # type: ignore[attr-defined]
    filtered = {k: v for k, v in raw.items() if k in known_fields}
    return DepwatchConfig(**filtered)
