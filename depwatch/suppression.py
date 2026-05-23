"""Suppression list for known/accepted vulnerabilities."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class SuppressionEntry:
    """A single suppressed vulnerability."""
    vuln_id: str
    package: str
    reason: str = ""
    expires: Optional[str] = None  # ISO-8601 date string, optional

    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id,
            "package": self.package,
            "reason": self.reason,
            "expires": self.expires,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SuppressionEntry":
        return cls(
            vuln_id=data["vuln_id"],
            package=data["package"],
            reason=data.get("reason", ""),
            expires=data.get("expires"),
        )


@dataclass
class SuppressionList:
    """Collection of suppressed vulnerability entries."""
    entries: List[SuppressionEntry] = field(default_factory=list)

    def is_suppressed(self, vuln_id: str, package: str) -> bool:
        """Return True if the given vuln/package pair is suppressed."""
        return any(
            e.vuln_id == vuln_id and e.package == package
            for e in self.entries
        )

    def to_dict(self) -> dict:
        return {"suppressions": [e.to_dict() for e in self.entries]}

    @classmethod
    def from_dict(cls, data: dict) -> "SuppressionList":
        return cls(
            entries=[
                SuppressionEntry.from_dict(e)
                for e in data.get("suppressions", [])
            ]
        )


def save_suppression_list(sl: SuppressionList, path: Path) -> None:
    path.write_text(json.dumps(sl.to_dict(), indent=2))


def load_suppression_list(path: Path) -> SuppressionList:
    if not path.exists():
        return SuppressionList()
    data = json.loads(path.read_text())
    return SuppressionList.from_dict(data)


def filter_suppressed(reports, suppression_list: SuppressionList):
    """Remove suppressed vulnerabilities from a list of PackageReport objects."""
    from depwatch.reporter import PackageReport  # local import to avoid cycles

    filtered = []
    for report in reports:
        kept_vulns = [
            v for v in report.vulnerabilities
            if not suppression_list.is_suppressed(v.vuln_id, report.name)
        ]
        filtered.append(
            PackageReport(
                name=report.name,
                installed_version=report.installed_version,
                latest_version=report.latest_version,
                vulnerabilities=kept_vulns,
            )
        )
    return filtered
