"""Aggregates checker and vulnerability results into a unified report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from depwatch.checker import PackageStatus, check_packages, get_installed_packages
from depwatch.vulnerability import Vulnerability, scan_packages


@dataclass
class PackageReport:
    """Full report entry for a single package."""

    name: str
    installed_version: str
    latest_version: str
    is_outdated: bool
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def needs_attention(self) -> bool:
        return self.is_outdated or self.is_vulnerable


@dataclass
class Report:
    """Top-level report aggregating all package results."""

    packages: List[PackageReport] = field(default_factory=list)

    @property
    def outdated(self) -> List[PackageReport]:
        return [p for p in self.packages if p.is_outdated]

    @property
    def vulnerable(self) -> List[PackageReport]:
        return [p for p in self.packages if p.is_vulnerable]

    @property
    def has_issues(self) -> bool:
        return bool(self.outdated or self.vulnerable)

    def summary(self) -> str:
        total = len(self.packages)
        out = len(self.outdated)
        vuln = len(self.vulnerable)
        return (
            f"Scanned {total} package(s): "
            f"{out} outdated, {vuln} vulnerable."
        )


def build_report(packages: Dict[str, str] | None = None) -> Report:
    """Build a full dependency report.

    Args:
        packages: Optional mapping of name -> version. If None, uses installed packages.

    Returns:
        A Report instance with all findings.
    """
    if packages is None:
        packages = get_installed_packages()

    statuses: List[PackageStatus] = check_packages(packages)
    vuln_map = scan_packages(packages)

    status_by_name = {s.name: s for s in statuses}
    report_packages = []
    for name, version in packages.items():
        status = status_by_name.get(name)
        latest = status.latest_version if status else version
        outdated = status.is_outdated if status else False
        report_packages.append(
            PackageReport(
                name=name,
                installed_version=version,
                latest_version=latest,
                is_outdated=outdated,
                vulnerabilities=vuln_map.get(name, []),
            )
        )

    return Report(packages=report_packages)
