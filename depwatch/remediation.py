"""Generates remediation suggestions for outdated or vulnerable packages."""

from dataclasses import dataclass, field
from typing import List, Optional

from depwatch.reporter import PackageReport


@dataclass
class RemediationSuggestion:
    package: str
    current_version: str
    suggested_version: Optional[str]
    reasons: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [f"Package: {self.package} (installed: {self.current_version})"]
        if self.reasons:
            lines.append("  Reasons: " + ", ".join(self.reasons))
        if self.suggested_version:
            lines.append(f"  Suggested version: {self.suggested_version}")
        for cmd in self.commands:
            lines.append(f"  $ {cmd}")
        return "\n".join(lines)


def build_suggestion(report: PackageReport) -> Optional[RemediationSuggestion]:
    """Return a RemediationSuggestion for a package that needs attention, or None."""
    if not report.needs_attention:
        return None

    reasons: List[str] = []
    commands: List[str] = []

    target_version = report.status.latest_version or report.status.installed_version

    if report.is_vulnerable:
        reasons.append("has known vulnerabilities")
        vuln_ids = ", ".join(v.vuln_id for v in report.vulnerabilities)
        reasons.append(f"CVEs/IDs: {vuln_ids}")

    if report.status.latest_version and (
        report.status.latest_version != report.status.installed_version
    ):
        reasons.append(
            f"outdated ({report.status.installed_version} -> {report.status.latest_version})"
        )

    install_cmd = f"pip install --upgrade {report.status.name}"
    if target_version:
        install_cmd = f"pip install {report.status.name}=={target_version}"
    commands.append(install_cmd)

    return RemediationSuggestion(
        package=report.status.name,
        current_version=report.status.installed_version,
        suggested_version=target_version,
        reasons=reasons,
        commands=commands,
    )


def generate_remediations(reports: List[PackageReport]) -> List[RemediationSuggestion]:
    """Return remediation suggestions for all packages that need attention."""
    suggestions = []
    for report in reports:
        suggestion = build_suggestion(report)
        if suggestion is not None:
            suggestions.append(suggestion)
    return suggestions
