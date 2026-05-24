"""Formats and prints remediation reports for the CLI."""

from typing import List

from depwatch.remediation import RemediationSuggestion, generate_remediations
from depwatch.reporter import PackageReport


HEADER = "=" * 60
SECTION_SEP = "-" * 40


def format_remediation_report(suggestions: List[RemediationSuggestion]) -> str:
    """Return a human-readable remediation report string."""
    if not suggestions:
        return "No remediation needed. All packages are up-to-date and secure.\n"

    lines = [
        HEADER,
        f"  REMEDIATION REPORT  ({len(suggestions)} package(s) need attention)",
        HEADER,
        "",
    ]

    for suggestion in suggestions:
        lines.append(str(suggestion))
        lines.append(SECTION_SEP)

    lines.append("")
    lines.append(
        f"Run the suggested pip commands above to resolve {len(suggestions)} issue(s)."
    )
    return "\n".join(lines) + "\n"


def report_remediations(reports: List[PackageReport], *, verbose: bool = False) -> str:
    """Generate and format a remediation report from a list of PackageReports."""
    suggestions = generate_remediations(reports)
    report = format_remediation_report(suggestions)
    if verbose and suggestions:
        summary_lines = ["\nSummary of affected packages:"]
        for s in suggestions:
            summary_lines.append(
                f"  - {s.package}: {s.current_version} -> {s.suggested_version or 'N/A'}"
            )
        report += "\n".join(summary_lines) + "\n"
    return report
