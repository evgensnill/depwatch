"""Command-line interface for depwatch."""

from __future__ import annotations

import argparse
import sys

from depwatch.reporter import build_report


def _print_report(report) -> None:
    print(report.summary())
    print()

    if report.outdated:
        print("Outdated packages:")
        for pkg in report.outdated:
            print(f"  {pkg.name}: {pkg.installed_version} -> {pkg.latest_version}")
        print()

    if report.vulnerable:
        print("Vulnerable packages:")
        for pkg in report.vulnerable:
            print(f"  {pkg.name} ({pkg.installed_version}):")
            for vuln in pkg.vulnerabilities:
                print(f"    - {vuln}")
        print()

    if not report.has_issues:
        print("All packages are up to date and vulnerability-free.")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depwatch",
        description="Monitor Python dependencies for outdated or vulnerable packages.",
    )
    parser.add_argument(
        "--package",
        metavar="NAME=VERSION",
        nargs="+",
        help="Specific packages to check in NAME=VERSION format.",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if issues are found.",
    )
    return parser


def parse_packages(package_args: list[str]) -> dict[str, str]:
    """Parse NAME=VERSION strings into a dict."""
    result: dict[str, str] = {}
    for item in package_args:
        if "=" not in item:
            raise ValueError(f"Invalid format '{item}'. Expected NAME=VERSION.")
        name, _, version = item.partition("=")
        result[name.strip()] = version.strip()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    packages = None
    if args.package:
        try:
            packages = parse_packages(args.package)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    report = build_report(packages)
    _print_report(report)

    if args.exit_code and report.has_issues:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
