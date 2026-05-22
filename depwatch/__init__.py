"""depwatch — Monitors Python project dependencies for outdated or vulnerable packages."""

from depwatch.checker import (
    PackageStatus,
    check_packages,
    fetch_latest_version,
    get_installed_packages,
)

__all__ = [
    "PackageStatus",
    "check_packages",
    "fetch_latest_version",
    "get_installed_packages",
]

__version__ = "0.1.0"
