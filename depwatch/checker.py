"""Core dependency checker module for depwatch.

Fetches installed package versions and checks for newer releases on PyPI.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
from dataclasses import dataclass, field
from typing import Optional

import requests

PYPI_URL = "https://pypi.org/pypi/{package}/json"
REQUEST_TIMEOUT = 10  # seconds


@dataclass
class PackageStatus:
    name: str
    installed_version: str
    latest_version: Optional[str] = None
    is_outdated: bool = False
    error: Optional[str] = None


def get_installed_packages() -> dict[str, str]:
    """Return a mapping of package name -> installed version."""
    return {
        dist.metadata["Name"]: dist.version
        for dist in importlib_metadata.distributions()
        if dist.metadata.get("Name")
    }


def fetch_latest_version(package_name: str) -> Optional[str]:
    """Query PyPI for the latest stable version of a package."""
    url = PYPI_URL.format(package=package_name)
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        return data["info"]["version"]
    except requests.RequestException:
        return None


def check_packages(packages: dict[str, str]) -> list[PackageStatus]:
    """Check a dict of {name: installed_version} against PyPI.

    Returns a list of PackageStatus objects.
    """
    results: list[PackageStatus] = []
    for name, installed in packages.items():
        latest = fetch_latest_version(name)
        if latest is None:
            status = PackageStatus(
                name=name,
                installed_version=installed,
                error=f"Could not fetch info for '{name}' from PyPI",
            )
        else:
            status = PackageStatus(
                name=name,
                installed_version=installed,
                latest_version=latest,
                is_outdated=installed != latest,
            )
        results.append(status)
    return results
