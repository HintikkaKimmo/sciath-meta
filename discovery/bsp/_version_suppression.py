"""
Version-based CVE suppression engine.

Given a BSP kernel version (e.g., 6.1.77) and the vulns.git database,
determines which CVEs are already fixed by that version and which are not.

Uses tuple comparison for correctness: (6, 1, 100) > (6, 1, 99).
Fork-based BSPs get "medium" confidence (may not include all stable patches).
"""

from __future__ import annotations

import logging
import os
import re

from discovery.bsp._types import (
    BSPProfile,
    Confidence,
    PatchSourceType,
    SuppressionStatus,
    VersionMatch,
)
from discovery.bsp._vulns_db import VulnEntry

logger = logging.getLogger(__name__)

# Version normalization: strip vendor suffixes, SRCPV, rc tags
_VERSION_RE = re.compile(
    r"(\d+)\.(\d+)(?:\.(\d+))?"  # X.Y or X.Y.Z
)
_RC_RE = re.compile(r"-rc\d+")
_VENDOR_SUFFIX_RE = re.compile(r"[-+].*$")


def _parse_version_tuple(version_str: str) -> tuple[int, ...] | None:
    """Parse a kernel version string into a comparable tuple.

    Handles:
    - Standard: "6.1.77" → (6, 1, 77)
    - Two-segment: "6.6" → (6, 6, 0)
    - Vendor suffix: "6.1.77-toradex-1.0" → (6, 1, 77)
    - SRCPV: "6.1.77+git${SRCPV}" → (6, 1, 77)
    - RC: "6.1.77-rc1" → (6, 1, 76, -1) (less than 6.1.77)

    Returns None if unparseable.
    """
    if not version_str:
        return None

    is_rc = bool(_RC_RE.search(version_str))

    # Strip everything after + or - (except for extracting RC)
    cleaned = _VENDOR_SUFFIX_RE.sub("", version_str)

    match = _VERSION_RE.search(cleaned)
    if not match:
        # Try the original string before vendor stripping
        match = _VERSION_RE.search(version_str)
        if not match:
            return None

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0

    if is_rc:
        # RC versions sort before the release: 6.1.77-rc1 < 6.1.77
        # Represent as (6, 1, 76, -1) so it's less than (6, 1, 77)
        return (major, minor, patch - 1, -1) if patch > 0 else (major, minor - 1, 9999, -1)

    return (major, minor, patch)


def _extract_stable_branch(version_tuple: tuple[int, ...]) -> str:
    """Extract stable branch from a version tuple: (6, 1, 77) → "6.1"."""
    if len(version_tuple) < 2:
        return ""
    return f"{version_tuple[0]}.{version_tuple[1]}"


def _normalize_kernel_version(raw: str) -> str:
    """Normalize a raw kernel version string.

    Strips vendor suffixes, SRCPV, rc tags to get the base version.
    Returns empty string if unparseable.
    """
    tup = _parse_version_tuple(raw)
    if tup is None:
        return ""
    # Don't include RC marker in the normalized string
    if len(tup) > 3:
        # RC version: reconstruct without RC marker
        return f"{tup[0]}.{tup[1]}.{tup[2] + 1}"
    return f"{tup[0]}.{tup[1]}.{tup[2]}"


def parse_kernel_version(profile: BSPProfile) -> tuple[str, str]:
    """Extract (stable_branch, version) from BSP recipe metadata.

    Sources (in priority order):
    1. SCIATH_KERNEL_VERSION env var override
    2. metadata["linux_version"] from recipe parser
    3. metadata["upstream_base_hint"] from forked kernel adapter
    4. PV from recipe filename (e.g., linux-vendor_6.1.77.bb)

    Returns ("6.1", "6.1.77") or ("", "") if not determinable.
    """
    # Env var override
    env_version = os.environ.get("SCIATH_KERNEL_VERSION", "")
    if env_version:
        tup = _parse_version_tuple(env_version)
        if tup:
            normalized = _normalize_kernel_version(env_version)
            return _extract_stable_branch(tup), normalized

    # Try metadata sources in priority order
    for key in ("linux_version", "upstream_base_hint"):
        raw = profile.metadata.get(key, "")
        if raw:
            tup = _parse_version_tuple(raw)
            if tup:
                normalized = _normalize_kernel_version(raw)
                return _extract_stable_branch(tup), normalized

    # Try recipe filename: linux-vendor_6.1.77.bb → 6.1.77
    recipe = profile.kernel_recipe
    if recipe and "_" in recipe:
        version_part = recipe.split("_", 1)[1]
        # Remove .bb extension if present
        version_part = re.sub(r"\.bb$", "", version_part)
        tup = _parse_version_tuple(version_part)
        if tup:
            normalized = _normalize_kernel_version(version_part)
            return _extract_stable_branch(tup), normalized

    return "", ""


def check_version_suppression(
    profile: BSPProfile,
    vulns_db: dict[str, VulnEntry],
) -> list[VersionMatch]:
    """Match BSP kernel version against vulns DB.

    For each CVE in vulns_db:
    1. Find the fixing version for the BSP's stable branch
    2. Compare: if bsp_version >= fixed_in_version → SUPPRESSED
    3. If bsp_version < fixed_in_version → VULNERABLE
    4. If branch not in fixed_in_versions → UNKNOWN

    Fork-based BSPs get Confidence.MEDIUM (may not include all upstream patches).
    """
    if os.environ.get("SCIATH_VERSION_SUPPRESSION", "1") == "0":
        logger.info("Version suppression disabled via SCIATH_VERSION_SUPPRESSION=0")
        return []

    branch, version = parse_kernel_version(profile)
    if not version:
        logger.info("Cannot determine kernel version for %s, skipping suppression",
                     profile.vendor or "unknown vendor")
        return []

    bsp_tuple = _parse_version_tuple(version)
    if bsp_tuple is None:
        return []

    # Determine confidence based on source type
    has_fork = any(p.source_type == PatchSourceType.GIT_FORK for p in profile.patches)
    base_confidence = Confidence.MEDIUM if has_fork else Confidence.HIGH

    matches: list[VersionMatch] = []

    for cve_id, entry in vulns_db.items():
        fix_version_str = entry.fixed_in_versions.get(branch)

        if fix_version_str is None:
            matches.append(VersionMatch(
                cve_id=cve_id,
                fixed_in_version="",
                bsp_version=version,
                stable_branch=branch,
                status=SuppressionStatus.UNKNOWN,
                confidence=Confidence.LOW,
            ))
            continue

        fix_tuple = _parse_version_tuple(fix_version_str)
        if fix_tuple is None:
            continue

        if bsp_tuple >= fix_tuple:
            status = SuppressionStatus.SUPPRESSED
        else:
            status = SuppressionStatus.VULNERABLE

        matches.append(VersionMatch(
            cve_id=cve_id,
            fixed_in_version=fix_version_str,
            bsp_version=version,
            stable_branch=branch,
            status=status,
            confidence=base_confidence,
        ))

    suppressed = sum(1 for m in matches if m.status == SuppressionStatus.SUPPRESSED)
    vulnerable = sum(1 for m in matches if m.status == SuppressionStatus.VULNERABLE)
    unknown = sum(1 for m in matches if m.status == SuppressionStatus.UNKNOWN)

    logger.info(
        "Version suppression for %s on %s: %d suppressed, %d vulnerable, %d unknown "
        "(out of %d CVEs checked)",
        profile.vendor or "unknown", version,
        suppressed, vulnerable, unknown, len(matches),
    )

    return matches
