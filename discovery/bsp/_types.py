"""
Data types for BSP layer patch discovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class PatchSourceType(Enum):
    """How the patch was sourced from the BSP layer."""

    FILE = "file"          # file:// in SRC_URI → .patch on disk
    GIT_FORK = "git_fork"  # vendor kernel fork, patches are commits
    UNKNOWN = "unknown"


class SuppressionStatus(str, Enum):
    """Result of version-based CVE suppression check."""

    SUPPRESSED = "suppressed"   # BSP version >= fix version → CVE fixed
    VULNERABLE = "vulnerable"   # BSP version < fix version → CVE NOT fixed
    UNKNOWN = "unknown"         # fix not on this stable branch


class Confidence(str, Enum):
    """Confidence level for suppression and patch matches."""

    HIGH = "high"      # exact version match, file patch with CVE tag
    MEDIUM = "medium"  # fork (may not include all stable patches), file patch without CVE tag
    LOW = "low"        # AUTOREV, ambiguous version, reference only


@dataclass(frozen=True)
class VersionMatch:
    """Result of comparing a BSP kernel version against a vulns.git CVE fix."""

    cve_id: str
    fixed_in_version: str    # e.g. "6.1.75"
    bsp_version: str         # e.g. "6.1.77"
    stable_branch: str       # e.g. "6.1"
    status: SuppressionStatus = SuppressionStatus.UNKNOWN
    confidence: Confidence = Confidence.HIGH


@dataclass(frozen=True)
class PatchInfo:
    """A single discovered kernel/BSP patch.

    Frozen: once discovered, patch metadata does not change. The diff
    fingerprinter creates its own result objects with match information.
    """

    name: str
    source_type: PatchSourceType
    path: Path | None = None       # FILE type only — absolute, validated
    git_url: str = ""              # GIT_FORK type only
    commit_hash: str = ""          # SRCREV value
    recipe: str = ""               # originating recipe (e.g. "linux-raspberrypi")
    layer: str = ""                # originating layer name
    confidence: str = "high"       # "high", "medium", "low" — see Confidence Spec


@dataclass
class BSPProfile:
    """Full BSP patch analysis result.

    Confidence levels:
      high   — .patch file exists on disk + CVE tag in header/filename
               Consumer: auto-suppress in filter pipeline
      medium — .patch file exists on disk, no CVE tag
               Consumer: include in suppression report, not auto-suppressed
      low    — reference only (git fork URL, unresolved path, generic fallback)
               Consumer: flag for manual review
    """

    vendor: str = ""
    vendor_layer: str = ""
    adapter_used: str = ""
    kernel_recipe: str = ""
    kernel_src_uri: str = ""
    kernel_srcrev: str = ""
    patches: list[PatchInfo] = field(default_factory=list)
    version_matches: list[VersionMatch] = field(default_factory=list)
    kernel_version_detected: str = ""    # e.g. "6.1.77"
    kernel_branch_detected: str = ""     # e.g. "6.1"
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def patch_count(self) -> int:
        return len(self.patches)

    @property
    def file_patch_count(self) -> int:
        return sum(1 for p in self.patches if p.source_type == PatchSourceType.FILE)

    @property
    def fork_patch_count(self) -> int:
        return sum(1 for p in self.patches if p.source_type == PatchSourceType.GIT_FORK)

    @property
    def suppressed_cves(self) -> set[str]:
        """CVEs suppressed by version match."""
        return {m.cve_id for m in self.version_matches
                if m.status == SuppressionStatus.SUPPRESSED}

    @property
    def vulnerable_cves(self) -> set[str]:
        """CVEs explicitly NOT fixed (version < fix version)."""
        return {m.cve_id for m in self.version_matches
                if m.status == SuppressionStatus.VULNERABLE}
