"""
Data types for BSP layer patch discovery.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class PatchSourceType(Enum):
    """How the patch was sourced from the BSP layer."""

    FILE = "file"          # file:// in SRC_URI → .patch on disk
    GIT_FORK = "git_fork"  # vendor kernel fork, patches are commits
    UNKNOWN = "unknown"


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
