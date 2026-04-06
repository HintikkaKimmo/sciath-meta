"""
Linux kernel vulns.git database parser and loader.

Parses the stream/ directory from git.kernel.org/pub/scm/linux/security/vulns.git
and produces a JSON database mapping CVE IDs to fixing commits and the stable
kernel versions they first appeared in.

The vulns_db.json file is shipped pre-built. The ingestion script
(scripts/ingest_vulns.py) regenerates it from a fresh vulns.git clone.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Default location for the pre-built vulns DB
_DEFAULT_VULNS_DB = Path(__file__).parent.parent / "bsp_data" / "vulns_db.json"

# CVE ID pattern
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# Version pattern for extracting branch: "6.1.77" → "6.1"
_VERSION_BRANCH_RE = re.compile(r"^(\d+\.\d+)\.\d+$")


@dataclass
class VulnEntry:
    """A single CVE entry from vulns.git."""

    cve_id: str
    fixing_commits: list[str] = field(default_factory=list)
    fixed_in_versions: dict[str, str] = field(default_factory=dict)

    @property
    def single_commit(self) -> bool:
        return len(self.fixing_commits) == 1


def ingest_vulns_git(vulns_repo_path: Path) -> dict[str, VulnEntry]:
    """Parse vulns.git CVE JSON files into a lookup dict keyed by CVE ID.

    The repo uses CVE JSON 5.0 format. Each CVE has two affected blocks:
    1. Git commit ranges (versionType="git") with fixing commit hashes
    2. Semver ranges (versionType="semver") with stable version numbers

    The semver "unaffected" entries give us fixed_in_versions directly:
    {"version": "6.1.75", "lessThanOrEqual": "6.1.*", "status": "unaffected"}
    means the CVE is fixed starting at version 6.1.75.

    Returns empty dict on error.
    """
    published_dir = vulns_repo_path / "cve" / "published"
    if not published_dir.is_dir():
        logger.warning("vulns.git cve/published/ directory not found at %s",
                       vulns_repo_path)
        return {}

    entries: dict[str, VulnEntry] = {}

    for json_file in published_dir.rglob("*.json"):
        if "schema" in json_file.name.lower():
            continue

        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Cannot parse %s: %s", json_file.name, e)
            continue

        # Extract CVE ID from filename
        cve_match = _CVE_RE.search(json_file.stem)
        if not cve_match:
            continue
        cve_id = cve_match.group(0)

        fixing_commits: list[str] = []
        fixed_in_versions: dict[str, str] = {}

        for affected in data.get("containers", {}).get("cna", {}).get("affected", []):
            for v in affected.get("versions", []):
                vtype = v.get("versionType", "")
                status = v.get("status", "")

                # Git fix commits
                if vtype == "git" and status == "affected" and "lessThan" in v:
                    commit = v["lessThan"]
                    if len(commit) == 40:
                        fixing_commits.append(commit)

                # Semver fix versions (the good stuff)
                if vtype == "semver" and status == "unaffected":
                    ver = v.get("version", "")
                    branch_match = _VERSION_BRANCH_RE.match(ver)
                    if branch_match:
                        branch = branch_match.group(1)
                        fixed_in_versions[branch] = ver

        if fixing_commits or fixed_in_versions:
            entries[cve_id] = VulnEntry(
                cve_id=cve_id,
                fixing_commits=fixing_commits,
                fixed_in_versions=fixed_in_versions,
            )

    logger.info("Parsed %d CVE entries from vulns.git (%d with version info)",
                len(entries),
                sum(1 for e in entries.values() if e.fixed_in_versions))
    return entries


def save_vulns_db(entries: dict[str, VulnEntry], output: Path,
                  vulns_commit: str = "") -> None:
    """Serialize vulns DB to compact JSON.

    Strips fixing_commits to reduce file size (only needed for the
    deferred fingerprinting layer). Entries without fixed_in_versions
    are excluded since they provide no suppression value.
    """
    # Only include entries that have version fix info
    useful = {
        cve_id: entry
        for cve_id, entry in entries.items()
        if entry.fixed_in_versions
    }

    data = {
        "schema_version": "1.0",
        "generated": datetime.now(tz=timezone.utc).isoformat(),
        "vulns_commit": vulns_commit,
        "entry_count": len(useful),
        "total_parsed": len(entries),
        "entries": {
            cve_id: {
                "cve_id": entry.cve_id,
                "fixed_in_versions": entry.fixed_in_versions,
            }
            for cve_id, entry in sorted(useful.items())
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(data, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    logger.info("Wrote vulns DB with %d entries (%d total parsed) to %s",
                len(useful), len(entries), output)


def load_vulns_db(path: Path | None = None) -> dict[str, VulnEntry] | None:
    """Load pre-built vulns DB from JSON.

    Lookup order:
    1. Explicit path argument
    2. SCIATH_VULNS_DB environment variable
    3. Default location (discovery/bsp_data/vulns_db.json)

    Returns None if not found (graceful degradation).
    Logs INFO with fix command when missing.
    """
    if path is None:
        env_path = os.environ.get("SCIATH_VULNS_DB")
        if env_path:
            path = Path(env_path)
        else:
            path = _DEFAULT_VULNS_DB

    if not path.is_file():
        logger.info(
            "vulns_db.json not found at %s. Version-based CVE suppression "
            "disabled. Run: python3 scripts/ingest_vulns.py",
            path,
        )
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Cannot load vulns DB from %s: %s", path, e)
        return None

    # Check age
    generated = data.get("generated", "")
    if generated:
        try:
            gen_dt = datetime.fromisoformat(generated)
            age_days = (datetime.now(tz=timezone.utc) - gen_dt).days
            if age_days > 30:
                logger.warning(
                    "vulns_db.json is %d days old. Consider refreshing: "
                    "python3 scripts/ingest_vulns.py",
                    age_days,
                )
        except (ValueError, TypeError):
            pass

    entries: dict[str, VulnEntry] = {}
    for cve_id, entry_data in data.get("entries", {}).items():
        entries[cve_id] = VulnEntry(
            cve_id=entry_data.get("cve_id", cve_id),
            fixing_commits=entry_data.get("fixing_commits", []),
            fixed_in_versions=entry_data.get("fixed_in_versions", {}),
        )

    logger.info("Loaded vulns DB: %d entries from %s", len(entries), path)
    return entries
