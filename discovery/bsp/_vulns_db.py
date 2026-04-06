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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Default location for the pre-built vulns DB
_DEFAULT_VULNS_DB = Path(__file__).parent.parent / "bsp_data" / "vulns_db.json"

# CVE ID pattern in stream filenames
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# Parsing patterns for vulns.git stream files
_FIXED_BY_RE = re.compile(r"^fixed-by:\s*$", re.MULTILINE)
_COMMIT_RE = re.compile(r"^\s+-\s+([0-9a-f]{40})", re.MULTILINE)
_CVE_FIELD_RE = re.compile(r"^cve:\s+(CVE-\d{4}-\d+)", re.MULTILINE)


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
    """Parse vulns.git stream/ files into a lookup dict keyed by CVE ID.

    Each file in stream/ contains structured data like:
        cve: CVE-2024-1234
        fixed-by:
          - abc123def456...

    Returns empty dict on error.
    """
    stream_dir = vulns_repo_path / "cve" / "published"
    if not stream_dir.is_dir():
        # Try alternative layout
        stream_dir = vulns_repo_path / "stream"
    if not stream_dir.is_dir():
        logger.warning("vulns.git stream directory not found at %s", vulns_repo_path)
        return {}

    entries: dict[str, VulnEntry] = {}

    for cve_file in stream_dir.rglob("*"):
        if not cve_file.is_file():
            continue

        try:
            text = cve_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Cannot read %s: %s", cve_file, e)
            continue

        # Extract CVE ID
        cve_match = _CVE_FIELD_RE.search(text)
        if not cve_match:
            # Try filename
            fname_match = _CVE_RE.search(cve_file.name)
            if not fname_match:
                continue
            cve_id = fname_match.group(0)
        else:
            cve_id = cve_match.group(1)

        # Extract fixing commits
        commits: list[str] = []
        for commit_match in _COMMIT_RE.finditer(text):
            commits.append(commit_match.group(1))

        if commits:
            entries[cve_id] = VulnEntry(cve_id=cve_id, fixing_commits=commits)

    logger.info("Parsed %d CVE entries from vulns.git", len(entries))
    return entries


def save_vulns_db(entries: dict[str, VulnEntry], output: Path,
                  vulns_commit: str = "") -> None:
    """Serialize vulns DB to JSON."""
    data = {
        "schema_version": "1.0",
        "generated": datetime.now(tz=timezone.utc).isoformat(),
        "vulns_commit": vulns_commit,
        "entry_count": len(entries),
        "entries": {
            cve_id: asdict(entry)
            for cve_id, entry in sorted(entries.items())
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    logger.info("Wrote vulns DB with %d entries to %s", len(entries), output)


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
