#!/usr/bin/env python3
"""
vulns.git ingestion script.

Clones the linux kernel vulns.git repo and generates
discovery/bsp_data/vulns_db.json. The CVE JSON 5.0 files in vulns.git
contain semver fix versions directly, so no kernel repo clone is needed.

Usage:
    python scripts/ingest_vulns.py                             # full ingestion
    python scripts/ingest_vulns.py --vulns-repo /path/to/vulns # local repo
    python scripts/ingest_vulns.py --stats                     # show DB stats

Cloned repos are cached in .bsp_cache/ (gitignored).
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

# Add project root to path so discovery module is importable
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from discovery.bsp._vulns_db import (  # noqa: E402
    VulnEntry,
    ingest_vulns_git,
    save_vulns_db,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s",
)
logger = logging.getLogger("ingest_vulns")

CACHE_DIR = _PROJECT_ROOT / ".bsp_cache"
OUTPUT_DIR = _PROJECT_ROOT / "discovery" / "bsp_data"

VULNS_GIT_URL = "https://git.kernel.org/pub/scm/linux/security/vulns.git"


def _clone_or_update(url: str, name: str) -> Path:
    """Clone or update a git repo in the cache directory."""
    repo_path = CACHE_DIR / name
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if repo_path.exists():
        logger.info("Updating %s...", name)
        subprocess.run(
            ["git", "-C", str(repo_path), "pull", "--ff-only"],
            check=True, capture_output=True,
        )
    else:
        logger.info("Cloning %s...", name)
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(repo_path)],
            check=True, capture_output=True,
        )

    return repo_path


def _print_stats(entries: dict[str, VulnEntry]) -> None:
    """Print summary statistics about the vulns DB."""
    total = len(entries)
    with_versions = sum(1 for e in entries.values() if e.fixed_in_versions)
    single_commit = sum(1 for e in entries.values() if e.single_commit)

    # Count per branch
    branch_counts: dict[str, int] = {}
    for entry in entries.values():
        for branch in entry.fixed_in_versions:
            branch_counts[branch] = branch_counts.get(branch, 0) + 1

    print("\nvulns_db statistics:")
    print(f"  Total CVEs:              {total}")
    print(f"  With stable version fix: {with_versions}")
    print(f"  Single-commit fixes:     {single_commit}")
    print(f"  Multi-commit fixes:      {total - single_commit}")
    print("\n  Per stable branch:")
    for branch in sorted(branch_counts, key=lambda b: tuple(int(x) for x in b.split("."))):
        print(f"    {branch}: {branch_counts[branch]} CVEs")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build vulns_db.json from linux kernel vulns.git",
    )
    parser.add_argument(
        "--vulns-repo", type=Path, default=None,
        help="Path to local vulns.git clone (default: clone from kernel.org)",
    )
    parser.add_argument(
        "--output", type=Path, default=OUTPUT_DIR / "vulns_db.json",
        help="Output path for vulns_db.json",
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Show DB statistics only (requires existing vulns_db.json)",
    )
    args = parser.parse_args()

    if args.stats:
        from discovery.bsp._vulns_db import load_vulns_db
        db = load_vulns_db(args.output)
        if db is None:
            logger.error("No vulns_db.json found at %s", args.output)
            return 1
        _print_stats(db)
        return 0

    # Step 1: Clone/update vulns.git
    if args.vulns_repo:
        vulns_repo = args.vulns_repo
    else:
        vulns_repo = _clone_or_update(VULNS_GIT_URL, "vulns.git")

    # Step 2: Parse CVE entries (JSON 5.0 includes semver fix versions directly)
    entries = ingest_vulns_git(vulns_repo)
    if not entries:
        logger.error("No CVE entries found in vulns.git")
        return 1

    # Step 3: Get vulns.git commit hash
    try:
        result = subprocess.run(
            ["git", "-C", str(vulns_repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        vulns_commit = result.stdout.strip()[:12]
    except (subprocess.CalledProcessError, FileNotFoundError):
        vulns_commit = ""

    # Step 4: Save
    save_vulns_db(entries, args.output, vulns_commit=vulns_commit)

    # Step 5: Stats
    _print_stats(entries)

    print(f"\nWrote: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
