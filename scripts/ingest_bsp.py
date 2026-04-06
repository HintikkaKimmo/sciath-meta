#!/usr/bin/env python3
"""
BSP pre-ingestion script.

Clones public BSP layer repos, runs vendor adapters against them,
and generates per-BSP data files in discovery/bsp_data/.

Usage:
    python scripts/ingest_bsp.py                     # ingest all configured BSPs
    python scripts/ingest_bsp.py --vendor raspberrypi # ingest one vendor
    python scripts/ingest_bsp.py --list               # list configured BSPs
    python scripts/ingest_bsp.py --clean              # remove cached clones

Cloned repos are cached in .bsp_cache/ (gitignored).
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path so discovery module is importable
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from discovery.bsp._layer_scanner import get_layer_name  # noqa: E402
from discovery.bsp._recipe_parser import find_kernel_recipe, has_cve_tag  # noqa: E402
from discovery.bsp._types import PatchSourceType  # noqa: E402
from discovery.bsp.adapters import clear_caches  # noqa: E402
from discovery.bsp.adapters.file_patches import FilePatchAdapter  # noqa: E402
from discovery.bsp.adapters.forked_kernel import ForkedKernelAdapter  # noqa: E402
from discovery.bsp.adapters.hybrid import HybridAdapter  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s",
)
logger = logging.getLogger("ingest_bsp")

CACHE_DIR = _PROJECT_ROOT / ".bsp_cache"
OUTPUT_DIR = _PROJECT_ROOT / "discovery" / "bsp_data"


@dataclass
class RelatedRepo:
    """An additional repo to clone alongside the main BSP layer."""
    name: str           # e.g. "kconfig", "machines-nxp"
    repo_url: str
    branch: str
    purpose: str        # "kconfig" or "machines"


@dataclass
class BSPTarget:
    """A BSP layer to ingest."""
    vendor: str
    repo_url: str
    branch: str
    adapter_type: str  # "file_patches", "forked_kernel", "hybrid"
    kernel_recipe_patterns: list[str]
    machines: list[str]  # machines to test
    related_repos: list[RelatedRepo] | None = None


# ── Configured BSP targets ────────────────────────────────────────

TARGETS: list[BSPTarget] = [
    BSPTarget(
        vendor="raspberrypi",
        repo_url="https://github.com/agherzan/meta-raspberrypi.git",
        branch="scarthgap",
        adapter_type="forked_kernel",
        kernel_recipe_patterns=["linux-raspberrypi"],
        machines=["raspberrypi4-64", "raspberrypi5"],
    ),
    BSPTarget(
        vendor="toradex",
        repo_url="https://git.toradex.com/meta-toradex-bsp-common.git",
        branch="scarthgap-7.x.y",
        adapter_type="forked_kernel",
        kernel_recipe_patterns=["linux-toradex", "linux-toradex-upstream"],
        machines=["verdin-imx8mp"],
        related_repos=[
            RelatedRepo(
                name="kconfig",
                repo_url="https://git.toradex.com/linux-toradex-kconfig.git",
                branch="main",
                purpose="kconfig",
            ),
            RelatedRepo(
                name="machines-nxp",
                repo_url="https://git.toradex.com/meta-toradex-nxp.git",
                branch="scarthgap-7.x.y",
                purpose="machines",
            ),
        ],
    ),
    BSPTarget(
        vendor="phytec",
        repo_url="https://github.com/phytec/meta-phytec.git",
        branch="scarthgap",
        adapter_type="hybrid",
        kernel_recipe_patterns=["linux-phytec", "linux-phytec-ti", "linux-phytec-imx"],
        machines=["phyboard-electra-am62xx-2"],
    ),
]


def _clone_or_update_repo(cache_path: Path, repo_url: str, branch: str) -> Path:
    """Clone or update a git repo. Returns the repo path."""
    CACHE_DIR.mkdir(exist_ok=True)

    if cache_path.exists():
        logger.info("  Updating cached %s...", cache_path.name)
        subprocess.run(
            ["git", "fetch", "--depth=1", "origin", branch],
            cwd=cache_path, capture_output=True, timeout=120,
        )
        subprocess.run(
            ["git", "checkout", f"origin/{branch}"],
            cwd=cache_path, capture_output=True, timeout=30,
        )
    else:
        logger.info("  Cloning %s (branch: %s)...", repo_url, branch)
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--branch", branch,
             repo_url, str(cache_path)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            logger.error("Clone failed: %s", result.stderr)
            raise RuntimeError(f"Failed to clone {repo_url}")

    return cache_path


def clone_or_update(target: BSPTarget) -> tuple[Path, list[tuple[str, Path]]]:
    """Clone or update a BSP layer and its related repos.

    Returns (main_layer_path, [(related_name, related_path), ...]).
    """
    main_path = _clone_or_update_repo(
        CACHE_DIR / target.vendor, target.repo_url, target.branch,
    )

    related: list[tuple[str, Path]] = []
    for repo in target.related_repos or []:
        try:
            repo_path = _clone_or_update_repo(
                CACHE_DIR / f"{target.vendor}-{repo.name}",
                repo.repo_url, repo.branch,
            )
            related.append((repo.name, repo_path))
        except RuntimeError as e:
            logger.warning("  Skipping related repo %s: %s", repo.name, e)

    return main_path, related


def get_commit_hash(repo_path: Path) -> str:
    """Get the current HEAD commit hash."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_path, capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def get_adapter(adapter_type: str):
    """Get the adapter instance by type."""
    adapters = {
        "file_patches": FilePatchAdapter,
        "forked_kernel": ForkedKernelAdapter,
        "hybrid": HybridAdapter,
    }
    cls = adapters.get(adapter_type)
    if cls is None:
        raise ValueError(f"Unknown adapter type: {adapter_type}")
    return cls()


def count_kconfig_fragments(layer_path: Path) -> tuple[int, int]:
    """Count .cfg kernel config fragments and total keys."""
    cfg_files = list(layer_path.rglob("*.cfg"))
    total_keys = 0
    for cfg in cfg_files:
        try:
            for line in cfg.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    total_keys += 1
        except OSError:
            pass
    return len(cfg_files), total_keys


def collect_machine_configs(layer_path: Path) -> list[str]:
    """List all machine configs in the layer."""
    machine_dir = layer_path / "conf" / "machine"
    if not machine_dir.exists():
        return []
    return sorted(f.stem for f in machine_dir.glob("*.conf"))


def ingest_one(target: BSPTarget) -> dict:
    """Ingest a single BSP layer. Returns the data dict."""
    layer_path, related_repos = clone_or_update(target)
    commit = get_commit_hash(layer_path)
    adapter = get_adapter(target.adapter_type)

    logger.info("Analyzing %s (commit: %s)...", target.vendor, commit[:12])

    # Find kernel recipe
    kernel_recipe = find_kernel_recipe(
        layer_path,
        machine=target.machines[0] if target.machines else "",
        kernel_recipe_patterns=target.kernel_recipe_patterns,
    )

    if kernel_recipe is None:
        logger.warning("No kernel recipe found in %s", layer_path)
        return _empty_result(target, commit)

    logger.info("  Kernel recipe: %s", kernel_recipe.relative_to(layer_path))

    # Run adapter
    profile = adapter.extract_patches(layer_path, kernel_recipe, layer_path)
    profile.vendor = target.vendor
    profile.vendor_layer = get_layer_name(layer_path)

    # Collect kconfig fragments from main layer + kconfig related repos
    cfg_count, key_count = count_kconfig_fragments(layer_path)
    for repo_name, repo_path in related_repos:
        related_target = next(
            (r for r in (target.related_repos or []) if r.name == repo_name), None
        )
        if related_target and related_target.purpose == "kconfig":
            extra_cfg, extra_keys = count_kconfig_fragments(repo_path)
            cfg_count += extra_cfg
            key_count += extra_keys
            logger.info("  Kconfig from %s: %d keys from %d fragments", repo_name, extra_keys, extra_cfg)

    # Collect machine configs from main layer + machine related repos
    machines = collect_machine_configs(layer_path)
    for repo_name, repo_path in related_repos:
        related_target = next(
            (r for r in (target.related_repos or []) if r.name == repo_name), None
        )
        if related_target and related_target.purpose == "machines":
            extra_machines = collect_machine_configs(repo_path)
            machines.extend(extra_machines)
            logger.info("  Machines from %s: %d configs", repo_name, len(extra_machines))

    # Build output
    patches_data = []
    for p in profile.patches:
        entry: dict = {
            "name": p.name,
            "source_type": p.source_type.value,
            "confidence": p.confidence,
            "recipe": p.recipe,
        }
        if p.source_type == PatchSourceType.FILE and p.path:
            try:
                entry["relative_path"] = str(p.path.relative_to(layer_path))
            except ValueError:
                entry["relative_path"] = str(p.path)
            entry["has_cve_tag"] = has_cve_tag(p.path)
        if p.source_type == PatchSourceType.GIT_FORK:
            entry["git_url"] = p.git_url
            entry["commit_hash"] = p.commit_hash
        patches_data.append(entry)

    # Classify patches
    cve_tagged = [p for p in patches_data if p.get("has_cve_tag")]
    file_patches = [p for p in patches_data if p.get("source_type") == "file"]
    fork_refs = [p for p in patches_data if p.get("source_type") == "git_fork"]

    result = {
        "vendor": target.vendor,
        "display_name": target.vendor.replace("-", " ").title(),
        "bsp_repo": target.repo_url,
        "branch": target.branch,
        "analyzed_commit": commit,
        "analyzed_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "adapter_used": target.adapter_type,
        "kernel_recipe": profile.kernel_recipe,
        "kernel_srcrev": profile.kernel_srcrev,
        "kernel_src_uri": profile.kernel_src_uri,
        "machines": machines,
        "summary": {
            "total_patches": len(patches_data),
            "file_patches": len(file_patches),
            "fork_references": len(fork_refs),
            "cve_tagged_patches": len(cve_tagged),
            "kconfig_fragments": cfg_count,
            "kconfig_keys": key_count,
        },
        "patches": patches_data,
        "metadata": profile.metadata,
        "warnings": profile.warnings,
    }

    logger.info(
        "  Result: %d patches (%d file, %d fork), %d kconfig keys from %d fragments",
        len(patches_data), len(file_patches), len(fork_refs),
        key_count, cfg_count,
    )
    if profile.warnings:
        for w in profile.warnings:
            logger.warning("  %s", w)

    return result


def _empty_result(target: BSPTarget, commit: str) -> dict:
    return {
        "vendor": target.vendor,
        "bsp_repo": target.repo_url,
        "branch": target.branch,
        "analyzed_commit": commit,
        "analyzed_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "error": "No kernel recipe found",
        "patches": [],
        "summary": {"total_patches": 0},
    }


def main():
    parser = argparse.ArgumentParser(description="BSP pre-ingestion")
    parser.add_argument("--vendor", type=str, help="Ingest a single vendor")
    parser.add_argument("--list", action="store_true", help="List configured BSPs")
    parser.add_argument("--clean", action="store_true", help="Remove cached clones")
    parser.add_argument("--output-dir", type=str, default=str(OUTPUT_DIR))
    args = parser.parse_args()

    if args.list:
        for t in TARGETS:
            print(f"  {t.vendor:15s} {t.repo_url} ({t.branch}) [{t.adapter_type}]")
        return

    if args.clean:
        import shutil
        if CACHE_DIR.exists():
            shutil.rmtree(CACHE_DIR)
            print(f"Removed {CACHE_DIR}")
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = TARGETS
    if args.vendor:
        targets = [t for t in TARGETS if t.vendor == args.vendor]
        if not targets:
            logger.error("Unknown vendor: %s", args.vendor)
            sys.exit(1)

    clear_caches()

    for target in targets:
        try:
            result = ingest_one(target)
            out_path = output_dir / f"{target.vendor}.json"
            with open(out_path, "w") as f:
                json.dump(result, f, indent=2)
                f.write("\n")
            logger.info("  Wrote %s", out_path)
        except Exception as e:
            logger.error("Failed to ingest %s: %s", target.vendor, e)

    print()
    print(f"BSP data written to {output_dir}/")


if __name__ == "__main__":
    main()
