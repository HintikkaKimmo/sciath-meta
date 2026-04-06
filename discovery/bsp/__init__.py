"""
BSP layer patch discovery for Yocto builds.

Discovers kernel/BSP patches from vendor BSP layers using vendor-specific
adapters. Static analysis only — no BitBake environment required.
"""

import logging
from pathlib import Path

from discovery.bsp._layer_scanner import find_bsp_layers, get_layer_name, parse_bblayers
from discovery.bsp._recipe_parser import find_kernel_recipe
from discovery.bsp._types import (
    BSPProfile,
    Confidence,
    PatchInfo,
    PatchSourceType,
    SuppressionStatus,
    VersionMatch,
)
from discovery.bsp.adapters import detect_vendor

__all__ = [
    "BSPProfile",
    "Confidence",
    "PatchInfo",
    "PatchSourceType",
    "SuppressionStatus",
    "VersionMatch",
    "extract_bsp_patches",
]

logger = logging.getLogger(__name__)


def extract_bsp_patches(build_dir: Path, machine: str = "") -> BSPProfile | None:
    """Main entry point for BSP patch discovery.

    1. Parse bblayers.conf to find all layers
    2. Identify BSP layers (layers with conf/machine/*.conf)
    3. Detect vendor from layer name patterns
    4. Find the kernel recipe in the BSP layer
    5. Run vendor-specific adapter to extract patches
    6. Return BSPProfile or None

    Non-blocking: catches all exceptions, returns BSPProfile with
    warnings rather than raising.
    """
    try:
        return _extract_bsp_patches_inner(build_dir, machine)
    except Exception as e:
        logger.warning("BSP patch discovery failed (non-blocking): %s", e)
        return None


def _extract_bsp_patches_inner(build_dir: Path, machine: str) -> BSPProfile | None:
    """Inner implementation without exception handling."""
    # Find all layers
    all_layers = parse_bblayers(build_dir)
    if not all_layers:
        logger.debug("No layers found in bblayers.conf")
        return None

    # Build layer name → path mapping
    layer_names: list[str] = []
    layer_paths: dict[str, Path] = {}
    for layer_path in all_layers:
        name = get_layer_name(layer_path)
        layer_names.append(name)
        layer_paths[name] = layer_path

    # Detect vendor
    vendor, adapter, profile_data = detect_vendor(layer_names, layer_paths)
    if adapter is None:
        logger.debug("No BSP vendor detected")
        return None

    # Find the BSP layer path
    vendor_layer_name = ""
    vendor_layer_path = None
    for pattern in profile_data.get("layer_patterns", []):
        if pattern in layer_paths:
            vendor_layer_name = pattern
            vendor_layer_path = layer_paths[pattern]
            break

    # For generic fallback, use the first BSP layer found
    if vendor_layer_path is None:
        bsp_layers = find_bsp_layers(build_dir)
        if bsp_layers:
            vendor_layer_name, vendor_layer_path = bsp_layers[0]
        else:
            logger.debug("No BSP layer found for vendor %s", vendor)
            return None

    # Find kernel recipe
    kernel_recipe_patterns = profile_data.get("kernel_recipe_patterns", [])
    kernel_recipe = find_kernel_recipe(
        vendor_layer_path,
        machine=machine,
        kernel_recipe_patterns=kernel_recipe_patterns,
    )
    if kernel_recipe is None:
        logger.debug("No kernel recipe found in %s", vendor_layer_path)
        return None

    # Run adapter
    result = adapter.extract_patches(vendor_layer_path, kernel_recipe, build_dir)
    result.vendor = vendor
    result.vendor_layer = vendor_layer_name

    # Extract kernel version from recipe
    from discovery.bsp._recipe_parser import parse_linux_version

    linux_version = parse_linux_version(kernel_recipe)
    if linux_version:
        result.metadata["linux_version"] = linux_version

    # Version-based CVE suppression
    _run_version_suppression(result)

    logger.info(
        "BSP discovery: %s vendor, %d patches (%d file, %d fork)",
        vendor, result.patch_count, result.file_patch_count, result.fork_patch_count,
    )

    return result


def _run_version_suppression(profile: BSPProfile) -> None:
    """Run version-based CVE suppression if vulns_db is available.

    Non-blocking: all errors become warnings.
    """
    try:
        from discovery.bsp._version_suppression import (
            check_version_suppression,
            parse_kernel_version,
        )
        from discovery.bsp._vulns_db import load_vulns_db

        vulns_db = load_vulns_db()
        if vulns_db is None:
            return

        branch, version = parse_kernel_version(profile)
        if not version:
            return

        profile.version_matches = check_version_suppression(profile, vulns_db)
        profile.kernel_version_detected = version
        profile.kernel_branch_detected = branch
    except Exception as e:
        logger.warning("Version suppression failed (non-blocking): %s", e)
