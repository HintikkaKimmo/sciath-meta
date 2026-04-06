"""
FilePatchAdapter: extracts file:// patches from BSP layers.

Handles vendors that use standard .patch files referenced via
file:// in SRC_URI (Raspberry Pi, Boundary Devices, CompuLab).
"""

import logging
import re
from pathlib import Path

from discovery.bsp._recipe_parser import (
    gather_all_src_uris,
    has_cve_tag,
    parse_srcrev,
    parse_variable,
)
from discovery.bsp._types import BSPProfile, PatchInfo, PatchSourceType
from discovery.bsp.adapters import VendorAdapter, register_adapter

logger = logging.getLogger(__name__)

_FILE_URI_RE = re.compile(r"^file://(.+?)(?:;.*)?$")


@register_adapter("file_patches")
class FilePatchAdapter(VendorAdapter):
    """Extract file:// patches from SRC_URI."""

    @property
    def name(self) -> str:
        return "file_patches"

    def extract_patches(
        self,
        layer_path: Path,
        kernel_recipe_path: Path,
        build_dir: Path,
    ) -> BSPProfile:
        profile = BSPProfile(adapter_used=self.name)
        profile.kernel_recipe = kernel_recipe_path.stem.split("_")[0]
        profile.kernel_srcrev = parse_srcrev(kernel_recipe_path)

        # Get machine from recipe path context if possible
        machine = parse_variable(kernel_recipe_path, "MACHINE")
        uris = gather_all_src_uris(kernel_recipe_path, layer_path, machine=machine)
        profile.kernel_src_uri = " ".join(uris)

        # Extract file:// entries
        for uri in uris:
            match = _FILE_URI_RE.match(uri)
            if not match:
                continue

            filename = match.group(1)
            if not (filename.endswith(".patch") or filename.endswith(".diff")):
                continue

            # Resolve patch file path within the layer
            patch_path = self._resolve_patch_path(
                filename, kernel_recipe_path, layer_path
            )

            if patch_path is None:
                profile.warnings.append(
                    f"Patch file not found: {filename} (referenced in {kernel_recipe_path.name})"
                )
                continue

            # Validate path safety
            try:
                patch_path.resolve().relative_to(layer_path.resolve())
            except ValueError:
                profile.warnings.append(
                    f"Patch file outside layer boundary: {filename}"
                )
                continue

            confidence = "high" if has_cve_tag(patch_path) else "medium"

            profile.patches.append(PatchInfo(
                name=filename,
                source_type=PatchSourceType.FILE,
                path=patch_path.resolve(),
                recipe=profile.kernel_recipe,
                layer=layer_path.name,
                confidence=confidence,
            ))

        return profile

    def _resolve_patch_path(
        self, filename: str, recipe_path: Path, layer_path: Path
    ) -> Path | None:
        """Resolve a file:// patch name to an absolute path.

        Yocto resolution order (mirrors FILESEXTRAPATHS behavior):
        1. Version-specific subdirectory (e.g., linux-toradex-upstream-6.12/)
        2. Recipe-named subdirectory (e.g., linux-raspberrypi/)
        3. files/ subdirectory next to recipe
        4. Recipe's parent directory
        """
        recipe_dir = recipe_path.parent
        recipe_name = recipe_path.stem.split("_")[0]
        recipe_full_stem = recipe_path.stem  # e.g. linux-toradex-upstream_6.12

        # 1. Version-specific subdirectory (FILESEXTRAPATHS pattern)
        # e.g., linux-toradex-upstream-6.12/ for linux-toradex-upstream_6.12.bb
        version_dir_name = recipe_full_stem.replace("_", "-")
        candidate = recipe_dir / version_dir_name / filename
        if candidate.exists():
            return candidate

        # 2. Recipe-named subdirectory
        candidate = recipe_dir / recipe_name / filename
        if candidate.exists():
            return candidate

        # 3. files/ subdirectory
        candidate = recipe_dir / "files" / filename
        if candidate.exists():
            return candidate

        # 4. Recipe's parent directory
        candidate = recipe_dir / filename
        if candidate.exists():
            return candidate

        return None
