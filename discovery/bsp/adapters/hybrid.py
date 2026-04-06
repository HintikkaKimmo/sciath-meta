"""
HybridAdapter: handles BSP layers with both file patches and kernel forks.

Uses composition: delegates to FilePatchAdapter and ForkedKernelAdapter,
then merges and deduplicates results. Handles vendors like PHYTEC,
Variscite, and Digi International.
"""

import logging
from pathlib import Path

from discovery.bsp._types import BSPProfile, PatchInfo
from discovery.bsp.adapters import VendorAdapter, register_adapter

logger = logging.getLogger(__name__)


@register_adapter("hybrid")
class HybridAdapter(VendorAdapter):
    """Composite adapter: runs both file_patches and forked_kernel."""

    @property
    def name(self) -> str:
        return "hybrid"

    def extract_patches(
        self,
        layer_path: Path,
        kernel_recipe_path: Path,
        build_dir: Path,
    ) -> BSPProfile:
        # ForkedKernelAdapter already includes file patches internally,
        # so we just delegate to it. The fork adapter runs FilePatchAdapter
        # as part of its extraction.
        from discovery.bsp.adapters.forked_kernel import ForkedKernelAdapter

        fork_adapter = ForkedKernelAdapter()
        profile = fork_adapter.extract_patches(layer_path, kernel_recipe_path, build_dir)
        profile.adapter_used = self.name

        # Deduplicate patches by (name, source_type)
        seen: set[tuple[str, str]] = set()
        unique_patches: list[PatchInfo] = []
        for patch in profile.patches:
            key = (patch.name, patch.source_type.value)
            if key not in seen:
                seen.add(key)
                unique_patches.append(patch)
        profile.patches = unique_patches

        return profile
