"""
ForkedKernelAdapter: extracts git fork references from BSP layers.

Handles vendors that maintain kernel git forks where patches are
commits, not files (Toradex, NXP/meta-imx).

Does NOT clone the repository. Records the fork URL, branch, and
SRCREV for the diff fingerprinter to consume later.
"""

import logging
import re
from pathlib import Path

from discovery.bsp._recipe_parser import (
    gather_all_src_uris,
    parse_srcrev,
    parse_variable,
)
from discovery.bsp._types import BSPProfile, PatchInfo, PatchSourceType
from discovery.bsp.adapters import VendorAdapter, register_adapter

logger = logging.getLogger(__name__)

# Match git:// or https:// URIs with optional parameters
_GIT_URI_RE = re.compile(r"^(git|https?)://([^;]+)(?:;(.*))?$")


@register_adapter("forked_kernel")
class ForkedKernelAdapter(VendorAdapter):
    """Extract git fork references from SRC_URI."""

    @property
    def name(self) -> str:
        return "forked_kernel"

    def extract_patches(
        self,
        layer_path: Path,
        kernel_recipe_path: Path,
        build_dir: Path,
    ) -> BSPProfile:
        profile = BSPProfile(adapter_used=self.name)
        profile.kernel_recipe = kernel_recipe_path.stem.split("_")[0]
        profile.kernel_srcrev = parse_srcrev(kernel_recipe_path)

        machine = parse_variable(kernel_recipe_path, "MACHINE")
        uris = gather_all_src_uris(kernel_recipe_path, layer_path, machine=machine)
        profile.kernel_src_uri = " ".join(uris)

        # Handle AUTOREV
        if profile.kernel_srcrev == "${AUTOREV}":
            profile.warnings.append(
                f"SRCREV is AUTOREV in {kernel_recipe_path.name} — "
                "cannot determine exact commit without build environment"
            )

        # Extract git:// entries
        for uri in uris:
            match = _GIT_URI_RE.match(uri)
            if not match:
                continue

            protocol = match.group(1)
            host_path = match.group(2)
            params_str = match.group(3) or ""

            # Parse parameters (;branch=main;protocol=https)
            params = self._parse_uri_params(params_str)
            branch = params.get("branch", "")

            git_url = f"{protocol}://{host_path}"

            # Try to resolve unexpanded branch variable
            if branch and "${" in branch:
                var_match = re.search(r"\$\{(\w+)\}", branch)
                if var_match:
                    resolved = parse_variable(kernel_recipe_path, var_match.group(1))
                    if resolved:
                        branch = resolved

            # Store branch in metadata
            if branch:
                profile.metadata["kernel_branch"] = branch

            # Try to detect upstream base from recipe PV
            pv = parse_variable(kernel_recipe_path, "PV")
            if pv:
                profile.metadata["upstream_base_hint"] = pv

            profile.patches.append(PatchInfo(
                name=f"kernel-fork:{host_path}",
                source_type=PatchSourceType.GIT_FORK,
                git_url=git_url,
                commit_hash=profile.kernel_srcrev,
                recipe=profile.kernel_recipe,
                layer=layer_path.name,
                confidence="low",
            ))

            # Only record the first git source (the kernel itself)
            # Additional git sources (firmware blobs, etc.) are not kernel patches
            break

        # Also check for any file:// patches alongside the fork
        # (some forked kernel recipes have a few file patches too)
        from discovery.bsp.adapters.file_patches import FilePatchAdapter
        file_adapter = FilePatchAdapter()
        file_result = file_adapter.extract_patches(layer_path, kernel_recipe_path, build_dir)
        profile.patches.extend(file_result.patches)
        profile.warnings.extend(file_result.warnings)

        return profile

    def _parse_uri_params(self, params_str: str) -> dict[str, str]:
        """Parse SRC_URI parameter string (;key=value;key2=value2)."""
        params: dict[str, str] = {}
        if not params_str:
            return params
        for part in params_str.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                params[key.strip()] = value.strip()
        return params
