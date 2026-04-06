"""
VendorAdapter ABC and adapter registry for BSP patch extraction.

Each concrete adapter knows how to extract patch information from
a specific vendor's BSP layer structure. Detection matches layer
names against vendor profile JSON files.
"""

import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any

from discovery.bsp._types import BSPProfile

logger = logging.getLogger(__name__)

_PROFILES_DIR = Path(__file__).parent.parent / "vendor_profiles"
_profile_cache: dict[str, dict[str, Any]] = {}
_ADAPTER_REGISTRY: dict[str, type["VendorAdapter"]] = {}


class VendorAdapter(ABC):
    """Abstract interface for vendor-specific BSP patch extraction.

    Adapters perform static analysis only: no BitBake environment,
    no git clone, no network access. Errors become warnings in
    BSPProfile, never exceptions.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter identifier (e.g. 'file_patches')."""

    @abstractmethod
    def extract_patches(
        self,
        layer_path: Path,
        kernel_recipe_path: Path,
        build_dir: Path,
    ) -> BSPProfile:
        """Extract patch information from a BSP layer.

        Args:
            layer_path: Absolute path to the BSP layer root
            kernel_recipe_path: Absolute path to the kernel .bb file
            build_dir: Yocto build directory root (for path validation)

        Returns:
            BSPProfile with discovered patches. Never raises.
        """


def register_adapter(adapter_key: str) -> "Callable[[type[VendorAdapter]], type[VendorAdapter]]":
    """Decorator to register an adapter class by key."""
    def decorator(cls: type[VendorAdapter]) -> type[VendorAdapter]:
        _ADAPTER_REGISTRY[adapter_key] = cls
        return cls
    return decorator


def _load_profiles() -> list[dict[str, Any]]:
    """Load all vendor profile JSON files, sorted by priority desc."""
    profiles: list[dict[str, Any]] = []

    if not _PROFILES_DIR.exists():
        return profiles

    for json_file in sorted(_PROFILES_DIR.glob("*.json")):
        if json_file.name in _profile_cache:
            profiles.append(_profile_cache[json_file.name])
            continue

        try:
            with open(json_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Invalid vendor profile %s: %s", json_file.name, e)
            continue

        if not isinstance(data, dict) or "vendor" not in data:
            logger.warning("Vendor profile %s missing 'vendor' key", json_file.name)
            continue

        _profile_cache[json_file.name] = data
        profiles.append(data)

    # Sort by priority descending (highest first)
    profiles.sort(key=lambda p: p.get("priority", 0), reverse=True)
    return profiles


def detect_vendor(
    layer_names: list[str],
    layer_paths: dict[str, Path],
) -> tuple[str, VendorAdapter | None, dict[str, Any]]:
    """Auto-detect which vendor's BSP is in use.

    Detection: exact match of layer names against vendor profile
    layer_patterns. First match (highest priority) wins.

    Returns (vendor_id, adapter_instance, profile_dict).
    Returns ("unknown", None, {}) on total failure.
    """
    # Ensure adapters are imported (triggers @register_adapter)
    _ensure_adapters_loaded()

    profiles = _load_profiles()

    for profile in profiles:
        vendor = profile.get("vendor", "")
        patterns = profile.get("layer_patterns", [])

        for pattern in patterns:
            if pattern in layer_names:
                adapter_key = profile.get("adapter", "")
                adapter_cls = _ADAPTER_REGISTRY.get(adapter_key)
                if adapter_cls is None:
                    logger.warning(
                        "Vendor %s uses adapter %r which is not registered",
                        vendor, adapter_key,
                    )
                    continue
                logger.info("Detected BSP vendor: %s (layer: %s)", vendor, pattern)
                return vendor, adapter_cls(), profile

    # Try generic fallback
    generic = _profile_cache.get("generic.json")
    if generic is None:
        # Load it directly
        generic_path = _PROFILES_DIR / "generic.json"
        if generic_path.exists():
            try:
                with open(generic_path) as f:
                    generic = json.load(f)
                    _profile_cache["generic.json"] = generic
            except (json.JSONDecodeError, OSError):
                pass

    if generic:
        adapter_key = generic.get("adapter", "file_patches")
        adapter_cls = _ADAPTER_REGISTRY.get(adapter_key)
        if adapter_cls:
            return "generic", adapter_cls(), generic

    return "unknown", None, {}


def _ensure_adapters_loaded() -> None:
    """Import concrete adapters to trigger registration."""
    if _ADAPTER_REGISTRY:
        return
    # These imports trigger @register_adapter decorators
    import discovery.bsp.adapters.file_patches  # noqa: F401
    import discovery.bsp.adapters.forked_kernel  # noqa: F401
    import discovery.bsp.adapters.hybrid  # noqa: F401


def clear_caches() -> None:
    """Clear profile and adapter caches (for testing)."""
    _profile_cache.clear()
