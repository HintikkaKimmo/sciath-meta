"""
Yocto layer scanning utilities for BSP discovery.

Parses bblayers.conf to find layer paths, reads layer.conf for
metadata, and locates bbappend files within a layer.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# BBLAYERS assignment — handles = and +=, multiline already joined by caller
_BBLAYERS_RE = re.compile(
    r'BBLAYERS\s*(?:\+?=)\s*"((?:[^"\\]|\\.)*)"',
    re.MULTILINE,
)

# BBFILE_COLLECTIONS in layer.conf
_COLLECTIONS_RE = re.compile(
    r'^BBFILE_COLLECTIONS\s*(?:\+?=)\s*"([^"]*)"',
    re.MULTILINE,
)

# Backslash continuation
_CONTINUATION_RE = re.compile(r"\\\s*\n")


def parse_bblayers(build_dir: Path) -> list[Path]:
    """Parse conf/bblayers.conf to get list of layer paths.

    Handles:
    - BBLAYERS = "..." (single and multiline)
    - BBLAYERS += "..."
    - ${TOPDIR} substitution (replaced with build_dir)
    - Relative paths resolved against build_dir

    Returns list of absolute, resolved layer paths that exist on disk.
    """
    bblayers_conf = build_dir / "conf" / "bblayers.conf"
    if not bblayers_conf.exists():
        return []

    try:
        text = bblayers_conf.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Cannot read bblayers.conf: %s", e)
        return []

    text = _CONTINUATION_RE.sub("", text)
    # Substitute ${TOPDIR} with build_dir
    text = text.replace("${TOPDIR}", str(build_dir))

    paths: list[Path] = []
    for match in _BBLAYERS_RE.finditer(text):
        raw = match.group(1)
        for entry in raw.split():
            entry = entry.strip()
            if not entry:
                continue
            p = Path(entry)
            if not p.is_absolute():
                p = (build_dir / p).resolve()
            else:
                p = p.resolve()
            if p.exists() and p.is_dir():
                paths.append(p)
            else:
                logger.debug("Layer path does not exist, skipping: %s", p)

    return paths


def get_layer_name(layer_path: Path) -> str:
    """Read layer name from conf/layer.conf BBFILE_COLLECTIONS.

    Falls back to directory basename if layer.conf is missing or
    doesn't contain BBFILE_COLLECTIONS.
    """
    layer_conf = layer_path / "conf" / "layer.conf"
    if not layer_conf.exists():
        return layer_path.name

    try:
        text = layer_conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return layer_path.name

    match = _COLLECTIONS_RE.search(text)
    if match:
        # BBFILE_COLLECTIONS may have multiple names; take the first
        names = match.group(1).split()
        if names:
            return names[0]

    return layer_path.name


def find_same_layer_bbappends(recipe_name: str, layer_path: Path) -> list[Path]:
    """Find .bbappend files within a layer that apply to a given recipe.

    Matches:
    - Exact: linux-raspberrypi_6.1.21.bbappend
    - Wildcard version: linux-raspberrypi_%.bbappend
    - Any file starting with recipe_name

    Only searches within the same layer (not cross-layer).
    Returns sorted list of matching bbappend paths.
    """
    matches: list[Path] = []

    for bbappend in layer_path.rglob("*.bbappend"):
        append_name = bbappend.stem  # linux-raspberrypi_6.1.21 or linux-raspberrypi_%
        # Extract recipe base name (before version)
        append_recipe = append_name.split("_")[0]
        if append_recipe == recipe_name:
            matches.append(bbappend)

    matches.sort(key=lambda p: p.name)
    return matches


def is_bsp_layer(layer_path: Path) -> bool:
    """Heuristic: a BSP layer contains conf/machine/*.conf files."""
    machine_dir = layer_path / "conf" / "machine"
    if not machine_dir.exists():
        return False
    return any(machine_dir.glob("*.conf"))


def find_bsp_layers(build_dir: Path) -> list[tuple[str, Path]]:
    """Find all BSP layers in the build configuration.

    Returns list of (layer_name, layer_path) for layers that look
    like BSP layers (contain conf/machine/ configs).
    """
    layers = parse_bblayers(build_dir)
    bsp_layers: list[tuple[str, Path]] = []

    for layer_path in layers:
        if is_bsp_layer(layer_path):
            name = get_layer_name(layer_path)
            bsp_layers.append((name, layer_path))

    return bsp_layers
