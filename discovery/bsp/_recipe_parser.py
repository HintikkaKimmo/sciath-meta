"""
Static regex parser for Yocto .bb and .bbappend recipe files.

Extracts SRC_URI, SRCREV, and other variables without requiring a
BitBake environment. Machine-aware: when MACHINE is known, also
parses conditional overrides like SRC_URI:append:MACHINE.

Limitations:
- Cannot expand variables (${PV}, ${BPN}) — recorded as-is with warning
- Cannot evaluate inline Python (${@...}) — skipped with warning
- Cannot resolve _remove operators — ignored
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Matches SRC_URI assignment variants:
#   SRC_URI = "..."
#   SRC_URI += "..."
#   SRC_URI .= "..."
#   SRC_URI:append = "..."
#   SRC_URI_append = "..."
#   SRC_URI:append:MACHINE = "..."  (machine-conditional, matched separately)
_SRC_URI_BASE_RE = re.compile(
    r'^SRC_URI\s*(?:\+|\.)?=\s*"((?:[^"\\]|\\.)*)"',
    re.MULTILINE,
)

_SRC_URI_APPEND_RE = re.compile(
    r'^SRC_URI(?::append|_append)\s*=\s*"((?:[^"\\]|\\.)*)"',
    re.MULTILINE,
)

# Backslash continuation: join lines before parsing
_CONTINUATION_RE = re.compile(r"\\\s*\n")

# SRCREV variants
_SRCREV_RE = re.compile(r'^SRCREV\s*=\s*"([^"]*)"', re.MULTILINE)
_SRCREV_PN_RE = re.compile(r'^SRCREV_pn-(\S+)\s*=\s*"([^"]*)"', re.MULTILINE)
_SRCREV_NAMED_RE = re.compile(r'^SRCREV_(\w+)\s*=\s*"([^"]*)"', re.MULTILINE)

# require/include directives
_REQUIRE_RE = re.compile(r'^(?:require|include)\s+(\S+)', re.MULTILINE)

# Generic variable
_VAR_RE_TEMPLATE = r'^{}\s*(?:\??=|:=)\s*"([^"]*)"'

# Inline Python detection
_INLINE_PYTHON_RE = re.compile(r"\$\{@[^}]*\}")

# Unexpanded variable detection
_UNEXPANDED_VAR_RE = re.compile(r"\$\{(?!@)[A-Z_][A-Z0-9_]*\}")

# CVE tag patterns in patch filenames and headers
_CVE_FILENAME_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _read_and_join(path: Path) -> str:
    """Read a recipe file and join backslash-continued lines."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Cannot read recipe %s: %s", path, e)
        return ""
    return _CONTINUATION_RE.sub("", text)


def _resolve_includes(text: str, recipe_path: Path, depth: int = 0) -> str:
    """Follow require/include directives and append included file contents.

    Only resolves relative paths within the same layer. Max depth 3
    to prevent infinite loops.
    """
    if depth > 3:
        return text

    recipe_dir = recipe_path.parent
    extra = ""

    for match in _REQUIRE_RE.finditer(text):
        inc_name = match.group(1)
        # Try relative to recipe directory first, then layer recipes-kernel
        candidates = [
            recipe_dir / inc_name,
            recipe_dir.parent / inc_name,
        ]
        for candidate in candidates:
            if candidate.exists():
                try:
                    inc_text = candidate.read_text(encoding="utf-8", errors="replace")
                    inc_text = _CONTINUATION_RE.sub("", inc_text)
                    inc_text = _resolve_includes(inc_text, candidate, depth + 1)
                    extra += "\n" + inc_text
                except OSError:
                    pass
                break

    return text + extra


def parse_src_uri(path: Path, machine: str = "") -> list[str]:
    """Extract SRC_URI entries from a .bb/.bbappend file.

    Returns a list of individual URI strings (split on whitespace).
    When machine is provided, also parses SRC_URI:append:MACHINE entries.
    """
    text = _read_and_join(path)
    if not text:
        return []

    # Follow require/include directives and expand local variables
    text = _resolve_includes(text, path)
    text = _expand_local_vars(text)

    uris: list[str] = []
    warnings: list[str] = []

    # Base assignments (=, +=, .=)
    for match in _SRC_URI_BASE_RE.finditer(text):
        uris.extend(_split_uris(match.group(1), warnings))

    # Unconditional appends (:append, _append without machine suffix)
    for match in _SRC_URI_APPEND_RE.finditer(text):
        uris.extend(_split_uris(match.group(1), warnings))

    # Machine-conditional appends
    if machine:
        pattern = re.compile(
            rf'^SRC_URI(?::append:{re.escape(machine)}|_append_{re.escape(machine)})\s*=\s*"((?:[^"\\]|\\.)*)"',
            re.MULTILINE,
        )
        for match in pattern.finditer(text):
            uris.extend(_split_uris(match.group(1), warnings))

    for w in warnings:
        logger.warning("Recipe %s: %s", path.name, w)

    return uris


def _split_uris(raw: str, warnings: list[str]) -> list[str]:
    """Split a raw SRC_URI value into individual URIs, checking for issues."""
    if _INLINE_PYTHON_RE.search(raw):
        warnings.append(f"Inline Python expression in SRC_URI skipped: {raw[:80]}")
    if _UNEXPANDED_VAR_RE.search(raw):
        warnings.append(f"Unexpanded variable in SRC_URI (recorded as-is): {raw[:80]}")
    return [u.strip() for u in raw.split() if u.strip()]


def _expand_local_vars(text: str) -> str:
    """Try to expand recipe-local ${VAR} references in SRC_URI.

    Looks for variable definitions in the same text and substitutes
    simple cases. Only handles string variables, not python expressions.
    """
    # Find all simple variable definitions: VAR = "value" or VAR ?= "value"
    var_defs: dict[str, str] = {}
    for match in re.finditer(r'^(\w+)\s*\??=\s*"((?:[^"\\]|\\.)*)"', text, re.MULTILINE):
        var_defs[match.group(1)] = match.group(2)

    # Substitute ${VAR} references (up to 3 passes for nested refs)
    result = text
    for _ in range(3):
        changed = False
        for var_name, var_value in var_defs.items():
            new = result.replace(f"${{{var_name}}}", var_value)
            if new != result:
                changed = True
                result = new
        if not changed:
            break
    return result


def parse_srcrev(path: Path, name: str = "") -> str:
    """Extract SRCREV value from a recipe file.

    Args:
        path: Path to the .bb/.bbappend file
        name: Optional named SRCREV (e.g., "machine" for SRCREV_machine)

    Handles SRCREV_pn-* per-recipe overrides, SRCREV_name named variants,
    and follows require/include directives.
    Returns "${AUTOREV}" as-is if that's what the recipe uses.
    Returns empty string if not found.
    """
    text = _read_and_join(path)
    if not text:
        return ""

    # Also read included files and expand local vars
    text = _resolve_includes(text, path)
    text = _expand_local_vars(text)

    # Check named SRCREV first (e.g., SRCREV_machine)
    if name:
        named_re = re.compile(rf'^SRCREV_{re.escape(name)}\s*=\s*"([^"]*)"', re.MULTILINE)
        match = named_re.search(text)
        if match:
            return match.group(1)

    # Check per-recipe override (more specific than base)
    pn_match = _SRCREV_PN_RE.search(text)
    if pn_match:
        return pn_match.group(2)

    # Named SRCREVs (SRCREV_machine, etc.) — take first that isn't "meta"
    for match in _SRCREV_NAMED_RE.finditer(text):
        variant_name = match.group(1)
        if variant_name not in ("meta",):  # skip kernel-meta SRCREV
            return match.group(2)

    # Standard SRCREV
    match = _SRCREV_RE.search(text)
    return match.group(1) if match else ""


def parse_variable(path: Path, name: str) -> str:
    """Extract a variable value from a recipe file.

    Simple extraction: matches NAME = "value" or NAME ?= "value".
    Follows require/include directives.
    Returns empty string if not found.
    """
    text = _read_and_join(path)
    if not text:
        return ""
    text = _resolve_includes(text, path)
    pattern = re.compile(_VAR_RE_TEMPLATE.format(re.escape(name)), re.MULTILINE)
    match = pattern.search(text)
    return match.group(1) if match else ""


def find_kernel_recipe(layer_path: Path, machine: str = "",
                       kernel_recipe_patterns: list[str] | None = None) -> Path | None:
    """Find the primary kernel recipe in a BSP layer.

    Search order:
    1. recipes-kernel/linux/*.bb
    2. recipes-kernel/linux-*/*.bb
    3. Any .bb with 'linux' in name under recipes-kernel/

    When multiple found and kernel_recipe_patterns is provided,
    filter by pattern match on recipe name (without version/extension).
    """
    recipes_kernel = layer_path / "recipes-kernel"
    if not recipes_kernel.exists():
        return None

    candidates: list[Path] = []

    # Standard locations
    linux_dir = recipes_kernel / "linux"
    if linux_dir.exists():
        candidates.extend(linux_dir.glob("*.bb"))

    # linux-* subdirectories (linux-raspberrypi, linux-toradex, etc.)
    for subdir in recipes_kernel.glob("linux-*"):
        if subdir.is_dir():
            candidates.extend(subdir.glob("*.bb"))

    # Broader search if nothing found
    if not candidates:
        for bb in recipes_kernel.rglob("*linux*.bb"):
            candidates.append(bb)

    if not candidates:
        return None

    # Filter by kernel_recipe_patterns if provided
    if kernel_recipe_patterns and len(candidates) > 1:
        filtered = []
        for c in candidates:
            recipe_name = c.stem.split("_")[0]  # linux-raspberrypi_6.1.bb → linux-raspberrypi
            if recipe_name in kernel_recipe_patterns:
                filtered.append(c)
        if filtered:
            candidates = filtered

    # If still multiple, prefer the one matching machine name heuristic
    if machine and len(candidates) > 1:
        for c in candidates:
            if machine.split("-")[0] in c.stem:
                return c

    # Return first (alphabetically for determinism)
    candidates.sort(key=lambda p: p.name)
    return candidates[0]


def gather_all_src_uris(recipe_path: Path, layer_path: Path,
                        machine: str = "") -> list[str]:
    """Gather all SRC_URI entries from a recipe and its same-layer bbappends.

    Parses the base .bb file and any matching .bbappend files within
    the same layer. Merges all URI entries into one list.
    """
    # Avoid circular import
    from discovery.bsp._layer_scanner import find_same_layer_bbappends

    uris = parse_src_uri(recipe_path, machine=machine)

    recipe_name = recipe_path.stem.split("_")[0]  # linux-raspberrypi_6.1.bb → linux-raspberrypi
    bbappends = find_same_layer_bbappends(recipe_name, layer_path)

    for bbappend in bbappends:
        uris.extend(parse_src_uri(bbappend, machine=machine))

    return uris


def has_cve_tag(patch_path: Path) -> bool:
    """Check if a patch file has CVE references in its filename or header."""
    if _CVE_FILENAME_RE.search(patch_path.name):
        return True

    try:
        # Read first 2KB for header check
        header = patch_path.read_text(encoding="utf-8", errors="replace")[:2048]
        return bool(_CVE_FILENAME_RE.search(header))
    except OSError:
        return False
