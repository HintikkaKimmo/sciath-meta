# Sciath-meta — Claude Context

## What is this?

Build system integration plugins for [Sciath](https://sciath.io) — CRA compliance
automation for embedded Linux. These plugins hook into build systems (Yocto, Buildroot,
Debian, etc.) to automatically extract firmware artifacts and run Sciath vulnerability
scans as part of the build process.

**This repo does NOT contain the Sciath engine or CLI.** It contains thin wrappers
that call the Sciath CLI or API. The server lives at
[HintikkaKimmo/sciath](https://github.com/HintikkaKimmo/sciath) and the CLI at
[HintikkaKimmo/sciath-cli](https://github.com/HintikkaKimmo/sciath-cli).

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  This repo: Sciath-meta                              │
│                                                      │
│  meta-sciath/        → Yocto/OE bbclass              │
│  buildroot/          → Buildroot post-build hook      │
│  debian/             → dpkg/sbuild integration        │
│  openwrt/            → OpenWrt build hook              │
│  discovery/          → Shared artifact discovery logic │
│  tests/              → Integration tests with fixtures │
└──────────────┬───────────────────────────────────────┘
               │ calls
┌──────────────▼───────────────────────────────────────┐
│  sciath-cli (separate repo + PyPI package)            │
│  sciath scan run --auto-discover --build-system yocto │
│  sciath policy create/import-vex                      │
└──────────────┬───────────────────────────────────────┘
               │ HTTP
┌──────────────▼───────────────────────────────────────┐
│  Sciath backend API                                   │
│  /policies/v1/ — filter policy CRUD + VEX import      │
│  /scans/v1/    — scan creation + analysis             │
└───────────────────────────────────────────────────────┘
```

## Supported build systems

| Build System | Plugin | Status | Artifacts Extracted |
|---|---|---|---|
| **Yocto/OpenEmbedded** | `meta-sciath/` | Phase 1 (priority) | SBOM, kconfig, DTB, PACKAGECONFIG, busybox config, cve-check patches |
| **Buildroot** | `buildroot/` | Planned | SBOM (from legal-info), kconfig, DTB, BR2 config opts |
| **Debian/Ubuntu** | `debian/` | Planned | SBOM (from dpkg), kconfig, DTB, quilt patches |
| **OpenWrt** | `openwrt/` | Planned | SBOM (from package feeds), kconfig, DTB |
| **Zephyr** | Future | Not started | west.yml manifest, prj.conf (Kconfig), DTS overlays |
| **NuttX** | Future | Not started | .config (Kconfig), Make.defs |

**Priority:** Yocto first. Others gated on paying customer demand.

## Yocto integration (meta-sciath/)

### How it works

```
# In your Yocto build's conf/local.conf or distro config:
SCIATH_API_KEY = "sk-..."          # Required
SCIATH_PROJECT = "rpi4-gateway"     # Required — project name in Sciath
SCIATH_POLICY = "Automotive Base"   # Optional — named filter policy
SCIATH_ENABLED = "1"                # Opt-in (disabled by default)

# In your image recipe:
inherit sciath
```

The `sciath.bbclass`:
1. Hooks into `do_rootfs` (runs after the root filesystem is assembled)
2. Discovers artifacts from the build tree:
   - SBOM: `create-spdx.bbclass` output or cve-check manifest
   - Kernel .config: `${STAGING_KERNEL_DIR}/.config`
   - DTBs: `${DEPLOY_DIR_IMAGE}/*.dtb`
   - PACKAGECONFIG: extracted via `bitbake -e` per recipe
   - Busybox .config: from busybox recipe workdir
3. Calls `sciath scan run --auto-discover` or the Sciath API directly
4. Stores `scan_id` in `${DEPLOY_DIR_IMAGE}/sciath_scan_id`

### Failure modes

- **`SCIATH_ENABLED = "0"` (default):** Plugin does nothing. Zero build impact.
- **Network error:** `bb.warn()` and continue. Build does NOT fail unless
  `SCIATH_FAIL_ON_ERROR = "1"` is explicitly set.
- **API error (auth, validation):** Same — warn and continue by default.
- **sciath-cli not installed:** `bb.error()` with installation instructions.

### Artifact locations in Yocto

| Artifact | Path | Notes |
|---|---|---|
| SBOM (SPDX) | `${DEPLOY_DIR}/spdx/` | Requires `INHERIT += "create-spdx"` in local.conf |
| SBOM (cve-check) | `${DEPLOY_DIR}/cve/` | Requires `INHERIT += "cve-check"` |
| Kernel .config | `${STAGING_KERNEL_DIR}/.config` | Always present after kernel build |
| DTBs | `${DEPLOY_DIR_IMAGE}/*.dtb` | Present if DTB is built for the machine |
| PACKAGECONFIG | `bitbake -e <recipe>` → `PACKAGECONFIG` var | Requires bitbake environment access |
| Busybox .config | `${WORKDIR}/busybox-*/build/.config` | Present if busybox is in the image |
| Yocto patches | `${WORKDIR}/temp/log.do_patch` | Build log of applied patches |

## Discovery module (discovery/)

Shared Python module for artifact discovery across build systems. Each build system
implements the `BuildSystemDiscovery` ABC:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

@dataclass
class ArtifactBundle:
    sbom: Optional[Path] = None
    sbom_format: str = ""
    kconfig: Optional[Path] = None
    dtb: list[Path] = field(default_factory=list)
    busybox_config: Optional[Path] = None
    packageconfigs: dict[str, list[str]] = field(default_factory=dict)
    yocto_machine: str = ""
    yocto_distro: str = ""
    kernel_version: str = ""
    build_system: str = ""
    metadata: dict = field(default_factory=dict)

class BuildSystemDiscovery(ABC):
    @abstractmethod
    def detect(self, build_dir: Path) -> bool:
        """Return True if this build system is detected."""

    @abstractmethod
    def collect(self, build_dir: Path) -> ArtifactBundle:
        """Collect all scannable artifacts from the build tree."""
```

**Path safety:** `collect()` must validate that `build_dir` is an absolute path
and all discovered files are within it. No traversal outside the build directory.

## Development

```bash
# Run tests (requires mock Yocto build tree fixtures)
pytest tests/ -v

# Lint
ruff check .

# Type check
mypy discovery/
```

## Key principles

- **Non-blocking by default.** Build system plugins must NEVER fail a build due to
  Sciath errors. Default is `SCIATH_ENABLED = "0"` (opt-in) and network errors are
  warnings, not failures.

- **Thin wrappers.** Each plugin is 50-200 lines of glue. The logic lives in the
  Sciath CLI/API, not here. If you're writing complex logic in a bbclass, it probably
  belongs in the CLI's discovery module instead.

- **Zero false negatives.** The Sciath engine's hard constraint applies here too:
  better to include an artifact (even if it might not be needed) than to skip one
  and miss CVE matches. When in doubt, collect more, not less.

- **Build system native.** Use the build system's own extension mechanism (bbclass for
  Yocto, post-build hook for Buildroot, dpkg trigger for Debian). Don't fight the
  build system.

## Relationship to other repos

| Repo | What it is | When to look there |
|---|---|---|
| [HintikkaKimmo/sciath](https://github.com/HintikkaKimmo/sciath) | Backend API + engine | API endpoint contracts, filter logic, policy model |
| [HintikkaKimmo/sciath-cli](https://github.com/HintikkaKimmo/sciath-cli) | CLI tool | `sciath scan run` flags, `sciath policy` commands, output format |
| **This repo** | Build system plugins | Artifact discovery, build hooks, integration patterns |

When implementing a new discovery module, first check the CLI's `--auto-discover`
flag implementation to understand what artifacts the scan API expects.

## Versioning

Independent from sciath and sciath-cli. Each plugin has its own version:
- `meta-sciath/conf/layer.conf` → `LAYERVERSION`
- `buildroot/sciath.mk` → version comment
- Discovery module → `discovery/__init__.py` → `__version__`

Use semantic versioning. Tag format: `v0.1.0`.
