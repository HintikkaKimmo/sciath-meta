# sciath-meta

Yocto/OpenEmbedded integration and Python artifact discovery for Sciath's
embedded-Linux CRA compliance tooling. This repository contains build hooks and
artifact collection, not the vulnerability-analysis service.

## What is implemented

| Build system | Status | Location |
| --- | --- | --- |
| Yocto/OpenEmbedded | Discovery implementation and BitBake class | `discovery/yocto.py`, `meta-sciath/` |
| Buildroot | Detection stub; collection raises `NotImplementedError` | `discovery/buildroot.py` |
| Debian | Detection stub; collection raises `NotImplementedError` | `discovery/debian.py` |
| OpenWrt | Detection stub; collection raises `NotImplementedError` | `discovery/openwrt.py` |

The layer declares compatibility with Kirkstone, Scarthgap, and Styhead in
`meta-sciath/conf/layer.conf`. This declaration is not a complete build-test
matrix. Discovery collects SBOMs, kernel configuration, device-tree artifacts,
PACKAGECONFIG data, and BSP metadata. Additional build-system support is planned.

## Yocto setup

Install [sciath-cli](https://github.com/HintikkaKimmo/sciath-cli) on the build
host and make the `sciath` executable available in the BitBake task's `PATH`.
Scanning also requires a compatible Sciath compliance API, a project, and an
API key. The backend is not included here; the current private `sciath` product
is not a drop-in compliance backend.

```bash
git clone https://github.com/HintikkaKimmo/sciath-meta.git
# After entering your Yocto build environment:
bitbake-layers add-layer /absolute/path/to/sciath-meta/meta-sciath
```

In `conf/local.conf` (keep real credentials out of version control):

```bitbake
SCIATH_ENABLED = "1"
SCIATH_API_URL = "https://your-compliance-api.example"
SCIATH_API_KEY = "your-api-key"
SCIATH_PROJECT = "your-project-id"
```

In the image recipe:

```bitbake
inherit sciath
```

Then build the image normally, for example `bitbake core-image-minimal`. The
scan task runs after `do_rootfs`, with a ten-minute timeout. It writes
`${DEPLOY_DIR_IMAGE}/sciath_scan_id` when an ID is returned, and `sciath_result`
when a remaining-finding count is available (`PASS` or `REVIEW`). These files
are not guaranteed after a failed scan, and `PASS` is not a legal compliance
certification.

## Configuration

BitBake variables in `local.conf`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCIATH_ENABLED` | `0` | Set to `1` to run scans |
| `SCIATH_API_KEY` | empty | Required API credential |
| `SCIATH_PROJECT` | empty | Required compliance API project identifier |
| `SCIATH_API_URL` | `https://api.sciath.io` | Compatible compliance API endpoint |
| `SCIATH_POLICY` | empty | Optional named filter policy |
| `SCIATH_FAIL_ON_ERROR` | `0` | Set to `1` to make scan errors fatal to the build |

Discovery also reads these process environment variables: `SCIATH_MAX_DTBS`
(default `20`), `SCIATH_PACKAGECONFIG_RECIPES` (nine built-in recipe mappings),
`SCIATH_VULNS_DB` (alternative vulnerability database), `SCIATH_KERNEL_VERSION`
(version override), and `SCIATH_VERSION_SUPPRESSION` (`0` disables version-based
suppression). A process environment variable must reach the discovery process;
setting it as an arbitrary BitBake variable alone does not export it.

## Python development

Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are required for the
locked development environment. The discovery package has no runtime Python
dependencies. The wheel contains `discovery`; use the repository checkout for
the BitBake layer.

```bash
uv sync --frozen --extra dev
uv run pytest tests/
uv run ruff check .
uv run mypy discovery/
uv run pip-audit
uv build
```

```python
from discovery import auto_discover, bundle_to_payload

bundle = auto_discover("/absolute/path/to/yocto/build", "yocto")
payload = bundle_to_payload(bundle, project_id="your-project-id", version_label="build-1")
```

This local example collects artifacts and constructs a payload; it does not
submit a scan. The published CLI bundles its own discovery module, so installing
this package does not replace discovery inside `sciath-cli`.

## License

[PolyForm Shield 1.0.0](LICENSE.md). Copyright 2026 Kimmo Hintikka;
see [NOTICE](NOTICE). This is source-available software, not OSI-approved open
source. The license permits noncompeting uses, including commercial uses, and
restricts competing uses as defined in its terms. Contact the licensor for
permission for uses outside those terms. Third-party dependencies retain their
own licenses.

Earlier revisions declared MIT and remain in Git history. This license change
does not revoke rights already granted under those earlier terms.
