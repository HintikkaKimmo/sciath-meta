# Sciath-meta

Build system integration plugins for [Sciath](https://sciath.io) — CRA compliance
automation for embedded Linux.

## Quick Start (Yocto)

```bash
# 1. Add meta-sciath to your bblayers.conf
bitbake-layers add-layer /path/to/Sciath-meta/meta-sciath

# 2. Configure in conf/local.conf
SCIATH_ENABLED = "1"
SCIATH_API_KEY = "sk-..."
SCIATH_PROJECT = "my-product"
SCIATH_POLICY = "Automotive Base"    # optional

# 3. Inherit in your image recipe
inherit sciath

# 4. Build — scan runs automatically after do_rootfs
bitbake core-image-minimal
```

Results are written to `${DEPLOY_DIR_IMAGE}/sciath_scan_id` and
`${DEPLOY_DIR_IMAGE}/sciath_result`.

## Supported Build Systems

| Build System | Status | Plugin |
|---|---|---|
| Yocto/OE | **Ready** | `meta-sciath/` |
| Buildroot | Planned | `buildroot/` |
| Debian | Planned | `debian/` |
| OpenWrt | Planned | `openwrt/` |

## Configuration

### Required (in Yocto `local.conf`)

| Variable | Description |
|----------|-------------|
| `SCIATH_ENABLED` | Set to `"1"` to enable scanning (disabled by default) |
| `SCIATH_API_KEY` | Your Sciath API key |
| `SCIATH_PROJECT` | Project name in Sciath |

### Optional (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `SCIATH_PACKAGECONFIG_RECIPES` | `openssl,curl,busybox,...` (9 recipes) | Comma-separated list of recipes to extract PACKAGECONFIG from |
| `SCIATH_MAX_DTBS` | `20` | Maximum number of DTB files to collect |

## Requirements

- [sciath-cli](https://github.com/HintikkaKimmo/sciath-cli) installed (`pip install sciath-cli`)
- Sciath API key (get one at [sciath.io](https://sciath.io))

## License

MIT
