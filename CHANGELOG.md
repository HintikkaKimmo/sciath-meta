# Changelog

All notable changes to sciath-meta will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Scan API payload bridge** — `bundle_to_payload()` converts ArtifactBundle to the dict format expected by the scan creation API. Reads artifact files, serializes PACKAGECONFIG and BSP version suppressions into custom_filter_raw rules, generates idempotency keys. This is the missing link between discovery and the CLI's `--auto-discover` flag.
- **BSP layer patch discovery** — VendorAdapter pattern for extracting kernel patches from vendor BSP layers. Supports file patches (Raspberry Pi), forked kernel repos (Toradex, NXP), and hybrid (PHYTEC). Static analysis only, no BitBake environment required.
- **Machine-aware recipe parsing** — static regex parser for .bb/.bbappend files handles SRC_URI assignment variants including machine-conditional overrides (SRC_URI:append:MACHINE).
- **Vendor profile system** — JSON-based vendor detection with profiles for Raspberry Pi, Toradex, NXP i.MX, PHYTEC, and a generic fallback.
- **Confidence-rated patch metadata** — PatchInfo includes high/medium/low confidence based on CVE tag presence, with defined consumer behavior spec.
- **Version-based CVE suppression** — cross-references BSP kernel version against vulns.git database to identify which CVEs are already fixed by the running kernel version. Produces suppressed/vulnerable/unknown status per CVE with configurable confidence levels.
- **Kernel version extraction** — `parse_linux_version()` extracts LINUX_VERSION, PV, or filename-based version from kernel recipes without BitBake.
- **vulns.git database parser** — parses linux kernel vulns.git repository and produces a JSON database mapping CVE IDs to fixing commits and stable kernel versions.
- **SuppressionStatus/Confidence enums** — type-safe enums replace string literals for suppression status and confidence levels.

### Changed

- **Schema version bump** — ArtifactBundle schema_version updated from "1.1" to "1.2" (new bsp_profile field).
- **Configurable PACKAGECONFIG recipes** — override default recipe list via `SCIATH_PACKAGECONFIG_RECIPES` env var (comma-separated)
- **Configurable DTB cap** — override default 20-DTB limit via `SCIATH_MAX_DTBS` env var
- **Schema version** — `ArtifactBundle` now includes `schema_version` field (default "1.0")
- **Path validation** — `auto_discover()` resolves symlinks and validates absolute paths
- **Expanded test coverage** — added `test_yocto_edge_cases.py` covering DTB cap enforcement, CycloneDX SBOM detection, bitbake timeout handling, PACKAGECONFIG edge cases, configurable recipes/DTB cap, and schema version
- **Updated CLAUDE.md** — added `schema_version` to `ArtifactBundle` code example, added environment variable configuration table
- **Updated README.md** — added configuration section with required Yocto variables and optional env vars

### Added

- **Initial Yocto bbclass + discovery modules.** Sciath-meta integrates with Yocto
  builds to extract SBOM, kconfig, DTB, and PACKAGECONFIG metadata for upload to
  the Sciath platform.
- **Packaging, linting, and test suite.** pyproject.toml packaging, ruff linting,
  and initial test coverage.
- **CI workflow.** GitHub Actions for linting and tests. Pre-commit hooks configured.
- **Signed releases.** Hash-verified dependencies, pip-audit for vulnerability
  scanning in CI.
- **SECURITY.md, CODEOWNERS.** Gitleaks, semgrep scanning, SHA-pinned GitHub Actions.
- **Conventional commit enforcement** via pre-commit hook and CI.

[Unreleased]: https://github.com/HintikkaKimmo/sciath-meta/commits/main
