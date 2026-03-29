# Changelog

All notable changes to sciath-meta will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
