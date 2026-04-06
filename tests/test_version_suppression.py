"""Tests for version-based CVE suppression engine."""

from unittest.mock import patch

from discovery.bsp._types import (
    BSPProfile,
    Confidence,
    PatchInfo,
    PatchSourceType,
    SuppressionStatus,
    VersionMatch,
)
from discovery.bsp._version_suppression import (
    _normalize_kernel_version,
    _parse_version_tuple,
    check_version_suppression,
    parse_kernel_version,
)
from discovery.bsp._vulns_db import VulnEntry


def _make_vulns_db(**cves: dict) -> dict[str, VulnEntry]:
    """Helper to create a test vulns DB.

    Usage: _make_vulns_db(**{"CVE-2024-1234": {"6.1": "6.1.75"}})
    """
    db = {}
    for cve_id, versions in cves.items():
        db[cve_id] = VulnEntry(
            cve_id=cve_id,
            fixing_commits=["a" * 40],
            fixed_in_versions=versions,
        )
    return db


class TestParseVersionTuple:
    def test_standard(self):
        assert _parse_version_tuple("6.1.77") == (6, 1, 77)

    def test_two_segment(self):
        assert _parse_version_tuple("6.6") == (6, 6, 0)

    def test_vendor_suffix(self):
        assert _parse_version_tuple("6.1.77-toradex-1.0") == (6, 1, 77)

    def test_srcpv_suffix(self):
        assert _parse_version_tuple("6.1.77+git${SRCPV}") == (6, 1, 77)

    def test_rc_version(self):
        tup = _parse_version_tuple("6.1.77-rc1")
        assert tup is not None
        assert tup < (6, 1, 77)

    def test_three_digit_patch(self):
        assert _parse_version_tuple("6.1.100") == (6, 1, 100)

    def test_three_digit_gt(self):
        """The classic bug: 6.1.100 > 6.1.99 must work with tuples."""
        assert _parse_version_tuple("6.1.100") > _parse_version_tuple("6.1.99")

    def test_empty_string(self):
        assert _parse_version_tuple("") is None

    def test_garbage(self):
        assert _parse_version_tuple("not-a-version") is None

    def test_plus_git(self):
        assert _parse_version_tuple("6.1.77+gitAUTOINC") == (6, 1, 77)


class TestNormalizeKernelVersion:
    def test_standard(self):
        assert _normalize_kernel_version("6.1.77") == "6.1.77"

    def test_vendor_suffix(self):
        assert _normalize_kernel_version("6.1.77-toradex-1.0") == "6.1.77"

    def test_srcpv(self):
        assert _normalize_kernel_version("6.1.77+git${SRCPV}") == "6.1.77"

    def test_two_segment(self):
        assert _normalize_kernel_version("6.6") == "6.6.0"

    def test_rc(self):
        # RC normalizes to the target version (stripping RC marker)
        assert _normalize_kernel_version("6.1.77-rc1") == "6.1.77"

    def test_empty(self):
        assert _normalize_kernel_version("") == ""


class TestParseKernelVersion:
    def test_from_linux_version_metadata(self):
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        branch, version = parse_kernel_version(profile)
        assert branch == "6.1"
        assert version == "6.1.77"

    def test_from_upstream_base_hint(self):
        profile = BSPProfile(metadata={"upstream_base_hint": "6.6.15"})
        branch, version = parse_kernel_version(profile)
        assert branch == "6.6"
        assert version == "6.6.15"

    def test_from_recipe_filename(self):
        profile = BSPProfile(kernel_recipe="linux-raspberrypi_6.6")
        branch, version = parse_kernel_version(profile)
        assert branch == "6.6"
        assert version == "6.6.0"

    def test_linux_version_priority(self):
        """linux_version takes priority over upstream_base_hint."""
        profile = BSPProfile(
            metadata={"linux_version": "6.1.77", "upstream_base_hint": "6.6.15"},
        )
        branch, version = parse_kernel_version(profile)
        assert version == "6.1.77"

    def test_env_var_override(self):
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        with patch.dict("os.environ", {"SCIATH_KERNEL_VERSION": "6.6.20"}):
            branch, version = parse_kernel_version(profile)
        assert branch == "6.6"
        assert version == "6.6.20"

    def test_empty_profile(self):
        profile = BSPProfile()
        branch, version = parse_kernel_version(profile)
        assert branch == ""
        assert version == ""

    def test_autorev_srcrev(self):
        profile = BSPProfile(kernel_srcrev="${AUTOREV}")
        branch, version = parse_kernel_version(profile)
        assert branch == ""
        assert version == ""


class TestCheckVersionSuppression:
    def test_suppressed(self):
        """BSP on 6.1.77, CVE fixed in 6.1.75 → SUPPRESSED."""
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        db = _make_vulns_db(**{"CVE-2024-1234": {"6.1": "6.1.75"}})
        matches = check_version_suppression(profile, db)
        assert len(matches) == 1
        assert matches[0].status == SuppressionStatus.SUPPRESSED
        assert matches[0].confidence == Confidence.HIGH

    def test_vulnerable(self):
        """BSP on 6.1.77, CVE fixed in 6.1.80 → VULNERABLE."""
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        db = _make_vulns_db(**{"CVE-2024-5678": {"6.1": "6.1.80"}})
        matches = check_version_suppression(profile, db)
        assert len(matches) == 1
        assert matches[0].status == SuppressionStatus.VULNERABLE

    def test_unknown_branch(self):
        """BSP on 6.1.77, CVE only fixed in 6.6.x → UNKNOWN."""
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        db = _make_vulns_db(**{"CVE-2024-9999": {"6.6": "6.6.15"}})
        matches = check_version_suppression(profile, db)
        assert len(matches) == 1
        assert matches[0].status == SuppressionStatus.UNKNOWN

    def test_exact_match_suppressed(self):
        """BSP on 6.1.77, CVE fixed in 6.1.77 → SUPPRESSED (>=)."""
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        db = _make_vulns_db(**{"CVE-2024-1111": {"6.1": "6.1.77"}})
        matches = check_version_suppression(profile, db)
        assert matches[0].status == SuppressionStatus.SUPPRESSED

    def test_fork_gets_medium_confidence(self):
        """Fork-based BSP should get MEDIUM confidence."""
        profile = BSPProfile(
            metadata={"linux_version": "6.1.77"},
            patches=[
                PatchInfo(
                    name="kernel-fork",
                    source_type=PatchSourceType.GIT_FORK,
                    git_url="https://github.com/vendor/linux.git",
                ),
            ],
        )
        db = _make_vulns_db(**{"CVE-2024-1234": {"6.1": "6.1.75"}})
        matches = check_version_suppression(profile, db)
        assert matches[0].confidence == Confidence.MEDIUM

    def test_empty_vulns_db(self):
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        matches = check_version_suppression(profile, {})
        assert matches == []

    def test_no_version(self):
        profile = BSPProfile()
        db = _make_vulns_db(**{"CVE-2024-1234": {"6.1": "6.1.75"}})
        matches = check_version_suppression(profile, db)
        assert matches == []

    def test_multi_branch_cve(self):
        """CVE fixed in both 6.1 and 6.6 → picks correct branch."""
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        db = _make_vulns_db(**{
            "CVE-2024-2222": {"6.1": "6.1.80", "6.6": "6.6.10"},
        })
        matches = check_version_suppression(profile, db)
        assert len(matches) == 1
        assert matches[0].status == SuppressionStatus.VULNERABLE
        assert matches[0].fixed_in_version == "6.1.80"

    def test_three_digit_patch_comparison(self):
        """6.1.100 > 6.1.99 must use tuple comparison, not string."""
        profile = BSPProfile(metadata={"linux_version": "6.1.100"})
        db = _make_vulns_db(**{"CVE-2024-3333": {"6.1": "6.1.99"}})
        matches = check_version_suppression(profile, db)
        assert matches[0].status == SuppressionStatus.SUPPRESSED

    def test_disabled_via_env(self):
        profile = BSPProfile(metadata={"linux_version": "6.1.77"})
        db = _make_vulns_db(**{"CVE-2024-1234": {"6.1": "6.1.75"}})
        with patch.dict("os.environ", {"SCIATH_VERSION_SUPPRESSION": "0"}):
            matches = check_version_suppression(profile, db)
        assert matches == []

    def test_suppressed_cves_property(self):
        profile = BSPProfile(
            metadata={"linux_version": "6.1.77"},
            version_matches=[
                VersionMatch(
                    cve_id="CVE-2024-1234",
                    fixed_in_version="6.1.75",
                    bsp_version="6.1.77",
                    stable_branch="6.1",
                    status=SuppressionStatus.SUPPRESSED,
                ),
                VersionMatch(
                    cve_id="CVE-2024-5678",
                    fixed_in_version="6.1.80",
                    bsp_version="6.1.77",
                    stable_branch="6.1",
                    status=SuppressionStatus.VULNERABLE,
                ),
            ],
        )
        assert profile.suppressed_cves == {"CVE-2024-1234"}
        assert profile.vulnerable_cves == {"CVE-2024-5678"}
