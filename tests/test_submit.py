"""Tests for discovery.submit — ArtifactBundle → scan API payload conversion."""

import json
from pathlib import Path

import pytest

from discovery.base import ArtifactBundle
from discovery.bsp._types import (
    BSPProfile,
    Confidence,
    PatchInfo,
    PatchSourceType,
    SuppressionStatus,
    VersionMatch,
)
from discovery.submit import bundle_to_payload


@pytest.fixture
def tmp_sbom(tmp_path: Path) -> Path:
    sbom = tmp_path / "sbom.spdx.json"
    sbom.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}')
    return sbom


@pytest.fixture
def tmp_kconfig(tmp_path: Path) -> Path:
    cfg = tmp_path / ".config"
    cfg.write_text("# Linux kernel config\nCONFIG_BT=n\nCONFIG_USB=y\n")
    return cfg


@pytest.fixture
def tmp_dtbs(tmp_path: Path) -> list[Path]:
    dtb1 = tmp_path / "board1.dts"
    dtb1.write_text("/dts-v1/;\n/ { model = \"Board 1\"; };")
    dtb2 = tmp_path / "board2.dts"
    dtb2.write_text("/dts-v1/;\n/ { model = \"Board 2\"; };")
    return [dtb1, dtb2]


class TestBundleToPayload:
    """Core conversion: ArtifactBundle → API payload dict."""

    def test_minimal_bundle(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(
            sbom=tmp_sbom,
            sbom_format="spdx",
            build_system="yocto",
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        assert payload["project_id"] == "proj-1"
        assert payload["version_label"] == "v1.0"
        assert payload["sbom_format"] == "spdx"
        assert '"spdxVersion"' in payload["sbom_raw"]
        assert payload["kconfig_raw"] == ""
        assert "dtb_raw" not in payload
        assert "idempotency_key" in payload
        assert len(payload["idempotency_key"]) == 32

    def test_full_bundle(self, tmp_sbom: Path, tmp_kconfig: Path, tmp_dtbs: list[Path]) -> None:
        bundle = ArtifactBundle(
            sbom=tmp_sbom,
            sbom_format="spdx",
            kconfig=tmp_kconfig,
            dtb=tmp_dtbs,
            yocto_machine="imx6qdl",
            yocto_distro="poky",
            kernel_version="6.1.77",
            build_system="yocto",
        )
        payload = bundle_to_payload(bundle, "proj-1", "v2.0")

        assert "CONFIG_BT=n" in payload["kconfig_raw"]
        assert "Board 1" in payload["dtb_raw"]
        assert "Board 2" in payload["dtb_raw"]
        assert payload["yocto_machine"] == "imx6qdl"
        assert payload["yocto_distro"] == "poky"
        assert payload["kernel_version"] == "6.1.77"

    def test_empty_bundle(self) -> None:
        bundle = ArtifactBundle(build_system="yocto")
        payload = bundle_to_payload(bundle, "proj-1", "v0.1")

        assert payload["sbom_raw"] == ""
        assert payload["sbom_format"] == ""
        assert payload["kconfig_raw"] == ""
        assert "dtb_raw" not in payload

    def test_policy_name_excludes_custom_filter(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(
            sbom=tmp_sbom,
            sbom_format="spdx",
            packageconfig_suppressions={"openssl": ["CVE-2023-0001"]},
            build_system="yocto",
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0", policy_name="Automotive Base")

        assert payload["policy_name"] == "Automotive Base"
        assert "custom_filter_raw" not in payload

    def test_idempotency_key_deterministic(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx")
        p1 = bundle_to_payload(bundle, "proj-1", "v1.0")
        p2 = bundle_to_payload(bundle, "proj-1", "v1.0")
        assert p1["idempotency_key"] == p2["idempotency_key"]

    def test_idempotency_key_changes_with_version(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx")
        p1 = bundle_to_payload(bundle, "proj-1", "v1.0")
        p2 = bundle_to_payload(bundle, "proj-1", "v2.0")
        assert p1["idempotency_key"] != p2["idempotency_key"]

    def test_missing_dtb_file_skipped(self, tmp_path: Path, tmp_sbom: Path) -> None:
        """DTB paths that no longer exist are silently skipped."""
        ghost = tmp_path / "gone.dts"
        real = tmp_path / "real.dts"
        real.write_text("/dts-v1/;\n/ { model = \"Real\"; };")

        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx", dtb=[ghost, real])
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        assert "Real" in payload["dtb_raw"]
        assert "gone" not in payload.get("dtb_raw", "")


class TestSbomFormatNormalization:
    """SBOM format detection and normalization."""

    def test_spdx_declared(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "spdx"

    def test_cyclonedx_declared(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="cyclonedx")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "cyclonedx"

    def test_yocto_manifest_hyphen(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="yocto-manifest")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "yocto_manifest"

    def test_fallback_detection_spdx(self, tmp_path: Path) -> None:
        sbom = tmp_path / "output.spdx.json"
        sbom.write_text('{"spdxVersion": "SPDX-2.3"}')
        bundle = ArtifactBundle(sbom=sbom, sbom_format="unknown")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "spdx"

    def test_fallback_detection_cyclonedx(self, tmp_path: Path) -> None:
        sbom = tmp_path / "bom.json"
        sbom.write_text('{"bomFormat": "CycloneDX"}')
        bundle = ArtifactBundle(sbom=sbom, sbom_format="")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "cyclonedx"


class TestPackageConfigSuppression:
    """PACKAGECONFIG suppressions → custom_filter_raw rules."""

    def test_packageconfig_rules(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(
            sbom=tmp_sbom,
            sbom_format="spdx",
            build_system="yocto",
            packageconfig_suppressions={
                "openssl": ["CVE-2023-0001", "CVE-2023-0002"],
                "curl": ["CVE-2023-1000"],
            },
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        assert "custom_filter_raw" in payload
        doc = json.loads(payload["custom_filter_raw"])
        assert doc["version"] == "1"
        assert "yocto" in doc["description"]
        assert len(doc["rules"]) == 3

        cve_ids = {r["match"]["value"] for r in doc["rules"]}
        assert cve_ids == {"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-1000"}

        for rule in doc["rules"]:
            assert rule["match"]["type"] == "exact_cve"
            assert rule["result"]["status"] == "not_affected"
            assert rule["result"]["justification_category"] == "requires_configuration"
            assert rule["result"]["confidence"] == "medium"
            assert len(rule["result"]["justification_text"]) >= 20
            assert rule["id"].startswith("pkgcfg-")

    def test_no_suppressions_no_custom_filter(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx")
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")
        assert "custom_filter_raw" not in payload


class TestBspVersionSuppression:
    """BSP version-based suppressions → custom_filter_raw rules."""

    def test_bsp_version_rules(self, tmp_sbom: Path) -> None:
        profile = BSPProfile(
            vendor="raspberrypi",
            kernel_version_detected="6.1.77",
            kernel_branch_detected="6.1",
            version_matches=[
                VersionMatch(
                    cve_id="CVE-2024-1001",
                    fixed_in_version="6.1.75",
                    bsp_version="6.1.77",
                    stable_branch="6.1",
                    status=SuppressionStatus.SUPPRESSED,
                    confidence=Confidence.HIGH,
                ),
                VersionMatch(
                    cve_id="CVE-2024-2002",
                    fixed_in_version="6.1.80",
                    bsp_version="6.1.77",
                    stable_branch="6.1",
                    status=SuppressionStatus.VULNERABLE,
                    confidence=Confidence.HIGH,
                ),
                VersionMatch(
                    cve_id="CVE-2024-3003",
                    fixed_in_version="6.1.70",
                    bsp_version="6.1.77",
                    stable_branch="6.1",
                    status=SuppressionStatus.SUPPRESSED,
                    confidence=Confidence.MEDIUM,
                ),
            ],
        )
        bundle = ArtifactBundle(
            sbom=tmp_sbom,
            sbom_format="spdx",
            build_system="yocto",
            bsp_profile=profile,
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        doc = json.loads(payload["custom_filter_raw"])
        rules = doc["rules"]

        # Only SUPPRESSED matches become rules (not VULNERABLE)
        assert len(rules) == 2
        cve_ids = {r["match"]["value"] for r in rules}
        assert cve_ids == {"CVE-2024-1001", "CVE-2024-3003"}

        # Check rule structure
        r1 = next(r for r in rules if r["match"]["value"] == "CVE-2024-1001")
        assert r1["match"]["type"] == "exact_cve"
        assert r1["result"]["confidence"] == "high"
        assert r1["result"]["justification_category"] == "patched_backport"
        assert r1["result"]["status"] == "not_affected"
        assert "6.1.75" in r1["result"]["justification_text"]
        assert "6.1.77" in r1["result"]["justification_text"]
        assert r1["id"].startswith("bsp-ver-")

    def test_mixed_packageconfig_and_bsp(self, tmp_sbom: Path) -> None:
        profile = BSPProfile(
            vendor="toradex",
            version_matches=[
                VersionMatch(
                    cve_id="CVE-2024-5000",
                    fixed_in_version="5.15.100",
                    bsp_version="5.15.120",
                    stable_branch="5.15",
                    status=SuppressionStatus.SUPPRESSED,
                    confidence=Confidence.HIGH,
                ),
            ],
        )
        bundle = ArtifactBundle(
            sbom=tmp_sbom,
            sbom_format="spdx",
            build_system="yocto",
            packageconfig_suppressions={"openssl": ["CVE-2023-9999"]},
            bsp_profile=profile,
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        doc = json.loads(payload["custom_filter_raw"])
        rules = doc["rules"]
        assert len(rules) == 2

        # All use exact_cve match but different justification categories
        categories = {r["result"]["justification_category"] for r in rules}
        assert categories == {"requires_configuration", "patched_backport"}


class TestEdgeCases:
    """Edge cases and error handling."""

    def test_empty_optional_fields_omitted(self) -> None:
        """Payload should not include empty optional fields."""
        bundle = ArtifactBundle(build_system="yocto")
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        assert "dtb_raw" not in payload
        assert "policy_name" not in payload
        assert "custom_filter_raw" not in payload
        # These are always present (even if empty)
        assert "sbom_raw" in payload
        assert "kconfig_raw" in payload

    def test_yocto_metadata_absent(self) -> None:
        """Missing yocto_machine/distro/kernel_version omitted from payload."""
        bundle = ArtifactBundle(build_system="yocto")
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        assert "yocto_machine" not in payload
        assert "yocto_distro" not in payload
        assert "kernel_version" not in payload

    def test_bsp_profile_no_version_matches(self, tmp_sbom: Path) -> None:
        """BSP profile with patches but no version matches produces no rules."""
        profile = BSPProfile(
            vendor="nxp",
            patches=[
                PatchInfo(
                    name="fix-usb.patch",
                    source_type=PatchSourceType.FILE,
                    path=Path("/fake/fix-usb.patch"),
                ),
            ],
        )
        bundle = ArtifactBundle(
            sbom=tmp_sbom,
            sbom_format="spdx",
            bsp_profile=profile,
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")
        assert "custom_filter_raw" not in payload
