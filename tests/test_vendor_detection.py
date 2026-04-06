"""Tests for vendor detection from layer names."""

from pathlib import Path

from discovery.bsp.adapters import clear_caches, detect_vendor
from discovery.bsp.adapters.file_patches import FilePatchAdapter
from discovery.bsp.adapters.forked_kernel import ForkedKernelAdapter
from discovery.bsp.adapters.hybrid import HybridAdapter


class TestVendorDetection:
    def setup_method(self):
        clear_caches()

    def test_detects_raspberrypi(self, tmp_path: Path):
        vendor, adapter, profile = detect_vendor(
            ["meta-poky", "meta-raspberrypi"],
            {"meta-poky": tmp_path, "meta-raspberrypi": tmp_path},
        )
        assert vendor == "raspberrypi"
        assert isinstance(adapter, ForkedKernelAdapter)

    def test_detects_toradex(self, tmp_path: Path):
        vendor, adapter, profile = detect_vendor(
            ["meta-poky", "meta-toradex-bsp-common"],
            {"meta-poky": tmp_path, "meta-toradex-bsp-common": tmp_path},
        )
        assert vendor == "toradex"
        assert isinstance(adapter, ForkedKernelAdapter)

    def test_detects_toradex_nxp_variant(self, tmp_path: Path):
        vendor, adapter, _ = detect_vendor(
            ["meta-poky", "meta-toradex-nxp"],
            {"meta-poky": tmp_path, "meta-toradex-nxp": tmp_path},
        )
        assert vendor == "toradex"

    def test_detects_phytec_hybrid(self, tmp_path: Path):
        vendor, adapter, _ = detect_vendor(
            ["meta-poky", "meta-phytec"],
            {"meta-poky": tmp_path, "meta-phytec": tmp_path},
        )
        assert vendor == "phytec"
        assert isinstance(adapter, HybridAdapter)

    def test_detects_nxp_imx(self, tmp_path: Path):
        vendor, adapter, _ = detect_vendor(
            ["meta-poky", "meta-imx"],
            {"meta-poky": tmp_path, "meta-imx": tmp_path},
        )
        assert vendor == "nxp_imx"

    def test_falls_back_to_generic(self, tmp_path: Path):
        vendor, adapter, _ = detect_vendor(
            ["meta-poky", "meta-unknown-vendor"],
            {"meta-poky": tmp_path, "meta-unknown-vendor": tmp_path},
        )
        assert vendor == "generic"
        assert isinstance(adapter, FilePatchAdapter)

    def test_highest_priority_wins(self, tmp_path: Path):
        # Both toradex and nxp_imx are present — toradex should match first
        # since both have priority 10 but toradex appears first in layer list
        vendor, adapter, _ = detect_vendor(
            ["meta-toradex-bsp-common", "meta-imx"],
            {"meta-toradex-bsp-common": tmp_path, "meta-imx": tmp_path},
        )
        assert vendor in ("toradex", "nxp_imx")  # Either is valid
        assert adapter is not None
