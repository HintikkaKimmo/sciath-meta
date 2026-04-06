"""End-to-end BSP integration tests."""

from pathlib import Path
from unittest.mock import patch

from discovery.bsp import extract_bsp_patches
from discovery.bsp.adapters import clear_caches
from discovery.yocto import YoctoDiscovery


def _make_full_build_tree(tmp_path: Path) -> Path:
    """Create a complete Yocto build tree with BSP layer."""
    build = tmp_path / "build"
    (build / "conf").mkdir(parents=True)
    (build / "tmp" / "deploy" / "spdx").mkdir(parents=True)
    (build / "tmp" / "deploy" / "images" / "raspberrypi4-64").mkdir(parents=True)

    # local.conf
    (build / "conf" / "local.conf").write_text(
        'MACHINE = "raspberrypi4-64"\n'
        'DISTRO = "poky"\n'
    )

    # BSP layer
    bsp_layer = tmp_path / "layers" / "meta-raspberrypi"
    recipe_dir = bsp_layer / "recipes-kernel" / "linux-raspberrypi"
    recipe_dir.mkdir(parents=True)
    (bsp_layer / "conf" / "machine").mkdir(parents=True)
    (bsp_layer / "conf" / "machine" / "raspberrypi4-64.conf").write_text("")
    (bsp_layer / "conf" / "layer.conf").write_text(
        'BBFILE_COLLECTIONS = "meta-raspberrypi"\n'
    )

    recipe = recipe_dir / "linux-raspberrypi_6.1.bb"
    recipe.write_text(
        'SRC_URI = "git://github.com/raspberrypi/linux.git;branch=rpi-6.1.y \\\n'
        '           file://0001-rpi-fix.patch"\n'
        'SRCREV = "rpi123"\n'
    )
    patch_dir = recipe_dir / "linux-raspberrypi"
    patch_dir.mkdir()
    (patch_dir / "0001-rpi-fix.patch").write_text("diff content\n")

    # Poky layer (non-BSP)
    poky_layer = tmp_path / "layers" / "meta-poky"
    (poky_layer / "conf").mkdir(parents=True)
    (poky_layer / "conf" / "layer.conf").write_text(
        'BBFILE_COLLECTIONS = "meta-poky"\n'
    )

    # bblayers.conf
    (build / "conf" / "bblayers.conf").write_text(
        f'BBLAYERS = "{poky_layer} {bsp_layer}"\n'
    )

    # SBOM placeholder
    (build / "tmp" / "deploy" / "spdx" / "test.spdx.json").write_text('{"spdxVersion": "SPDX-2.3"}')

    return build


class TestBspIntegration:
    def setup_method(self):
        clear_caches()

    def test_extract_bsp_patches_end_to_end(self, tmp_path: Path):
        build = _make_full_build_tree(tmp_path)
        result = extract_bsp_patches(build, machine="raspberrypi4-64")
        assert result is not None
        assert result.vendor == "raspberrypi"
        assert result.patch_count >= 1
        assert result.file_patch_count >= 1

    def test_no_bsp_layer_returns_none(self, tmp_path: Path):
        build = tmp_path / "build"
        (build / "conf").mkdir(parents=True)
        (build / "conf" / "bblayers.conf").write_text('BBLAYERS = ""\n')
        result = extract_bsp_patches(build)
        assert result is None

    def test_exception_returns_none(self, tmp_path: Path):
        # Pass a nonexistent directory — should not raise
        result = extract_bsp_patches(tmp_path / "nonexistent")
        assert result is None

    @patch("discovery.yocto.subprocess.run")
    def test_yocto_collect_populates_bsp_profile(self, mock_run, tmp_path: Path):
        mock_run.return_value.returncode = 1  # bitbake fails, that's OK
        mock_run.return_value.stdout = ""

        build = _make_full_build_tree(tmp_path)
        discovery = YoctoDiscovery()
        bundle = discovery.collect(build)

        assert bundle.bsp_profile is not None
        assert bundle.bsp_profile.vendor == "raspberrypi"
        assert bundle.bsp_profile.patch_count >= 1

    @patch("discovery.yocto.subprocess.run")
    def test_artifact_count_includes_bsp(self, mock_run, tmp_path: Path):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""

        build = _make_full_build_tree(tmp_path)
        discovery = YoctoDiscovery()
        bundle = discovery.collect(build)

        # BSP profile should contribute to artifact count
        assert bundle.bsp_profile is not None
        assert bundle.artifact_count >= 1

    @patch("discovery.yocto.subprocess.run")
    def test_summary_includes_bsp_patches(self, mock_run, tmp_path: Path):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""

        build = _make_full_build_tree(tmp_path)
        discovery = YoctoDiscovery()
        bundle = discovery.collect(build)

        summary = bundle.summary()
        assert "BSP patches" in summary
