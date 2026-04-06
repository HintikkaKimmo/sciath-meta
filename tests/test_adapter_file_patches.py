"""Tests for FilePatchAdapter."""

from pathlib import Path

from discovery.bsp._types import PatchSourceType
from discovery.bsp.adapters.file_patches import FilePatchAdapter


def _make_rpi_layer(tmp_path: Path) -> tuple[Path, Path]:
    """Create a minimal RPi-like BSP layer with file patches."""
    layer = tmp_path / "meta-raspberrypi"
    recipe_dir = layer / "recipes-kernel" / "linux-raspberrypi"
    recipe_dir.mkdir(parents=True)

    # Kernel recipe with file:// patches
    recipe = recipe_dir / "linux-raspberrypi_6.1.bb"
    recipe.write_text(
        'SRC_URI = "git://github.com/raspberrypi/linux.git;branch=rpi-6.1.y \\\n'
        '           file://0001-fix-usb.patch \\\n'
        '           file://CVE-2024-1234.patch \\\n'
        '           file://rpi-config.cfg"\n'
        'SRCREV = "abc123"\n'
    )

    # Patch files in recipe-named subdirectory
    patch_dir = recipe_dir / "linux-raspberrypi"
    patch_dir.mkdir()
    (patch_dir / "0001-fix-usb.patch").write_text("diff --git a/foo b/foo\n")
    (patch_dir / "CVE-2024-1234.patch").write_text(
        "Subject: Fix CVE-2024-1234\n\ndiff --git a/bar b/bar\n"
    )
    (patch_dir / "rpi-config.cfg").write_text("CONFIG_USB=y\n")

    return layer, recipe


class TestFilePatchAdapter:
    def test_correct_patch_count(self, tmp_path: Path):
        layer, recipe = _make_rpi_layer(tmp_path)
        adapter = FilePatchAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        # Only .patch and .diff files, not .cfg
        assert len(result.patches) == 2

    def test_source_type_and_path(self, tmp_path: Path):
        layer, recipe = _make_rpi_layer(tmp_path)
        adapter = FilePatchAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        for patch in result.patches:
            assert patch.source_type == PatchSourceType.FILE
            assert patch.path is not None
            assert patch.path.exists()
            assert patch.layer == "meta-raspberrypi"

    def test_cve_tag_confidence(self, tmp_path: Path):
        layer, recipe = _make_rpi_layer(tmp_path)
        adapter = FilePatchAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        by_name = {p.name: p for p in result.patches}
        assert by_name["CVE-2024-1234.patch"].confidence == "high"
        assert by_name["0001-fix-usb.patch"].confidence == "medium"

    def test_path_safety_rejects_outside_layer(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)

        # Create patch outside layer
        outside = tmp_path / "evil.patch"
        outside.write_text("evil content\n")

        # Create a symlink inside layer pointing outside
        patch_dir = recipe_dir / "linux"
        patch_dir.mkdir()
        link = patch_dir / "evil.patch"
        link.symlink_to(outside)

        recipe = recipe_dir / "linux_6.1.bb"
        recipe.write_text('SRC_URI = "file://evil.patch"\n')

        adapter = FilePatchAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        assert len(result.patches) == 0
        assert any("outside layer" in w for w in result.warnings)

    def test_missing_patch_file_warning(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux_6.1.bb"
        recipe.write_text('SRC_URI = "file://nonexistent.patch"\n')

        adapter = FilePatchAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        assert len(result.patches) == 0
        assert any("not found" in w for w in result.warnings)

    def test_files_subdirectory_resolution(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux_6.1.bb"
        recipe.write_text('SRC_URI = "file://fix.patch"\n')
        # Patch in files/ subdirectory
        files_dir = recipe_dir / "files"
        files_dir.mkdir()
        (files_dir / "fix.patch").write_text("diff content\n")

        adapter = FilePatchAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        assert len(result.patches) == 1
        assert result.patches[0].path is not None
