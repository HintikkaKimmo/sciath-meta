"""Tests for HybridAdapter."""

from pathlib import Path

from discovery.bsp._types import PatchSourceType
from discovery.bsp.adapters.hybrid import HybridAdapter


class TestHybridAdapter:
    def test_runs_both_adapters(self, tmp_path: Path):
        layer = tmp_path / "meta-phytec"
        recipe_dir = layer / "recipes-kernel" / "linux-phytec"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-phytec_5.10.bb"
        recipe.write_text(
            'SRC_URI = "git://github.com/phytec/linux-phytec.git;branch=v5.10-phy \\\n'
            '           file://0001-dts-fix.patch"\n'
            'SRCREV = "phytec123"\n'
        )
        patch_dir = recipe_dir / "linux-phytec"
        patch_dir.mkdir()
        (patch_dir / "0001-dts-fix.patch").write_text("diff content\n")

        adapter = HybridAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)

        fork_patches = [p for p in result.patches if p.source_type == PatchSourceType.GIT_FORK]
        file_patches = [p for p in result.patches if p.source_type == PatchSourceType.FILE]
        assert len(fork_patches) == 1
        assert len(file_patches) == 1
        assert result.adapter_used == "hybrid"

    def test_deduplication(self, tmp_path: Path):
        layer = tmp_path / "meta-vendor"
        recipe_dir = layer / "recipes-kernel" / "linux-vendor"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-vendor_5.15.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git;branch=main \\\n'
            '           file://fix.patch"\n'
            'SRCREV = "abc"\n'
        )
        patch_dir = recipe_dir / "linux-vendor"
        patch_dir.mkdir()
        (patch_dir / "fix.patch").write_text("diff\n")

        adapter = HybridAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)

        # Check no duplicates (each patch name + source_type pair is unique)
        seen = set()
        for p in result.patches:
            key = (p.name, p.source_type.value)
            assert key not in seen, f"Duplicate patch: {key}"
            seen.add(key)

    def test_merged_warnings(self, tmp_path: Path):
        layer = tmp_path / "meta-vendor"
        recipe_dir = layer / "recipes-kernel" / "linux-vendor"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-vendor_5.15.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git;branch=main \\\n'
            '           file://missing.patch"\n'
            'SRCREV = "${AUTOREV}"\n'
        )

        adapter = HybridAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        # Should have warnings from both: AUTOREV + missing patch
        assert len(result.warnings) >= 2
