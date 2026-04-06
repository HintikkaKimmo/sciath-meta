"""Tests for ForkedKernelAdapter."""

from pathlib import Path

from discovery.bsp._types import PatchSourceType
from discovery.bsp.adapters.forked_kernel import ForkedKernelAdapter


def _make_toradex_layer(tmp_path: Path) -> tuple[Path, Path]:
    """Create a minimal Toradex-like BSP layer with git fork."""
    layer = tmp_path / "meta-toradex"
    recipe_dir = layer / "recipes-kernel" / "linux-toradex"
    recipe_dir.mkdir(parents=True)

    recipe = recipe_dir / "linux-toradex_5.15.bb"
    recipe.write_text(
        'SRC_URI = "git://git.toradex.com/linux-toradex.git;branch=toradex_5.15-2.2.x-imx;protocol=https"\n'
        'SRCREV = "deadbeef1234"\n'
        'PV = "5.15.71"\n'
    )

    return layer, recipe


class TestForkedKernelAdapter:
    def test_extracts_git_url_and_srcrev(self, tmp_path: Path):
        layer, recipe = _make_toradex_layer(tmp_path)
        adapter = ForkedKernelAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        fork_patches = [p for p in result.patches if p.source_type == PatchSourceType.GIT_FORK]
        assert len(fork_patches) == 1
        assert "git.toradex.com" in fork_patches[0].git_url
        assert fork_patches[0].commit_hash == "deadbeef1234"

    def test_source_type_git_fork(self, tmp_path: Path):
        layer, recipe = _make_toradex_layer(tmp_path)
        adapter = ForkedKernelAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        fork_patches = [p for p in result.patches if p.source_type == PatchSourceType.GIT_FORK]
        assert fork_patches[0].confidence == "low"

    def test_autorev_handling(self, tmp_path: Path):
        layer = tmp_path / "meta-vendor"
        recipe_dir = layer / "recipes-kernel" / "linux-vendor"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-vendor_6.1.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git;branch=main"\n'
            'SRCREV = "${AUTOREV}"\n'
        )
        adapter = ForkedKernelAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        assert any("AUTOREV" in w for w in result.warnings)
        fork_patches = [p for p in result.patches if p.source_type == PatchSourceType.GIT_FORK]
        assert fork_patches[0].commit_hash == "${AUTOREV}"

    def test_file_patches_alongside_fork(self, tmp_path: Path):
        layer = tmp_path / "meta-vendor"
        recipe_dir = layer / "recipes-kernel" / "linux-vendor"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-vendor_5.15.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git;branch=main \\\n'
            '           file://0001-extra-fix.patch"\n'
            'SRCREV = "abc123"\n'
        )
        patch_dir = recipe_dir / "linux-vendor"
        patch_dir.mkdir()
        (patch_dir / "0001-extra-fix.patch").write_text("diff content\n")

        adapter = ForkedKernelAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        fork_patches = [p for p in result.patches if p.source_type == PatchSourceType.GIT_FORK]
        file_patches = [p for p in result.patches if p.source_type == PatchSourceType.FILE]
        assert len(fork_patches) == 1
        assert len(file_patches) == 1

    def test_extracts_branch_metadata(self, tmp_path: Path):
        layer, recipe = _make_toradex_layer(tmp_path)
        adapter = ForkedKernelAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        assert result.metadata.get("kernel_branch") == "toradex_5.15-2.2.x-imx"

    def test_extracts_upstream_base_hint(self, tmp_path: Path):
        layer, recipe = _make_toradex_layer(tmp_path)
        adapter = ForkedKernelAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        assert result.metadata.get("upstream_base_hint") == "5.15.71"

    def test_multiple_git_sources_only_first(self, tmp_path: Path):
        layer = tmp_path / "meta-vendor"
        recipe_dir = layer / "recipes-kernel" / "linux-vendor"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-vendor_5.15.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git;branch=main;name=kernel \\\n'
            '           git://example.com/firmware.git;destsuffix=firmware;name=firmware"\n'
            'SRCREV = "kernel123"\n'
        )
        adapter = ForkedKernelAdapter()
        result = adapter.extract_patches(layer, recipe, tmp_path)
        fork_patches = [p for p in result.patches if p.source_type == PatchSourceType.GIT_FORK]
        # Only the first git source (kernel) is recorded
        assert len(fork_patches) == 1
        assert "linux.git" in fork_patches[0].git_url
