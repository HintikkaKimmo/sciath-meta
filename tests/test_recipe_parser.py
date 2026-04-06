"""Tests for static Yocto recipe parser."""

from pathlib import Path

from discovery.bsp._recipe_parser import (
    find_kernel_recipe,
    gather_all_src_uris,
    has_cve_tag,
    parse_src_uri,
    parse_srcrev,
    parse_variable,
)


class TestParseSrcUri:
    def test_single_line(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text('SRC_URI = "git://example.com/linux.git file://fix.patch"\n')
        uris = parse_src_uri(recipe)
        assert "git://example.com/linux.git" in uris
        assert "file://fix.patch" in uris

    def test_multiline_continuation(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git \\\n'
            '           file://fix1.patch \\\n'
            '           file://fix2.patch"\n'
        )
        uris = parse_src_uri(recipe)
        assert len(uris) == 3
        assert "file://fix1.patch" in uris
        assert "file://fix2.patch" in uris

    def test_append_colon_syntax(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git"\n'
            'SRC_URI:append = " file://extra.patch"\n'
        )
        uris = parse_src_uri(recipe)
        assert "file://extra.patch" in uris

    def test_append_underscore_syntax(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git"\n'
            'SRC_URI_append = " file://extra.patch"\n'
        )
        uris = parse_src_uri(recipe)
        assert "file://extra.patch" in uris

    def test_plus_equals(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git"\n'
            'SRC_URI += "file://extra.patch"\n'
        )
        uris = parse_src_uri(recipe)
        assert "file://extra.patch" in uris

    def test_dot_equals(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git"\n'
            'SRC_URI .= " file://extra.patch"\n'
        )
        uris = parse_src_uri(recipe)
        assert "file://extra.patch" in uris

    def test_ignores_comments(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            '# SRC_URI = "git://should-be-ignored.git"\n'
            'SRC_URI = "git://real.git"\n'
        )
        uris = parse_src_uri(recipe)
        assert len(uris) == 1
        assert "git://real.git" in uris

    def test_empty_recipe(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text("# No SRC_URI here\nDESCRIPTION = \"test\"\n")
        uris = parse_src_uri(recipe)
        assert uris == []

    def test_machine_conditional_append(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git"\n'
            'SRC_URI:append:raspberrypi4-64 = " file://rpi4-fix.patch"\n'
            'SRC_URI:append:raspberrypi3 = " file://rpi3-fix.patch"\n'
        )
        uris = parse_src_uri(recipe, machine="raspberrypi4-64")
        assert "file://rpi4-fix.patch" in uris
        assert "file://rpi3-fix.patch" not in uris

    def test_machine_conditional_without_machine(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRC_URI = "git://example.com/linux.git"\n'
            'SRC_URI:append:raspberrypi4-64 = " file://rpi4-fix.patch"\n'
        )
        uris = parse_src_uri(recipe)
        # Without machine, conditional appends are not parsed
        assert "file://rpi4-fix.patch" not in uris

    def test_inline_python_warning(self, tmp_path: Path, caplog):
        recipe = tmp_path / "test.bb"
        recipe.write_text('SRC_URI = "${@bb.utils.contains(\'FOO\', \'bar\', \'file://x.patch\', \'\', d)}"\n')
        parse_src_uri(recipe)
        # Should still return the raw value but log a warning
        assert any("Inline Python" in r.message for r in caplog.records)

    def test_unexpanded_variable_warning(self, tmp_path: Path, caplog):
        recipe = tmp_path / "test.bb"
        recipe.write_text('SRC_URI = "git://example.com/${BPN}.git"\n')
        uris = parse_src_uri(recipe)
        assert any("Unexpanded variable" in r.message for r in caplog.records)
        # Should still capture the URI as-is
        assert "git://example.com/${BPN}.git" in uris

    def test_nonexistent_file(self, tmp_path: Path):
        recipe = tmp_path / "nonexistent.bb"
        uris = parse_src_uri(recipe)
        assert uris == []


class TestParseSrcrev:
    def test_standard_srcrev(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text('SRCREV = "abc123def456"\n')
        assert parse_srcrev(recipe) == "abc123def456"

    def test_per_recipe_override(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text(
            'SRCREV = "default123"\n'
            'SRCREV_pn-linux-toradex = "vendor456"\n'
        )
        # Per-recipe override takes precedence
        assert parse_srcrev(recipe) == "vendor456"

    def test_autorev(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text('SRCREV = "${AUTOREV}"\n')
        assert parse_srcrev(recipe) == "${AUTOREV}"

    def test_no_srcrev(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text('DESCRIPTION = "No SRCREV here"\n')
        assert parse_srcrev(recipe) == ""


class TestParseVariable:
    def test_simple_variable(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text('PV = "5.15.0"\n')
        assert parse_variable(recipe, "PV") == "5.15.0"

    def test_weak_assignment(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text('MACHINE ?= "raspberrypi4-64"\n')
        assert parse_variable(recipe, "MACHINE") == "raspberrypi4-64"

    def test_missing_variable(self, tmp_path: Path):
        recipe = tmp_path / "test.bb"
        recipe.write_text('OTHER = "value"\n')
        assert parse_variable(recipe, "MISSING") == ""


class TestFindKernelRecipe:
    def test_single_recipe(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        (layer / "recipes-kernel" / "linux").mkdir(parents=True)
        recipe = layer / "recipes-kernel" / "linux" / "linux-bsp_6.1.bb"
        recipe.write_text('DESCRIPTION = "BSP kernel"\n')
        assert find_kernel_recipe(layer) == recipe

    def test_linux_star_subdirectory(self, tmp_path: Path):
        layer = tmp_path / "meta-rpi"
        (layer / "recipes-kernel" / "linux-raspberrypi").mkdir(parents=True)
        recipe = layer / "recipes-kernel" / "linux-raspberrypi" / "linux-raspberrypi_6.1.bb"
        recipe.write_text("")
        assert find_kernel_recipe(layer) == recipe

    def test_multiple_filter_by_pattern(self, tmp_path: Path):
        layer = tmp_path / "meta-phytec"
        (layer / "recipes-kernel" / "linux-phytec-ti").mkdir(parents=True)
        (layer / "recipes-kernel" / "linux-phytec-imx").mkdir(parents=True)
        ti = layer / "recipes-kernel" / "linux-phytec-ti" / "linux-phytec-ti_5.10.bb"
        imx = layer / "recipes-kernel" / "linux-phytec-imx" / "linux-phytec-imx_5.15.bb"
        ti.write_text("")
        imx.write_text("")
        result = find_kernel_recipe(layer, kernel_recipe_patterns=["linux-phytec-ti"])
        assert result == ti

    def test_none_found(self, tmp_path: Path):
        layer = tmp_path / "meta-empty"
        layer.mkdir()
        assert find_kernel_recipe(layer) is None

    def test_no_recipes_kernel_dir(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        (layer / "conf").mkdir(parents=True)
        assert find_kernel_recipe(layer) is None


class TestGatherAllSrcUris:
    def test_base_only(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-bsp_6.1.bb"
        recipe.write_text('SRC_URI = "git://example.com/linux.git file://fix.patch"\n')
        uris = gather_all_src_uris(recipe, layer)
        assert len(uris) == 2

    def test_base_plus_bbappend(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-bsp_6.1.bb"
        recipe.write_text('SRC_URI = "git://example.com/linux.git"\n')
        # Same-layer bbappend
        bbappend = recipe_dir / "linux-bsp_%.bbappend"
        bbappend.write_text('SRC_URI += "file://extra.patch"\n')
        uris = gather_all_src_uris(recipe, layer)
        assert "git://example.com/linux.git" in uris
        assert "file://extra.patch" in uris

    def test_wildcard_bbappend(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        recipe = recipe_dir / "linux-bsp_6.1.bb"
        recipe.write_text('SRC_URI = "git://example.com/linux.git"\n')
        bbappend = recipe_dir / "linux-bsp_%.bbappend"
        bbappend.write_text('SRC_URI += "file://wildcard.patch"\n')
        uris = gather_all_src_uris(recipe, layer)
        assert "file://wildcard.patch" in uris


class TestHasCveTag:
    def test_cve_in_filename(self, tmp_path: Path):
        patch = tmp_path / "CVE-2024-1234.patch"
        patch.write_text("diff content\n")
        assert has_cve_tag(patch) is True

    def test_cve_in_header(self, tmp_path: Path):
        patch = tmp_path / "fix-usb.patch"
        patch.write_text("Subject: Fix CVE-2024-5678 in USB driver\n\ndiff content\n")
        assert has_cve_tag(patch) is True

    def test_no_cve_tag(self, tmp_path: Path):
        patch = tmp_path / "fix-usb.patch"
        patch.write_text("Subject: Fix USB regression\n\ndiff content\n")
        assert has_cve_tag(patch) is False
