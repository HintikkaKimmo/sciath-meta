"""Tests for Yocto layer scanning utilities."""

from pathlib import Path

from discovery.bsp._layer_scanner import (
    find_bsp_layers,
    find_same_layer_bbappends,
    get_layer_name,
    is_bsp_layer,
    parse_bblayers,
)


class TestParseBblayers:
    def test_standard_bblayers(self, tmp_path: Path):
        build = tmp_path / "build"
        (build / "conf").mkdir(parents=True)
        layer1 = tmp_path / "layers" / "meta-poky"
        layer2 = tmp_path / "layers" / "meta-bsp"
        layer1.mkdir(parents=True)
        layer2.mkdir(parents=True)
        (build / "conf" / "bblayers.conf").write_text(
            f'BBLAYERS = "{layer1} {layer2}"\n'
        )
        result = parse_bblayers(build)
        assert len(result) == 2
        assert layer1.resolve() in result
        assert layer2.resolve() in result

    def test_topdir_substitution(self, tmp_path: Path):
        build = tmp_path / "build"
        (build / "conf").mkdir(parents=True)
        layer = build / "layers" / "meta-poky"
        layer.mkdir(parents=True)
        (build / "conf" / "bblayers.conf").write_text(
            'BBLAYERS = "${TOPDIR}/layers/meta-poky"\n'
        )
        result = parse_bblayers(build)
        assert len(result) == 1
        assert layer.resolve() in result

    def test_missing_bblayers_conf(self, tmp_path: Path):
        build = tmp_path / "build"
        build.mkdir()
        result = parse_bblayers(build)
        assert result == []

    def test_relative_paths(self, tmp_path: Path):
        build = tmp_path / "build"
        (build / "conf").mkdir(parents=True)
        layer = build / "relative-layer"
        layer.mkdir()
        (build / "conf" / "bblayers.conf").write_text(
            'BBLAYERS = "relative-layer"\n'
        )
        result = parse_bblayers(build)
        assert len(result) == 1

    def test_nonexistent_layer_skipped(self, tmp_path: Path):
        build = tmp_path / "build"
        (build / "conf").mkdir(parents=True)
        (build / "conf" / "bblayers.conf").write_text(
            'BBLAYERS = "/nonexistent/layer"\n'
        )
        result = parse_bblayers(build)
        assert result == []

    def test_multiline_bblayers(self, tmp_path: Path):
        build = tmp_path / "build"
        (build / "conf").mkdir(parents=True)
        layer1 = tmp_path / "layers" / "meta-poky"
        layer2 = tmp_path / "layers" / "meta-bsp"
        layer1.mkdir(parents=True)
        layer2.mkdir(parents=True)
        (build / "conf" / "bblayers.conf").write_text(
            f'BBLAYERS = " \\\n  {layer1} \\\n  {layer2} \\\n"\n'
        )
        result = parse_bblayers(build)
        assert len(result) == 2


class TestGetLayerName:
    def test_normal_layer_conf(self, tmp_path: Path):
        layer = tmp_path / "meta-test"
        (layer / "conf").mkdir(parents=True)
        (layer / "conf" / "layer.conf").write_text(
            'BBFILE_COLLECTIONS = "test-layer"\n'
        )
        assert get_layer_name(layer) == "test-layer"

    def test_missing_layer_conf(self, tmp_path: Path):
        layer = tmp_path / "meta-nolayerconf"
        layer.mkdir()
        assert get_layer_name(layer) == "meta-nolayerconf"

    def test_malformed_layer_conf(self, tmp_path: Path):
        layer = tmp_path / "meta-bad"
        (layer / "conf").mkdir(parents=True)
        (layer / "conf" / "layer.conf").write_text("# No BBFILE_COLLECTIONS\n")
        assert get_layer_name(layer) == "meta-bad"


class TestFindSameLayerBbappends:
    def test_matching_bbappend(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        bbappend = recipe_dir / "linux-bsp_%.bbappend"
        bbappend.write_text('SRC_URI += "file://extra.patch"\n')
        result = find_same_layer_bbappends("linux-bsp", layer)
        assert len(result) == 1
        assert result[0] == bbappend

    def test_no_matching_bbappend(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        bbappend = recipe_dir / "other-recipe_%.bbappend"
        bbappend.write_text("")
        result = find_same_layer_bbappends("linux-bsp", layer)
        assert result == []

    def test_exact_version_match(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        bbappend = recipe_dir / "linux-bsp_6.1.21.bbappend"
        bbappend.write_text("")
        result = find_same_layer_bbappends("linux-bsp", layer)
        assert len(result) == 1


class TestIsBspLayer:
    def test_with_machine_conf(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        (layer / "conf" / "machine").mkdir(parents=True)
        (layer / "conf" / "machine" / "testboard.conf").write_text("")
        assert is_bsp_layer(layer) is True

    def test_without_machine_conf(self, tmp_path: Path):
        layer = tmp_path / "meta-oe"
        (layer / "conf").mkdir(parents=True)
        (layer / "conf" / "layer.conf").write_text("")
        assert is_bsp_layer(layer) is False

    def test_empty_machine_dir(self, tmp_path: Path):
        layer = tmp_path / "meta-bsp"
        (layer / "conf" / "machine").mkdir(parents=True)
        assert is_bsp_layer(layer) is False


class TestFindBspLayers:
    def test_finds_bsp_layer(self, tmp_path: Path):
        build = tmp_path / "build"
        (build / "conf").mkdir(parents=True)
        bsp_layer = tmp_path / "layers" / "meta-bsp"
        oe_layer = tmp_path / "layers" / "meta-oe"
        bsp_layer.mkdir(parents=True)
        oe_layer.mkdir(parents=True)
        (bsp_layer / "conf" / "machine").mkdir(parents=True)
        (bsp_layer / "conf" / "machine" / "board.conf").write_text("")
        (bsp_layer / "conf" / "layer.conf").write_text('BBFILE_COLLECTIONS = "bsp"\n')
        (oe_layer / "conf").mkdir(parents=True)
        (oe_layer / "conf" / "layer.conf").write_text('BBFILE_COLLECTIONS = "openembedded"\n')
        (build / "conf" / "bblayers.conf").write_text(
            f'BBLAYERS = "{bsp_layer} {oe_layer}"\n'
        )
        result = find_bsp_layers(build)
        assert len(result) == 1
        assert result[0][0] == "bsp"
