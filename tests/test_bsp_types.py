"""Tests for BSP discovery data types."""

from pathlib import Path

from discovery.bsp._types import BSPProfile, PatchInfo, PatchSourceType


class TestPatchSourceType:
    def test_enum_values(self):
        assert PatchSourceType.FILE.value == "file"
        assert PatchSourceType.GIT_FORK.value == "git_fork"
        assert PatchSourceType.UNKNOWN.value == "unknown"


class TestPatchInfo:
    def test_frozen_immutability(self):
        p = PatchInfo(name="test.patch", source_type=PatchSourceType.FILE)
        try:
            p.name = "other"  # type: ignore[misc]
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_defaults(self):
        p = PatchInfo(name="test.patch", source_type=PatchSourceType.FILE)
        assert p.path is None
        assert p.git_url == ""
        assert p.commit_hash == ""
        assert p.recipe == ""
        assert p.layer == ""
        assert p.confidence == "high"

    def test_file_patch(self, tmp_path: Path):
        patch = tmp_path / "fix.patch"
        patch.write_text("diff --git a/foo b/foo\n")
        p = PatchInfo(
            name="fix.patch",
            source_type=PatchSourceType.FILE,
            path=patch,
            recipe="linux-rpi",
            layer="meta-raspberrypi",
            confidence="medium",
        )
        assert p.path == patch
        assert p.confidence == "medium"

    def test_git_fork_patch(self):
        p = PatchInfo(
            name="kernel-fork:git.toradex.com/linux.git",
            source_type=PatchSourceType.GIT_FORK,
            git_url="git://git.toradex.com/linux.git",
            commit_hash="abc123",
            confidence="low",
        )
        assert p.git_url == "git://git.toradex.com/linux.git"
        assert p.commit_hash == "abc123"


class TestBSPProfile:
    def test_defaults(self):
        p = BSPProfile()
        assert p.vendor == ""
        assert p.patches == []
        assert p.warnings == []
        assert p.patch_count == 0
        assert p.file_patch_count == 0
        assert p.fork_patch_count == 0

    def test_patch_counts(self):
        p = BSPProfile(patches=[
            PatchInfo(name="a.patch", source_type=PatchSourceType.FILE),
            PatchInfo(name="b.patch", source_type=PatchSourceType.FILE),
            PatchInfo(name="fork", source_type=PatchSourceType.GIT_FORK),
        ])
        assert p.patch_count == 3
        assert p.file_patch_count == 2
        assert p.fork_patch_count == 1

    def test_warnings_accumulation(self):
        p = BSPProfile()
        p.warnings.append("warning 1")
        p.warnings.append("warning 2")
        assert len(p.warnings) == 2
        assert "warning 1" in p.warnings

    def test_metadata(self):
        p = BSPProfile()
        p.metadata["upstream_base_hint"] = "5.15"
        assert p.metadata["upstream_base_hint"] == "5.15"
