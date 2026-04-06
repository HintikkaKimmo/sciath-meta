"""Tests for vulns.git database parser and loader."""

import json
from pathlib import Path

from discovery.bsp._vulns_db import (
    VulnEntry,
    ingest_vulns_git,
    load_vulns_db,
    save_vulns_db,
)


class TestVulnEntry:
    def test_single_commit_true(self):
        entry = VulnEntry(cve_id="CVE-2024-1234", fixing_commits=["abc123"])
        assert entry.single_commit is True

    def test_single_commit_false(self):
        entry = VulnEntry(cve_id="CVE-2024-1234", fixing_commits=["abc", "def"])
        assert entry.single_commit is False

    def test_single_commit_empty(self):
        entry = VulnEntry(cve_id="CVE-2024-1234", fixing_commits=[])
        assert entry.single_commit is False


def _make_cve_json(cve_id: str, git_commits: list[str] | None = None,
                   semver_fixes: dict[str, str] | None = None) -> str:
    """Create a CVE JSON 5.0 file for testing."""
    affected_blocks = []

    # Git commit block
    if git_commits:
        versions = []
        for commit in git_commits:
            versions.append({
                "version": "0" * 40,
                "lessThan": commit,
                "status": "affected",
                "versionType": "git",
            })
        affected_blocks.append({"product": "Linux", "vendor": "Linux", "versions": versions})

    # Semver block
    if semver_fixes:
        versions = []
        for branch_ver in semver_fixes.values():
            versions.append({
                "version": branch_ver,
                "lessThanOrEqual": f"{'.'.join(branch_ver.split('.')[:2])}.*",
                "status": "unaffected",
                "versionType": "semver",
            })
        affected_blocks.append({"product": "Linux", "vendor": "Linux", "versions": versions})

    data = {"containers": {"cna": {"affected": affected_blocks}}}
    return json.dumps(data)


class TestIngestVulnsGit:
    def test_parse_cve_json(self, tmp_path: Path):
        pub = tmp_path / "cve" / "published" / "2024"
        pub.mkdir(parents=True)
        (pub / "CVE-2024-1234.json").write_text(
            _make_cve_json(
                "CVE-2024-1234",
                git_commits=["abc123def456789012345678901234567890abcd"],
                semver_fixes={"6.1": "6.1.75"},
            )
        )
        result = ingest_vulns_git(tmp_path)
        assert "CVE-2024-1234" in result
        assert result["CVE-2024-1234"].fixing_commits == [
            "abc123def456789012345678901234567890abcd"
        ]
        assert result["CVE-2024-1234"].fixed_in_versions == {"6.1": "6.1.75"}

    def test_parse_multiple_commits(self, tmp_path: Path):
        pub = tmp_path / "cve" / "published"
        pub.mkdir(parents=True)
        (pub / "CVE-2024-5678.json").write_text(
            _make_cve_json(
                "CVE-2024-5678",
                git_commits=[
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ],
            )
        )
        result = ingest_vulns_git(tmp_path)
        assert len(result["CVE-2024-5678"].fixing_commits) == 2

    def test_parse_semver_only(self, tmp_path: Path):
        pub = tmp_path / "cve" / "published"
        pub.mkdir(parents=True)
        (pub / "CVE-2024-7777.json").write_text(
            _make_cve_json("CVE-2024-7777", semver_fixes={"6.1": "6.1.80", "6.6": "6.6.20"})
        )
        result = ingest_vulns_git(tmp_path)
        assert result["CVE-2024-7777"].fixed_in_versions == {"6.1": "6.1.80", "6.6": "6.6.20"}

    def test_handle_malformed_file(self, tmp_path: Path):
        pub = tmp_path / "cve" / "published"
        pub.mkdir(parents=True)
        (pub / "garbage.json").write_text("not json{{{")
        result = ingest_vulns_git(tmp_path)
        assert len(result) == 0

    def test_handle_empty_dir(self, tmp_path: Path):
        pub = tmp_path / "cve" / "published"
        pub.mkdir(parents=True)
        result = ingest_vulns_git(tmp_path)
        assert result == {}

    def test_missing_published_dir(self, tmp_path: Path):
        result = ingest_vulns_git(tmp_path)
        assert result == {}

    def test_skips_schema_files(self, tmp_path: Path):
        pub = tmp_path / "cve" / "published"
        pub.mkdir(parents=True)
        (pub / "CVE_JSON_5.0_schema.json").write_text("{}")
        result = ingest_vulns_git(tmp_path)
        assert len(result) == 0

    def test_cve_in_year_subdirectory(self, tmp_path: Path):
        subdir = tmp_path / "cve" / "published" / "2024"
        subdir.mkdir(parents=True)
        (subdir / "CVE-2024-1111.json").write_text(
            _make_cve_json("CVE-2024-1111", semver_fixes={"6.1": "6.1.90"})
        )
        result = ingest_vulns_git(tmp_path)
        assert "CVE-2024-1111" in result


class TestSaveLoadRoundtrip:
    def test_roundtrip(self, tmp_path: Path):
        entries = {
            "CVE-2024-1234": VulnEntry(
                cve_id="CVE-2024-1234",
                fixing_commits=["abc123"],
                fixed_in_versions={"6.1": "6.1.75", "6.6": "6.6.15"},
            ),
        }
        output = tmp_path / "vulns_db.json"
        save_vulns_db(entries, output, vulns_commit="test123")

        loaded = load_vulns_db(output)
        assert loaded is not None
        assert "CVE-2024-1234" in loaded
        # fixing_commits are stripped in compact save format
        assert loaded["CVE-2024-1234"].fixing_commits == []
        assert loaded["CVE-2024-1234"].fixed_in_versions == {"6.1": "6.1.75", "6.6": "6.6.15"}

    def test_load_nonexistent(self, tmp_path: Path):
        result = load_vulns_db(tmp_path / "does_not_exist.json")
        assert result is None

    def test_load_corrupt_json(self, tmp_path: Path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json{{{")
        result = load_vulns_db(bad_file)
        assert result is None

    def test_save_creates_parent_dirs(self, tmp_path: Path):
        output = tmp_path / "deep" / "nested" / "vulns_db.json"
        save_vulns_db({}, output)
        assert output.exists()

    def test_load_schema(self, tmp_path: Path):
        data = {
            "schema_version": "1.0",
            "generated": "2026-04-06T00:00:00+00:00",
            "vulns_commit": "abc",
            "entry_count": 1,
            "entries": {
                "CVE-2024-1234": {
                    "cve_id": "CVE-2024-1234",
                    "fixing_commits": ["abc"],
                    "fixed_in_versions": {"6.1": "6.1.75"},
                },
            },
        }
        db_file = tmp_path / "test.json"
        db_file.write_text(json.dumps(data))
        loaded = load_vulns_db(db_file)
        assert loaded is not None
        assert loaded["CVE-2024-1234"].fixed_in_versions["6.1"] == "6.1.75"
