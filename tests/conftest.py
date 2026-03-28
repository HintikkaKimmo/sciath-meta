"""Shared fixtures for Sciath-meta tests."""

from pathlib import Path

import pytest


@pytest.fixture
def tmp_build_dir(tmp_path: Path) -> Path:
    """Bare temporary directory for build tree fixtures."""
    return tmp_path


@pytest.fixture
def yocto_build_dir(tmp_path: Path) -> Path:
    """Minimal Yocto build tree fixture."""
    # conf/local.conf
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "local.conf").write_text(
        'MACHINE = "raspberrypi4-64"\n'
        'DISTRO = "poky"\n'
    )

    # tmp/ directory tree
    tmp = tmp_path / "tmp"
    tmp.mkdir()

    # deploy/spdx — SBOM
    spdx_dir = tmp / "deploy" / "spdx"
    spdx_dir.mkdir(parents=True)
    (spdx_dir / "image-raspberrypi4-64.spdx.json").write_text('{"spdxVersion": "SPDX-2.3"}')

    # deploy/images/<machine> — DTBs
    images_dir = tmp / "deploy" / "images" / "raspberrypi4-64"
    images_dir.mkdir(parents=True)
    (images_dir / "bcm2711-rpi-4-b.dtb").write_bytes(b"\x00")
    (images_dir / "bcm2711-rpi-cm4.dtb").write_bytes(b"\x00")

    # Kernel .config in staging
    kernel_dir = tmp / "sysroots-components" / "cortexa72" / "linux-raspberrypi"
    kernel_dir.mkdir(parents=True)
    (kernel_dir / ".config").write_text(
        "# Linux/aarch64 6.1.21 Kernel Configuration\n"
        "CONFIG_ARM64=y\n"
    )

    # Busybox .config in work dir
    bb_dir = tmp / "work" / "cortexa72" / "busybox" / "1.36.1" / "build"
    bb_dir.mkdir(parents=True)
    (bb_dir / ".config").write_text("CONFIG_BUSYBOX=y\n")

    return tmp_path


@pytest.fixture
def buildroot_build_dir(tmp_path: Path) -> Path:
    """Minimal Buildroot build tree fixture."""
    (tmp_path / ".config").write_text("BR2_arm=y\n")
    (tmp_path / "output" / "build").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def debian_build_dir(tmp_path: Path) -> Path:
    """Minimal Debian source tree fixture."""
    (tmp_path / "debian").mkdir()
    (tmp_path / "debian" / "control").write_text("Source: my-package\n")
    return tmp_path


@pytest.fixture
def openwrt_build_dir(tmp_path: Path) -> Path:
    """Minimal OpenWrt build tree fixture."""
    (tmp_path / "feeds.conf").write_text("src-git packages ...\n")
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "toplevel.mk").write_text("# top\n")
    return tmp_path
