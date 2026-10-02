# -*- mode: python ; coding: utf-8 -*-
# PyInstaller specification for gen_pass.
#
# ONEFILE, deliberately. The user asked for a single .exe to download and run, and
# an onedir build silently breaks the moment the .exe is copied out of its folder:
# PyInstaller's bootloader looks for python3xx.dll and the rest beside itself, fails,
# and shows a window titled "Error". Shipping the exe alone is the natural thing to
# do with an onedir build, which is exactly how that bug appeared here.
#
# The cost of onefile is a slower first launch, since the archive is unpacked to a
# temp directory. For a program someone installs once, that is the right trade.
#
# Kept in the repository rather than generated, so a build is reproducible.

import sys
from pathlib import Path

PROJECT_DIR = Path(SPECPATH)
ICON = PROJECT_DIR / "build_assets" / "icon.ico"
VERSION_FILE = PROJECT_DIR / "build_assets" / "version_info.txt"

block_cipher = None

analysis = Analysis(
    ["main.py"],
    pathex=[str(PROJECT_DIR)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # The project imports nothing beyond the standard library. flask and
    # cryptography are named explicitly so a regression cannot slip in quietly.
    excludes=[
        "flask",
        "cryptography",
        "numpy",
        "pandas",
        "PyQt5",
        "PyQt6",
        "pytest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=block_cipher)

# ONEFILE: binaries, zipfiles and datas go INTO the exe. No COLLECT step.
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.zipfiles,
    analysis.datas,
    [],
    name="Генератор паролей",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI program: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON) if ICON.exists() else None,
    version=str(VERSION_FILE) if VERSION_FILE.exists() else None,
)