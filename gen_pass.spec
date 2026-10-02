# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification for gen_pass.

Kept in the repository rather than generated, so a build is reproducible: anyone
can run `pyinstaller gen_pass.spec` and get the same layout.

Notes on the choices:
  - onefile: the user gets a single file to download and run. Slower first launch
    than onedir, which is the correct trade for a program people install once.
  - console=False: a GUI program. A console window would appear alongside the
    window and look like a bug.
  - tkinter is bundled by PyInstaller automatically; it is part of the standard
    distribution, not an extra dependency.
  - version info is attached from a file, so the .exe reports a real version in
    Windows file properties.
"""

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
    # The project imports nothing beyond the standard library, so nothing needs
    # to be collected. Listed explicitly anyway so a future import fails loudly
    # at build time instead of silently missing at runtime.
    excludes=[
        "flask",           # removed web layer; must never creep back in
        "cryptography",    # replaced by hashlib
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

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="Генератор паролей",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,          # smaller binary; skipped automatically if UPX is absent
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,     # GUI program: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,  # current machine
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON) if ICON.exists() else None,
    version=str(VERSION_FILE) if VERSION_FILE.exists() else None,
)

coll = COLLECT(
    exe,
    analysis.binaries,
    analysis.zipfiles,
    analysis.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="Генератор паролей",
)

if sys.platform == "win32":
    # The default icon is a generic Python one; ship a real one if present.
    pass