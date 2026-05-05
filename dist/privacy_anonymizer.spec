# PyInstaller spec — AI Privacy Anonymizer CLI
#
# Build: pyinstaller packaging/privacy_anonymizer.spec
# Output: dist/privacy-anonymizer.exe (Windows) or dist/privacy-anonymizer (Linux/macOS)
#
# Hidden imports include optional adapters that PyInstaller may not detect via
# static analysis because they are loaded lazily through the registry.

# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

hiddenimports = [
    "privacy_anonymizer",
    "privacy_anonymizer.cli",
    "privacy_anonymizer.anonymizer",
    "privacy_anonymizer.config",
    "privacy_anonymizer.errors",
    "privacy_anonymizer.masking",
    "privacy_anonymizer.models",
    "privacy_anonymizer.resolver",
    "privacy_anonymizer.compliance",
    "privacy_anonymizer.evaluation",
    "privacy_anonymizer.detectors",
    "privacy_anonymizer.detectors.patterns_it",
    "privacy_anonymizer.detectors.gliner_detector",
    "privacy_anonymizer.detectors.opf_detector",
    "privacy_anonymizer.io",
    "privacy_anonymizer.io.base",
    "privacy_anonymizer.io.registry",
    "privacy_anonymizer.io.text_files",
    "privacy_anonymizer.io.office",
    "privacy_anonymizer.io.pdf",
    "privacy_anonymizer.io.images",
    "privacy_anonymizer.io.email_files",
    "privacy_anonymizer.io.json_files",
    "privacy_anonymizer.io.legacy",
    "privacy_anonymizer.io.xml_files",
    "privacy_anonymizer.io._ocr",
    # tiktoken namespace package: must be explicit so the runtime hook can seed
    # ENCODING_CONSTRUCTORS (pkgutil.iter_modules fails on namespace pkgs in archives).
    "tiktoken_ext.openai_public",
    # gliner and torch have many dynamic imports; collect_submodules ensures
    # all submodules are bundled, including those loaded lazily at runtime.
    *collect_submodules("gliner"),
    *collect_submodules("torch.fx"),
]

a = Analysis(
    ["../src/privacy_anonymizer/cli.py"],
    pathex=["../src"],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[os.path.join(SPECPATH, "hooks", "rthook_tiktoken.py")],
    excludes=[
        # ML packages excluded from base build to keep .exe small.
        # User can install GLiNER/OPF in the runtime Python alongside the .exe
        # only if the build is intended to bundle them.
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="privacy-anonymizer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
