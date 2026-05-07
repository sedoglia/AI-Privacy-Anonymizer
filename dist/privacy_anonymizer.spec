# PyInstaller spec — AI Privacy Anonymizer CLI
#
# Build: pyinstaller packaging/privacy_anonymizer.spec
# Output: dist/privacy-anonymizer.exe (Windows) or dist/privacy-anonymizer (Linux/macOS)
#
# Hidden imports include optional adapters that PyInstaller may not detect via
# static analysis because they are loaded lazily through the registry.

# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

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
    # torch is also imported directly in anonymizer._resolve_device() for CUDA auto-detect.
    "torch",
    # gradio and its web server stack have many lazily loaded modules.
    *collect_submodules("gradio"),
    *collect_submodules("gradio_client"),
    # rapidocr has dynamic imports for its inference engines and post-processors.
    *collect_submodules("rapidocr"),
    # ---- Document / office adapters (lazy-loaded via _import_*() helpers) ----
    # PyInstaller's static analysis cannot see imports inside try-except functions;
    # every adapter package must be listed here explicitly.
    #
    # PDF: fitz is a thin re-export wrapper; the real package is pymupdf.
    *collect_submodules("fitz"),
    *collect_submodules("pymupdf"),
    *collect_submodules("pypdf"),
    # Images
    *collect_submodules("PIL"),
    # Office formats
    *collect_submodules("docx"),
    *collect_submodules("openpyxl"),
    *collect_submodules("pptx"),
    # Legacy formats
    *collect_submodules("xlrd"),
    *collect_submodules("striprtf"),
    # Email
    *collect_submodules("extract_msg"),
    # XML/HTML processing (used by docx track-changes acceptance)
    *collect_submodules("lxml"),
    # Compliance PDF export
    *collect_submodules("reportlab"),
    # Progress bar (lazy-loaded in anonymizer._RichProgressBar)
    *collect_submodules("rich"),
    # OPF (openai/privacy-filter): imported with bare `import opf` inside try-except
    *collect_submodules("opf"),
    # ---- Web / API stack ----
    "safehttpx",
    "aiofiles",
    "anyio",
    "starlette",
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "fastapi",
    "httpx",
    "websockets",
]

datas = []
datas += collect_data_files("safehttpx")
datas += collect_data_files("groovy")
datas += collect_data_files("gradio", include_py_files=True)
datas += collect_data_files("gradio_client", include_py_files=False)
# rapidocr needs its config YAMLs and bundled ONNX models at runtime;
# without these the engine raises FileNotFoundError on default_models.yaml.
datas += collect_data_files("rapidocr")
# ---- Document / office adapter data files ----
# pymupdf bundles mupdfcpp64.dll (24 MB) inside the package directory;
# collect_data_files maps it correctly to pymupdf/ so the C extension finds it.
datas += collect_data_files("pymupdf")
# python-docx and python-pptx ship XML/image templates used to create new files.
datas += collect_data_files("docx")
datas += collect_data_files("pptx")
# reportlab ships fonts (TTF) and other resources needed at runtime.
datas += collect_data_files("reportlab")
# Remaining adapters have small-but-required data files (schemas, tzdata, etc.).
datas += collect_data_files("pypdf")
datas += collect_data_files("PIL")
datas += collect_data_files("extract_msg")
datas += collect_data_files("striprtf")
datas += collect_data_files("rich")
datas += collect_data_files("lxml")

a = Analysis(
    ["../src/privacy_anonymizer/cli.py"],
    pathex=["../src"],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[os.path.join(SPECPATH, "hooks", "rthook_tiktoken.py")],
    excludes=[],
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
