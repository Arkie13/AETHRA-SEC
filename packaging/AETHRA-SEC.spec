# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build for AETHRA-SEC.

Produces one directory containing two executables that share a single copy of
the runtime and the libraries:

* ``AETHRA-SEC.exe``     - the desktop console. Windowed, so double-clicking the
                           shortcut does not leave a black console window behind
                           the interface for the whole session.
* ``aethra-sec-cli.exe`` - the same application with a console attached, for
                           ``--check``, ``--headless`` and console setup. A
                           windowed process cannot print, so a diagnostics
                           command needs its own subsystem rather than a flag.

Both run ``aethra_sec.main``, so there is one entry point and no second code
path that could behave differently from the one people actually use.

**onedir, not onefile.** A one-file build unpacks itself into a temporary
directory on every start and deletes it on exit. That is a poor fit here for
three reasons: start-up is slower on every launch; the application spawns real
subprocesses (Nmap, TShark) and long-lived children outliving a vanishing temp
directory is a class of problem worth not having; and an installer is copying
files onto disk anyway, so the compression buys nothing a user sees.

Build it through ``packaging/build.ps1``, which also compiles the installer.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

# SPECPATH is set by PyInstaller to the directory holding this file.
PROJECT_ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - PyInstaller global

APP_NAME = "AETHRA-SEC"
ICON = str(PROJECT_ROOT / "assets" / "aethra-sec.ico")

# Files that must exist beside the executable at run time. `assets` carries the
# icon and the alert sound; `sql` carries the schema an administrator applies by
# hand when the application's own account may not create tables; `deploy/snort`
# carries the reference Snort configuration and rules the documentation refers
# to. All are read-only.
DATAS = [
    (str(PROJECT_ROOT / "assets"), "assets"),
    (str(PROJECT_ROOT / "sql"), "sql"),
    (str(PROJECT_ROOT / "deploy" / "snort"), "deploy/snort"),
    (str(PROJECT_ROOT / "docs"), "docs"),
    (str(PROJECT_ROOT / ".env.example"), "."),
]

# Imports PyInstaller's static analysis cannot see.
#
# mysql-connector-python loads its authentication plugins and its error-message
# locale by name at connection time, so nothing imports them textually and the
# analyser leaves them out. The failure is not a missing module at start-up - it
# is a connection that fails with an unhelpful error the first time a server
# asks for caching_sha2_password, which is the default on MySQL 8.
HIDDEN_IMPORTS = [
    "mysql.connector.locales.eng.client_error",
    "mysql.connector.plugins.mysql_native_password",
    "mysql.connector.plugins.caching_sha2_password",
    "mysql.connector.plugins.sha256_password",
    "mysql.connector.plugins.mysql_clear_password",
    # PyShark builds its parser lazily and imports lxml through it.
    "lxml.etree",
    "lxml._elementpath",
    # Tkinter's themed widgets and the file dialog are imported on demand.
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "tkinter.scrolledtext",
]
HIDDEN_IMPORTS += collect_submodules("aethra_sec")

# Excluded: heavy libraries nothing in AETHRA-SEC imports, plus the test suite.
# Leaving them out is not only about size - a build that silently contained
# pytest would let a developer machine's packages change what shipped.
EXCLUDES = [
    "pytest",
    "_pytest",
    "numpy",
    "pandas",
    "matplotlib",
    "scipy",
    "IPython",
    "notebook",
    "PyQt5",
    "PySide2",
    "PIL.ImageQt",
    "tests",
]

analysis = Analysis(  # noqa: F821 - PyInstaller global
    [str(PROJECT_ROOT / "aethra_sec" / "main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(analysis.pure)  # noqa: F821 - PyInstaller global

# --- the windowed console -------------------------------------------------
gui_exe = EXE(  # noqa: F821 - PyInstaller global
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON,
    version=str(PROJECT_ROOT / "packaging" / "version_info.txt"),
)

# --- the console companion ------------------------------------------------
cli_exe = EXE(  # noqa: F821 - PyInstaller global
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="aethra-sec-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON,
    version=str(PROJECT_ROOT / "packaging" / "version_info.txt"),
)

collection = COLLECT(  # noqa: F821 - PyInstaller global
    gui_exe,
    cli_exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=APP_NAME,
)
