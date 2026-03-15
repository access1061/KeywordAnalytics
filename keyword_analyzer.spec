# keyword_analyzer.spec

# -*- mode: python ; coding: utf-8 -*-
import os
import sys
# [수정] 호환성 오류를 일으키는 import 라인을 삭제합니다.
# from PyInstaller.utils.hooks import get_qt_plugins_paths

block_cipher = None

a = Analysis(
    ['pyqt_app_new.py'],
    pathex=[],
    binaries=[],
    # ▼▼▼ [수정] datas 섹션에서 get_qt_plugins_paths 호출을 제거합니다 ▼▼▼
    datas=[
        ('version.json', '.'),
        ('style.qss', '.'),
        ('keyword_pro.ico', '.'),
    ],
    # ▲▲▲ [수정] 여기까지 교체 ▲▲▲
    hiddenimports=[
        'PyQt6',
        'pandas',
        'numpy',
        'requests',
        'selenium',
        'webdriver_manager',
        'packaging',
        'cryptography',
        'xlsxwriter'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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
    name='keyword_Pro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='keyword_pro.ico'
)