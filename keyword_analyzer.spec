# keyword_analyzer.spec

# -*- mode: python ; coding: utf-8 -*-
import os
import sys

block_cipher = None

a = Analysis(
    ['pyqt_app_new.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('version.json', '.'),
        ('style.qss', '.'),
        ('keyword_pro.ico', '.'),
        ('update_checker.py', '.') # 로컬 모듈 포함
    ],
    # [수정] hiddenimports 업데이트
    hiddenimports=[
        'PyQt6',
        'pandas',
        'requests',
        'selenium',
        'webdriver_manager',
        'cryptography', # 암호화 라이브러리 추가
        'xlsxwriter'    # 엑셀 엔진 추가
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