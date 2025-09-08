# -*- mode: python ; coding: utf-8 -*-
import os
import sys

# 상단의 불필요한 selenium import 제거

block_cipher = None

a = Analysis(
    ['pyqt_app_new.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('version.json', '.'),
        ('style.qss', '.'),
        ('keyword_pro.ico', '.'),
        ('api.env', '.'),
        ('update_checker.py', '.')  # [수정] update_checker.py 파일 포함
        # ('chrome_utils.py', '.') # [수정] 더 이상 사용하지 않으므로 제거
    ],
    # [수정] selenium과 webdriver_manager 추가
    hiddenimports=['PyQt6', 'pandas', 'requests', 'python-dotenv', 'selenium', 'webdriver_manager'],
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