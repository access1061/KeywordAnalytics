# -*- mode: python ; coding: utf-8 -*-

# KeywordAnalyzerPro.spec

# a.datas에 추가할 파일 목록입니다.
# (소스 경로, 실행 파일 내의 목적지 경로) 형식으로 지정합니다.
added_files = [
    ('keyword_pro.ico', '.'),
    ('style.qss', '.')
]

a = Analysis(
    ['pyqt_app.py'],  # 빌드할 메인 파이썬 스크립트
    pathex=[],
    binaries=[],
    datas=added_files,  # 위에서 정의한 리소스 파일들을 포함
    hiddenimports=[
        'xlsxwriter',  # Pandas 엑셀 출력 기능에 필요
        'webdriver_manager', # webdriver-manager 관련 모듈
        'selenium' # selenium 관련 모듈
    ],  # PyInstaller가 놓칠 수 있는 숨겨진 라이브러리
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='KeywordAnalyzerPro',  # 생성될 실행 파일의 이름
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True, # UPX가 설치된 경우 파일 압축으로 용량 감소
    console=False,  # GUI 앱이므로 콘솔 창을 띄우지 않음 (True로 바꾸면 디버깅 시 유용)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='keyword_pro.ico',  # 실행 파일에 적용할 아이콘
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='KeywordAnalyzerPro_folder', # --onedir 모드로 빌드 시 생성될 폴더 이름
)