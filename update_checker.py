import sys
import os
import json
from PyQt6.QtCore import QThread, pyqtSignal

def get_resource_path(relative_path):
    """PyInstaller 호환: 실행 환경에 따라 적절한 절대 경로를 반환합니다."""
    # PyInstaller에 의해 패키징된 경우 임시 폴더(_MEIPASS) 경로 사용
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    # 일반 파이썬 스크립트 실행 시 현재 폴더 경로 사용
    return os.path.join(os.path.abspath("."), relative_path)

def get_current_version():
    try:
        version_file = get_resource_path('version.json')
        with open(version_file, 'r', encoding='utf-8') as f:
            version_info = json.load(f)
            return version_info.get('version', '0.0.0')
    except Exception:
        # 콘솔 없는 배포 환경(windowed)을 위해 print 문 제거 및 조용한 예외 처리
        return '0.0.0'

class UpdateChecker(QThread):
    update_available = pyqtSignal(str)  # 현재 버전
    error_occurred = pyqtSignal(str)

    def __init__(self, current_version):
        super().__init__()
        self.current_version = current_version

    def run(self):
        try:
            # 향후 실제 서버(GitHub 등)에서 최신 버전을 가져와 비교하는 로직을 이곳에 추가할 수 있습니다.
            self.update_available.emit(self.current_version)
        except Exception as e:
            self.error_occurred.emit(str(e))