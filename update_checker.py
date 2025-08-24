import os
import json
from PyQt6.QtCore import QThread, pyqtSignal

class UpdateChecker(QThread):
    update_available = pyqtSignal(str)  # 현재 버전
    error_occurred = pyqtSignal(str)

    def __init__(self, current_version):
        super().__init__()
        self.current_version = current_version

    def run(self):
        try:
            self.update_available.emit(self.current_version)
        except Exception as e:
            self.error_occurred.emit(str(e))

def get_current_version():
    try:
        version_file = os.path.join(os.path.dirname(__file__), 'version.json')
        with open(version_file, 'r', encoding='utf-8') as f:
            version_info = json.load(f)
            return version_info.get('version', '0.0.0')
    except:
        return '0.0.0'
