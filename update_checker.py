import sys
import os
import json
import requests
from datetime import datetime
import hashlib
from PyQt6.QtWidgets import QMessageBox
from PyQt6.QtCore import QThread, pyqtSignal

class UpdateChecker(QThread):
    update_available = pyqtSignal(str, str)  # 현재 버전, 새 버전
    error_occurred = pyqtSignal(str)

    def __init__(self, current_version, github_repo):
        super().__init__()
        self.current_version = current_version
        self.github_repo = github_repo

    def run(self):
        try:
            # GitHub API를 통해 최신 버전 정보 확인
            api_url = f"https://api.github.com/repos/{self.github_repo}/releases/latest"
            response = requests.get(api_url)
            response.raise_for_status()
            latest_release = response.json()
            latest_version = latest_release['tag_name'].replace('v', '')

            if self._compare_versions(latest_version, self.current_version) > 0:
                self.update_available.emit(self.current_version, latest_version)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _compare_versions(self, version1, version2):
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1 = v1_parts[i] if i < len(v1_parts) else 0
            v2 = v2_parts[i] if i < len(v2_parts) else 0
            if v1 > v2:
                return 1
            elif v1 < v2:
                return -1
        return 0

def get_current_version():
    try:
        version_file = os.path.join(os.path.dirname(__file__), 'version.json')
        with open(version_file, 'r', encoding='utf-8') as f:
            version_info = json.load(f)
            return version_info.get('version', '0.0.0')
    except:
        return '0.0.0'

def calculate_file_hash(filepath):
    """파일의 SHA256 해시값을 계산합니다."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
