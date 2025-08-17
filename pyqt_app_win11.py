import sys
import os
import time
import json
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from urllib.parse import quote
import pandas as pd
import requests
from dotenv import load_dotenv
import xml.etree.ElementTree as ET
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QMessageBox, QLineEdit, QCheckBox
)
from PyQt6.QtGui import QIcon, QColor
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal

# --- PyInstaller를 위한 리소스 경로 설정 함수 ---
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# === [수정] OS 테마 독립적인 UI를 위한 스타일시트(QSS) 재정의 ===
# 외부 파일 대신 코드 내에 스타일시트를 직접 정의하여 일관성을 확보합니다.
STYLESHEET = """
    QWidget { 
        background-color: #F8F9FA; 
        color: #212529; 
        font-family: 'Malgun Gothic'; 
        font-size: 10pt; 
    }
    QMainWindow { 
        background-color: #FFFFFF; 
    }
    QTabWidget::pane { 
        border: 1px solid #DEE2E6; 
        border-radius: 4px; 
    }
    QTabBar::tab { 
        background-color: #E9ECEF; 
        color: #495057; 
        padding: 10px 20px; 
        border-top-left-radius: 4px; 
        border-top-right-radius: 4px; 
        border: 1px solid #DEE2E6; 
        border-bottom: none; 
    }
    QTabBar::tab:selected { 
        background-color: #007BFF; 
        color: white; 
        font-weight: bold; 
    }
    QPushButton { 
        background-color: #6C757D; 
        color: white; 
        border-radius: 4px; 
        padding: 10px; 
        border: none; 
        font-weight: bold; 
    }
    QPushButton:hover { 
        background-color: #5a6268; 
    }
    QPushButton#AuthButton { background-color: #17a2b8; }
    QPushButton#AuthButton:hover { background-color: #138496; }
    QPushButton#TrendButton { background-color: #007bff; }
    QPushButton#TrendButton:hover { background-color: #0056b3; }
    QPushButton#AnalyzeButton { background-color: #28a745; }
    QPushButton#AnalyzeButton:hover { background-color: #1e7e34; }
    QPushButton#CopyButton { background-color: #6f42c1; }
    QPushButton#CopyButton:hover { background-color: #553c9a; }
    QPushButton#ExcelButton { background-color: #fd7e14; }
    QPushButton#ExcelButton:hover { background-color: #c96a11; }
    QPushButton#AutocompleteSearchButton { background-color: #fd7e14; }
    QPushButton#AutocompleteSearchButton:hover { background-color: #c96a11; }
    QPushButton#AutocompleteCopyButton { background-color: #6f42c1; }
    QPushButton#AutocompleteCopyButton:hover { background-color: #553c9a; }
    QPushButton#ResetButton { background-color: #8f1313; }
    QPushButton#ResetButton:hover { background-color: #610d0d; }
    QPushButton:disabled { 
        background-color: #adb5bd; 
        color: #E0E0E0; 
    }
    QTextEdit, QTableWidget, QLineEdit { /* [수정] QLineEdit 추가 */
        background-color: #FFFFFF; 
        border: 1px solid #CED4DA; 
        border-radius: 4px; 
        padding: 5px; 
    }
    QHeaderView::section { 
        background-color: #E9ECEF; 
        color: #495057; 
        padding: 8px; 
        border: 1px solid #DEE2E6; 
        font-weight: bold; 
    }
    QProgressBar { 
        border: none; 
        border-radius: 8px; 
        background-color: #E9ECEF; 
        text-align: center; 
        color: #FFFFFF; 
        font-weight: bold; 
        font-size: 12pt; 
        min-height: 30px; 
    }
    QProgressBar::chunk { 
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4DA6FF, stop:1 #007ACC); 
        border-radius: 8px; 
    }
    QTextEdit#LogWindow { 
        background-color: #252525; 
        color: #F8F9FA; 
        font-family: 'Consolas', 'Courier New', monospace; 
    }
    /* [수정] QCheckBox 스타일 명시적 정의 */
    QCheckBox { 
        font-weight: bold; 
        spacing: 5px; /* 체크박스와 텍스트 간격 */
    }
    QCheckBox::indicator { /* 체크박스 모양 정의 */
        width: 16px;
        height: 16px;
        border: 1px solid #CED4DA;
        border-radius: 3px;
        background-color: #FFFFFF;
    }
    QCheckBox::indicator:hover {
        border: 1px solid #007BFF;
    }
    QCheckBox::indicator:checked { /* 체크되었을 때 모양 */
        background-color: #007BFF;
        border: 1px solid #0056b3;
        /* 간단한 체크 표시를 위한 이미지 (Base64 인코딩) */
        image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik05IDE2LjE3TDQuODMgMTIgMy40MSAxMy40MSA5IDE5IDIxIDcgMTkuNTkgNS41OXoiLz48L3N2Zz4=);
    }
"""

# --- API 관련 헬퍼 클래스 및 함수 ---
class Signature:
    @staticmethod
    def generate(timestamp, method, uri, secret_key):
        message = f"{timestamp}.{method}.{uri}"
        hash_val = hmac.new(bytes(secret_key, "utf-8"), bytes(message, "utf-8"), hashlib.sha256)
        return base64.b64encode(hash_val.digest())

def load_cookies_from_auth_file(path="auth.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            storage_state = json.load(f)
        return {cookie["name"]: cookie["value"] for cookie in storage_state["cookies"]}
    except FileNotFoundError:
        return None

def get_naver_ad_keywords(keyword: str, api_key: str, secret_key: str, customer_id: str):
    if not all([api_key, secret_key, customer_id]):
        raise ValueError("광고 API 키가 없습니다.")
    
    signature_generator = Signature()
    base_url, uri, method = "https://api.searchad.naver.com", "/keywordstool", "GET"
    
    timestamp = str(round(time.time() * 1000))
    signature = signature_generator.generate(timestamp, method, uri, secret_key)
    
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-Timestamp": timestamp,
        "X-API-KEY": api_key,
        "X-Customer": str(customer_id),
        "X-Signature": signature,
    }
    
    params = {"hintKeywords": keyword.replace(" ", ""), "showDetail": "1"}
    r = requests.get(base_url + uri, params=params, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json().get("keywordList", [])

def get_blog_post_count(keyword: str, client_id: str, client_secret: str):
    if not all([client_id, client_secret]):
        raise ValueError("검색 API 키가 없습니다.")
    
    url = f"https://openapi.naver.com/v1/search/blog?query={quote(keyword)}"
    headers = {"X-Naver-Client-Id": client_id, "X-Naver-Client-Secret": client_secret}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("total", 0)

class Worker(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)
    log = pyqtSignal(str, str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.fn(self, *self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            import traceback
            self.error.emit(f"{e}\n{traceback.format_exc()}")

class KeywordApp(QMainWindow):
    NAVER_TRENDS_API_URL = "https://creator-advisor.naver.com/api/v6/trend/category"
    AC_NAVER_URL = "https://ac.search.naver.com/nx/ac?q_enc=UTF-8&st=100&r_format=json&q="
    AC_GOOGLE_URL = "https://suggestqueries.google.com/complete/search?client=firefox&output=json&q="
    AC_DAUM_URL = "https://suggest.search.daum.net/sushi/opensearch/pc?q="
    CATEGORIES = ["맛집", "국내여행", "세계여행", "비즈니스·경제", "패션·미용", "상품리뷰", "일상·생각", "건강·의학", "육아·결혼", "요리·레시피", "IT·컴퓨터", "교육·학문", "자동차", "인테리어·DIY", "스포츠", "취미", "방송", "게임", "스타·연예인", "영화", "공연·전시", "반려동물", "사회·정치", "드라마", "어학·외국어", "문학·책", "음악", "만화·애니", "좋은글·이미지", "미술·디자인", "원예·재배", "사진"]
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("키워드 분석기 Pro v1.9")
        self.setGeometry(100, 100, 1400, 800)
        self.setStyleSheet(STYLESHEET) # [수정] 코드에 내장된 스타일시트 적용
        
        load_dotenv("api.env")
        self.NAVER_ADS_API_KEY = os.getenv("NAVER_ADS_API_KEY")
        self.NAVER_ADS_API_SECRET = os.getenv("NAVER_ADS_API_SECRET")
        self.NAVER_ADS_CUSTOMER_ID = os.getenv("NAVER_ADS_CUSTOMER_ID")
        self.NAVER_SEARCH_CLIENT_ID = os.getenv("NAVER_SEARCH_CLIENT_ID")
        self.NAVER_SEARCH_CLIENT_SECRET = os.getenv("NAVER_SEARCH_CLIENT_SECRET")

        icon_path = resource_path("keyword_pro.ico")
        if os.path.exists(icon_path): self.setWindowIcon(QIcon(icon_path))

        self.thread = None
        self.worker = None
        self.results_df = None

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        top_level_layout = QVBoxLayout(central_widget)

        self.create_settings_bar(top_level_layout)
        main_content_layout = QHBoxLayout()
        top_level_layout.addLayout(main_content_layout)

        self.tabs = QTabWidget()
        main_content_layout.addWidget(self.tabs, 2)

        log_container = QWidget()
        log_layout = QVBoxLayout(log_container)
        log_label = QLabel("실시간 로그")
        log_label.setStyleSheet("font-weight: bold; font-size: 12pt; padding: 5px;")
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setObjectName("LogWindow")
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.log_widget)
        main_content_layout.addWidget(log_container, 1)

        self.create_trend_fetch_tab()
        self.create_analysis_tab()
        self.create_autocomplete_tab()
        
        if self.NAVER_ADS_API_KEY:
            self.log_message("INFO", "프로그램이 시작되었습니다. API 키를 로드했습니다.")
        else:
            self.log_message("WARNING", "api.env 파일을 찾을 수 없습니다. API 키를 로드해주세요.")
            
    def create_settings_bar(self, parent_layout):
        settings_frame = QWidget()
        settings_layout = QHBoxLayout(settings_frame)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        self.reset_button = QPushButton("화면 초기화")
        self.reset_button.setObjectName("ResetButton")
        self.reset_button.clicked.connect(self.reset_ui)
        self.auth_button = QPushButton("인증 정보 갱신 (로그인)")
        self.auth_button.setObjectName("AuthButton")
        self.auth_button.clicked.connect(self.start_auth_regeneration)
        settings_layout.addStretch()
        settings_layout.addWidget(self.reset_button)
        settings_layout.addWidget(self.auth_button)
        parent_layout.addWidget(settings_frame)

    def reset_ui(self):
        self.trend_table.setRowCount(0)
        self.status_label_fetch.setText("버튼을 눌러 트렌드 키워드 수집을 시작하세요.")
        self.progress_bar_fetch.setValue(0)
        self.analysis_input_widget.clear()
        self.result_table.setRowCount(0)
        self.progress_bar_analysis.setValue(0)
        self.export_excel_button.setDisabled(True)
        self.autocomplete_input.clear()
        self.autocomplete_table.setRowCount(0)
        self.cb_naver.setChecked(True); self.cb_daum.setChecked(True); self.cb_google.setChecked(True)
        self.log_message("INFO", "모든 작업 공간이 초기화되었습니다.")

    def create_trend_fetch_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        control_widget = QWidget()
        control_layout = QHBoxLayout(control_widget)
        control_layout.setContentsMargins(0, 0, 0, 0)
        self.fetch_trends_button = QPushButton("트렌드 가져오기")
        self.fetch_trends_button.setObjectName("TrendButton")
        self.copy_to_analyzer_button = QPushButton("키워드 → 분석 탭으로 복사")
        self.copy_to_analyzer_button.setObjectName("CopyButton")
        control_layout.addWidget(self.fetch_trends_button)
        control_layout.addWidget(self.copy_to_analyzer_button)
        control_layout.addStretch()
        status_container = QWidget()
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label_fetch = QLabel("버튼을 눌러 트렌드 키워드 수집을 시작하세요.")
        self.progress_bar_fetch = QProgressBar()
        self.progress_bar_fetch.setFormat("수집 진행률: %p%")
        status_layout.addWidget(self.status_label_fetch)
        status_layout.addWidget(self.progress_bar_fetch)
        control_layout.addWidget(status_container)
        self.trend_table = QTableWidget()
        headers = ["카테고리", "키워드", "순위변동"]
        self.trend_table.setColumnCount(len(headers))
        self.trend_table.setHorizontalHeaderLabels(headers)
        layout.addWidget(control_widget)
        layout.addWidget(self.trend_table)
        self.tabs.addTab(tab, "트렌드 키워드 수집")
        self.fetch_trends_button.clicked.connect(self.start_trend_fetching)
        self.copy_to_analyzer_button.clicked.connect(self.copy_trends_to_analyzer)

    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        placeholder_text = """--- 키워드를 입력하거나 붙여넣어 주세요 (한 줄에 하나씩) ---

💡 '기회 지수'란?
'월간 총검색량 ÷ 블로그 총문서수'로 계산되는 값으로,
문서(공급) 대비 검색량(수요)이 얼마나 높은지를 나타내는 지표입니다."""
        self.analysis_input_widget = QTextEdit()
        self.analysis_input_widget.setPlaceholderText(placeholder_text)
        
             
        control_layout = QHBoxLayout()
        self.analyze_button = QPushButton("기회지수 분석 시작")
        self.analyze_button.setObjectName("AnalyzeButton")
        
        self.export_excel_button = QPushButton("엑셀로 저장")
        self.export_excel_button.setObjectName("ExcelButton")
        self.export_excel_button.setDisabled(True)
        
        self.progress_bar_analysis = QProgressBar()
        self.progress_bar_analysis.setFixedHeight(20); self.progress_bar_analysis.setTextVisible(True); self.progress_bar_analysis.setFormat("%p%")
        
        control_layout.addWidget(self.analyze_button)
        control_layout.addWidget(self.export_excel_button)
        control_layout.addStretch()
        control_layout.addWidget(self.progress_bar_analysis)
        
        self.result_table = QTableWidget()
        headers = ["분류", "키워드", "총검색량", "총문서수", "기회지수"]
        self.result_table.setColumnCount(len(headers)); self.result_table.setHorizontalHeaderLabels(headers)
        
        layout.addWidget(self.analysis_input_widget, 1)
        layout.addLayout(control_layout)
        layout.addWidget(self.result_table, 3)
        self.tabs.addTab(tab, "기회지수 분석")
        
        self.analyze_button.clicked.connect(self.start_competition_analysis)
        self.export_excel_button.clicked.connect(self.export_to_excel)

    def create_autocomplete_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        top_control_layout = QVBoxLayout()
        top_control_layout.setContentsMargins(0, 0, 0, 10)
        input_layout = QHBoxLayout()
        self.autocomplete_input = QLineEdit()
        self.autocomplete_input.setPlaceholderText("자동완성 키워드를 검색할 단어를 입력하세요...")
        input_layout.addWidget(QLabel("검색어:"), 0); input_layout.addWidget(self.autocomplete_input, 1)
        checkbox_layout = QHBoxLayout()
        checkbox_layout.setContentsMargins(10, 5, 0, 5)
        checkbox_layout.addWidget(QLabel("검색 엔진:"), 0)
        self.cb_naver = QCheckBox("네이버"); self.cb_daum = QCheckBox("Daum"); self.cb_google = QCheckBox("Google")
        self.cb_naver.setChecked(True); self.cb_daum.setChecked(True); self.cb_google.setChecked(True)
        checkbox_layout.addWidget(self.cb_naver); checkbox_layout.addWidget(self.cb_daum); checkbox_layout.addWidget(self.cb_google)
        checkbox_layout.addStretch()
        button_layout = QHBoxLayout()
        self.autocomplete_search_button = QPushButton("자동완성 검색")
        self.autocomplete_search_button.setObjectName("AutocompleteSearchButton")
        self.autocomplete_copy_button = QPushButton("키워드 → 분석 탭으로 복사")
        self.autocomplete_copy_button.setObjectName("AutocompleteCopyButton")
        button_layout.addStretch()
        button_layout.addWidget(self.autocomplete_search_button, 1); button_layout.addWidget(self.autocomplete_copy_button, 1)
        top_control_layout.addLayout(input_layout); top_control_layout.addLayout(checkbox_layout); top_control_layout.addLayout(button_layout)
        self.autocomplete_table = QTableWidget()
        headers = ["자동완성 키워드"]
        self.autocomplete_table.setColumnCount(len(headers)); self.autocomplete_table.setHorizontalHeaderLabels(headers)
        self.autocomplete_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addLayout(top_control_layout)
        layout.addWidget(self.autocomplete_table)
        self.tabs.addTab(tab, "자동완성 키워드 수집")
        self.autocomplete_search_button.clicked.connect(self.start_autocomplete_search)
        self.autocomplete_input.returnPressed.connect(self.start_autocomplete_search)
        self.autocomplete_copy_button.clicked.connect(self.copy_autocomplete_to_analyzer)
    
    def run_worker(self, worker_fn, finish_slot, progress_bar=None, **kwargs):
        self.thread = QThread()
        self.worker = Worker(worker_fn, **kwargs)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(finish_slot)
        self.worker.error.connect(self.on_worker_error)
        
        if progress_bar: self.worker.progress.connect(progress_bar.setValue)
        
        self.worker.log.connect(self.log_message)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        
        self.worker.error.connect(self.thread.quit)
        self.worker.error.connect(self.worker.deleteLater)
        self.thread.start()

    def start_trend_fetching(self):
        self.fetch_trends_button.setDisabled(True)
        self.status_label_fetch.setText("트렌드 수집 중...")
        self.trend_table.setRowCount(0); self.progress_bar_fetch.setValue(0)
        self.run_worker(self.fetch_trends_worker, self.on_trend_fetching_finished, progress_bar=self.progress_bar_fetch)

    def start_competition_analysis(self):
        keywords = self.analysis_input_widget.toPlainText().strip().split("\n")
        keywords = [kw.strip() for kw in keywords if kw.strip()]
        if not keywords:
            self.log_message("WARNING", "분석할 키워드가 입력되지 않았습니다.")
            QMessageBox.warning(self, "경고", "분석할 키워드를 입력하거나 붙여넣어 주세요.")
            return
        
        self.analyze_button.setDisabled(True)
        self.export_excel_button.setDisabled(True)
        self.result_table.setRowCount(0)
        self.progress_bar_analysis.setValue(0)
        
        self.run_worker(
            self.analyze_competition_worker, 
            self.on_analysis_finished, 
            progress_bar=self.progress_bar_analysis, 
            keywords=keywords
        )

    def start_auth_regeneration(self):
        self.auth_button.setDisabled(True)
        self.log_message("INFO", "사용자 인증 갱신 프로세스를 시작합니다.")
        self.run_worker(self.save_auth_logic, self.on_auth_finished)
        
    def start_autocomplete_search(self):
        keyword = self.autocomplete_input.text().strip()
        if not keyword:
            QMessageBox.warning(self, "입력 오류", "검색어를 입력해주세요.")
            return
        selected_engines = [name for cb, name in [(self.cb_naver, 'naver'), (self.cb_daum, 'daum'), (self.cb_google, 'google')] if cb.isChecked()]
        if not selected_engines:
            QMessageBox.warning(self, "선택 오류", "하나 이상의 검색 엔진을 선택해주세요.")
            return
        self.autocomplete_search_button.setDisabled(True)
        self.autocomplete_table.setRowCount(0)
        self.run_worker(self.autocomplete_worker, self.on_autocomplete_finished, keyword=keyword, engines=selected_engines)

    def fetch_trends_worker(self, worker_instance):
        worker_instance.log.emit("INFO", "📈 트렌드 키워드 수집을 시작합니다...")
        cookies = load_cookies_from_auth_file()
        if not cookies:
            raise ValueError("'auth.json' 파일을 찾을 수 없습니다. '인증 정보 갱신' 버튼을 눌러주세요.")

        now = datetime.now()
        if now.hour < 9:
            days_to_subtract = 2
            worker_instance.log.emit("INFO", "현재 시간(오전 9시 이전) 기준으로 2일 전 트렌드를 검색합니다.")
        else:
            days_to_subtract = 1
            worker_instance.log.emit("INFO", "현재 시간(오전 9시 이후) 기준으로 1일 전 트렌드를 검색합니다.")
        
        target_date = now - timedelta(days=days_to_subtract)
        target_date_str = target_date.strftime("%Y-%m-%d")
        worker_instance.log.emit("INFO", f"🎯 검색 대상 날짜: {target_date_str}")

        try:
            worker_instance.log.emit("INFO", "인증 정보 유효성을 확인합니다...")
            test_category = self.CATEGORIES[0]
            test_api_url = f"{self.NAVER_TRENDS_API_URL}?categories={quote(test_category)}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=1&service=naver_blog"
            
            response = requests.get(test_api_url, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"}, timeout=10)
            
            if response.status_code != 200:
                raise ValueError(f"인증 확인 실패 (HTTP {response.status_code}). '인증 정보 갱신'이 필요할 수 있습니다.")

            try:
                data = response.json()
            except json.JSONDecodeError:
                raise ValueError("인증 정보가 유효하지 않습니다 (API 응답이 올바르지 않음). '인증 정보 갱신'을 해주세요.")

            if "data" not in data:
                error_message = data.get("message", "알 수 없는 API 구조")
                raise ValueError(f"API 응답 구조가 예상과 다릅니다. 서버 응답: {error_message}")

        except requests.RequestException as e:
            raise ConnectionError(f"인증 확인 중 네트워크 오류가 발생했습니다: {e}")
        
        worker_instance.log.emit("SUCCESS", "✅ 인증 정보가 유효합니다.")
        
        all_trends_data = []
        for i, category in enumerate(self.CATEGORIES):
            worker_instance.log.emit("INFO", f"   - '{category}' 카테고리 수집 중...")
            worker_instance.progress.emit(int((i + 1) / len(self.CATEGORIES) * 100))
            api_url = f"{self.NAVER_TRENDS_API_URL}?categories={quote(category)}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=20&service=naver_blog"
            try:
                response = requests.get(api_url, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"})
                if response.status_code == 200 and (data := response.json()).get("data") and data["data"] and data["data"][0].get("queryList"):
                    for item in data["data"][0]["queryList"]:
                        rank_change = item.get("rankChange")
                        try:
                            if rank_change is not None:
                                rank_change = int(rank_change)
                        except (ValueError, TypeError):
                            rank_change = None
                        all_trends_data.append({"카테고리": category, "키워드": item.get("query", "N/A"), "순위변동": rank_change})
                else:
                    worker_instance.log.emit("WARNING", f"   - '{category}' 카테고리 요청 실패 (상태 코드: {response.status_code})")
                time.sleep(0.3)
            except Exception as e:
                worker_instance.log.emit("ERROR", f"   - '{category}' 처리 중 오류: {e}")
        return all_trends_data

    def analyze_competition_worker(self, worker_instance, keywords):
        worker_instance.log.emit("INFO", "🔬 키워드 기회지수 분석을 시작합니다 (0.15초 간격)...")
        unique_keywords, analysis_results, total = list(dict.fromkeys(keywords)), [], len(list(dict.fromkeys(keywords)))
        worker_instance.log.emit("INFO", f"중복 제거 후 {total}개의 키워드를 분석합니다.")
        
        for i, original_keyword in enumerate(unique_keywords):
            worker_instance.progress.emit(int((i + 1) / total * 100))
            
            keyword_for_api = original_keyword.replace(" ", "")
            if not keyword_for_api:
                worker_instance.log.emit("WARNING", f"'{original_keyword}'는 공백만 있어 분석에서 제외됩니다.")
                continue

            worker_instance.log.emit("INFO", f"({i+1}/{total}) '{original_keyword}' (API 조회: '{keyword_for_api}') 분석 중...")
            try:
                ad_api_data = get_naver_ad_keywords(keyword_for_api, self.NAVER_ADS_API_KEY, self.NAVER_ADS_API_SECRET, self.NAVER_ADS_CUSTOMER_ID)
                post_count = get_blog_post_count(keyword_for_api, self.NAVER_SEARCH_CLIENT_ID, self.NAVER_SEARCH_CLIENT_SECRET)

                pc_search, mobile_search = 0, 0
                if ad_api_data and (exact_match := next((item for item in ad_api_data if item["relKeyword"] == keyword_for_api), None)):
                    pc_count_str = str(exact_match.get("monthlyPcQcCnt", 0))
                    mobile_count_str = str(exact_match.get("monthlyMobileQcCnt", 0))
                    pc_search = 5 if "<" in pc_count_str else int(pc_count_str)
                    mobile_search = 5 if "<" in mobile_count_str else int(mobile_count_str)
                
                total_search = pc_search + mobile_search
                opportunity_index_float = (total_search / post_count) if post_count > 0 else 0
                
                category = "일반"
                if opportunity_index_float >= 0.2: category = "🏆 황금"
                elif opportunity_index_float >= 0.05 and total_search >= 1000: category = "✨ 매력"
                
                analysis_results.append({"분류": category, "키워드": original_keyword, "총검색량": total_search, "총문서수": post_count, "기회지수": round(opportunity_index_float, 2)})
            except Exception as e: worker_instance.log.emit("ERROR", f"'{original_keyword}' 분석 중 오류 발생: {e}")
            time.sleep(0.15)
        return pd.DataFrame(analysis_results)

    def save_auth_logic(self, worker_instance):
        worker_instance.log.emit("INFO", "🔒 인증 정보 갱신을 시작합니다...")
        worker_instance.log.emit("WARNING", "새로운 크롬 창에서 네이버 로그인을 직접 진행해주세요.")
        
        driver = None
        try:
            service = ChromeService(ChromeDriverManager().install())
            options = webdriver.ChromeOptions()
            driver = webdriver.Chrome(service=service, options=options)

            driver.get("https://nid.naver.com/nidlogin.login")
            worker_instance.log.emit("INFO", "로그인 페이지가 열렸습니다. 로그인이 완료될 때까지 대기합니다...")
            WebDriverWait(driver, 300).until(lambda d: "nid.naver.com" not in d.current_url)
            worker_instance.log.emit("INFO", "로그인이 감지되었습니다. 쿠키를 저장합니다...")
            storage_state = {"cookies": driver.get_cookies()}
            with open("auth.json", "w", encoding="utf-8") as f:
                json.dump(storage_state, f, ensure_ascii=False, indent=4)
            return "✅ 인증 정보(auth.json)가 성공적으로 갱신되었습니다!"
        except Exception as e:
            import traceback
            error_msg = f"인증 절차 중 오류 발생: {e}\n{traceback.format_exc()}"
            worker_instance.log.emit("ERROR", error_msg)
            raise e
        finally: 
            if driver:
                driver.quit()

    def _fetch_naver_autocomplete(self, worker_instance, keyword, all_results):
        try:
            worker_instance.log.emit("INFO", "  - 네이버 검색 중...")
            url = self.AC_NAVER_URL + quote(keyword)
            resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and (items := data.get("items")) and isinstance(items, list) and len(items) > 0:
                for item in items[0]:
                    if isinstance(item, list) and len(item) > 0 and isinstance(item[0], str):
                        all_results.add(item[0])
            worker_instance.log.emit("SUCCESS", "  - 네이버 검색 완료.")
        except Exception as e:
            worker_instance.log.emit("ERROR", f"  - 네이버 자동완성 검색 실패: {e}")

    def _fetch_daum_autocomplete(self, worker_instance, keyword, all_results):
        try:
            worker_instance.log.emit("INFO", "  - Daum 검색 중...")
            url = self.AC_DAUM_URL + quote(keyword)
            resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
            content_text = resp.text
            if "json" in resp.headers.get("Content-Type", "").lower():
                data = json.loads(content_text)
                if isinstance(data, list) and len(data) > 1:
                    for item in data[1]: all_results.add(item.strip())
                elif isinstance(data, dict) and (items := data.get("items", {}).get("s")):
                    for item in items:
                        if len(item) > 1: all_results.add(item[1])
            else:
                root = ET.fromstring(resp.content)
                for item in root.findall('.//item/keyword'):
                    if item.text: all_results.add(item.text.strip())
            worker_instance.log.emit("SUCCESS", "  - Daum 검색 완료.")
        except Exception as e:
            worker_instance.log.emit("ERROR", f"  - Daum 자동완성 검색 실패: {e}")

    def _fetch_google_autocomplete(self, worker_instance, keyword, all_results):
        try:
            worker_instance.log.emit("INFO", "  - Google 검색 중...")
            url = self.AC_GOOGLE_URL + quote(keyword)
            resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                for item in data[1]: all_results.add(item.strip())
            worker_instance.log.emit("SUCCESS", "  - Google 검색 완료.")
        except Exception as e:
            worker_instance.log.emit("ERROR", f"  - Google 자동완성 검색 실패: {e}")

    def autocomplete_worker(self, worker_instance, keyword, engines):
        worker_instance.log.emit("INFO", f"'{keyword}' 자동완성 키워드 검색 시작 (대상: {', '.join(engines)})")
        all_results = set()
        if 'naver' in engines: self._fetch_naver_autocomplete(worker_instance, keyword, all_results)
        if 'daum' in engines: self._fetch_daum_autocomplete(worker_instance, keyword, all_results)
        if 'google' in engines: self._fetch_google_autocomplete(worker_instance, keyword, all_results)
        worker_instance.log.emit("SUCCESS", f"✅ 총 {len(all_results)}개의 키워드를 찾았습니다.")
        return sorted(list(all_results))

    def on_trend_fetching_finished(self, trend_data):
        self.fetch_trends_button.setDisabled(False)
        self.progress_bar_fetch.setValue(100)
        self.status_label_fetch.setText(f"✅ {len(trend_data)}개 트렌드 키워드 수집 완료!")
        self.log_message("SUCCESS", "트렌드 키워드 수집이 완료되었습니다.")
        self.trend_table.setRowCount(len(trend_data))
        for row_idx, item in enumerate(trend_data):
            category_item, keyword_item = QTableWidgetItem(str(item["카테고리"])), QTableWidgetItem(str(item["키워드"]))
            rank_change = item["순위변동"]
            rank_text = "NEW" if rank_change is None else ("-" if rank_change == 0 else f"{rank_change:g}")
            rank_item = QTableWidgetItem(rank_text)
            rank_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if rank_change is None: rank_item.setForeground(QColor("#28A745"))
            elif rank_change > 0: rank_item.setForeground(QColor("#DC3545"))
            elif rank_change < 0: rank_item.setForeground(QColor("#007BFF"))
            self.trend_table.setItem(row_idx, 0, category_item)
            self.trend_table.setItem(row_idx, 1, keyword_item)
            self.trend_table.setItem(row_idx, 2, rank_item)
        self.trend_table.resizeColumnsToContents()

    def on_analysis_finished(self, df):
        self.analyze_button.setDisabled(False)
        if df is not None and not df.empty:
            self.results_df = df.sort_values(by="기회지수", ascending=False)
            self.update_result_table(self.results_df)
            self.export_excel_button.setDisabled(False)
            self.log_message("SUCCESS", "🎉 모든 키워드의 기회지수 분석이 완료되었습니다.")
        else: self.log_message("WARNING", "분석된 결과가 없습니다.")
        self.progress_bar_analysis.setValue(100)

    def on_autocomplete_finished(self, keywords):
        self.autocomplete_table.setRowCount(len(keywords))
        for row_idx, keyword in enumerate(keywords): self.autocomplete_table.setItem(row_idx, 0, QTableWidgetItem(keyword))
        self.autocomplete_table.resizeColumnsToContents()
        self.autocomplete_search_button.setDisabled(False)
        self.log_message("SUCCESS", "자동완성 키워드 수집이 완료되었습니다.")

    def on_auth_finished(self, message):
        self.auth_button.setDisabled(False)
        self.log_message("SUCCESS", message)
        QMessageBox.information(self, "성공", message)

    def on_worker_error(self, error_message):
        concise_error = error_message.splitlines()[0]
        self.log_message("ERROR", f"작업 중 오류 발생: {concise_error}")
        QMessageBox.critical(self, "오류", f"오류가 발생했습니다:\n{concise_error}")
        self.fetch_trends_button.setDisabled(False)
        self.analyze_button.setDisabled(False)
        self.auth_button.setDisabled(False)
        self.autocomplete_search_button.setDisabled(False)

    def copy_trends_to_analyzer(self):
        if (rows := self.trend_table.rowCount()) > 0:
            keywords = [self.trend_table.item(row, 1).text() for row in range(rows)]
            self.analysis_input_widget.setPlainText("\n".join(keywords))
            self.tabs.setCurrentIndex(1)
            self.log_message("INFO", f"{len(keywords)}개 키워드를 분석 탭으로 복사했습니다.")
        else: QMessageBox.information(self, "알림", "먼저 트렌드 키워드를 가져와주세요.")

    def copy_autocomplete_to_analyzer(self):
        if (rows := self.autocomplete_table.rowCount()) > 0:
            keywords = [self.autocomplete_table.item(row, 0).text() for row in range(rows)]
            current_text = self.analysis_input_widget.toPlainText().strip()
            new_text = "\n".join(keywords)
            final_text = f"{current_text}\n{new_text}" if current_text else new_text
            self.analysis_input_widget.setPlainText(final_text.strip())
            self.tabs.setCurrentIndex(1)
            self.log_message("INFO", f"{len(keywords)}개 키워드를 분석 탭으로 복사했습니다.")
        else: QMessageBox.information(self, "알림", "먼저 자동완성 키워드를 검색해주세요.")

    def update_result_table(self, df):
        self.result_table.setRowCount(len(df))
        headers = ["분류", "키워드", "총검색량", "총문서수", "기회지수"]
        self.result_table.setHorizontalHeaderLabels(headers)
        for row_idx, row_data in enumerate(df.itertuples()):
            self.result_table.setItem(row_idx, 0, QTableWidgetItem(str(row_data.분류)))
            self.result_table.setItem(row_idx, 1, QTableWidgetItem(str(row_data.키워드)))
            self.result_table.setItem(row_idx, 2, QTableWidgetItem(f"{row_data.총검색량:,}"))
            self.result_table.setItem(row_idx, 3, QTableWidgetItem(f"{row_data.총문서수:,}"))
            self.result_table.setItem(row_idx, 4, QTableWidgetItem(f"{row_data.기회지수:,}"))
        self.result_table.resizeColumnsToContents()

    def export_to_excel(self):
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "경고", "엑셀로 내보낼 데이터가 없습니다.")
            return
        if (filtered_df := self.results_df[self.results_df['분류'] != '일반']).empty:
            QMessageBox.information(self, "알림", "저장할 키워드가 없습니다. '일반' 분류만 존재합니다.")
            return
        filename = f"keyword_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        try:
            with pd.ExcelWriter(filename, engine="xlsxwriter") as writer:
                filtered_df.to_excel(writer, index=False, sheet_name="KeywordAnalysis")
                workbook, worksheet = writer.book, writer.sheets["KeywordAnalysis"]
                header_format = workbook.add_format({"bold": True, "font_color": "white", "bg_color": "#4F81BD", "align": "center", "valign": "vcenter", "border": 1})
                for col_num, value in enumerate(filtered_df.columns.values): worksheet.write(0, col_num, value, header_format)
                for idx, col in enumerate(filtered_df):
                    max_len = max(filtered_df[col].astype(str).map(len).max(), len(str(filtered_df[col].name))) + 2
                    worksheet.set_column(idx, idx, max_len)
            self.log_message("SUCCESS", f"✅ 성공! '{filename}' 파일이 저장되었습니다.")
            QMessageBox.information(self, "성공", f"'{filename}' 파일이 성공적으로 저장되었습니다.")
        except Exception as e:
            self.log_message("ERROR", f"🚨 엑셀 저장 실패: {e}")
            QMessageBox.critical(self, "오류", f"엑셀 파일 저장 중 오류가 발생했습니다:\n{e}")

    def log_message(self, level, message):
        color_map = {"INFO": "#82C0FF", "SUCCESS": "#28A745", "WARNING": "orange", "ERROR": "#DC3545"}
        color = color_map.get(level, "#E0E0E0")
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f'<font color="{color}">[{timestamp}] - {level} - {message}</font>'
        self.log_widget.append(log_entry)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = KeywordApp()
    window.show()
    sys.exit(app.exec())