import sys
import os
import time
import json
import hashlib
import hmac
import base64
import webbrowser
from datetime import datetime, timedelta
from urllib.parse import quote
import pandas as pd
import requests
from dotenv import load_dotenv
from update_checker import UpdateChecker, get_current_version
import xml.etree.ElementTree as ET
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from multiprocessing import Process, Queue, freeze_support

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QMessageBox,
    QLineEdit, QCheckBox, QComboBox, QDateEdit, QRadioButton,
    QButtonGroup, QDialog, QCalendarWidget, QGroupBox
)
from PyQt6.QtGui import QIcon, QColor, QFont
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal, QDate, QPoint, QTimer

def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def load_stylesheet():
    """
    [UI 개선] Win11/Win10 체크박스 및 라디오버튼 디자인 통합
    OS 네이티브 테마의 간섭을 막고 모던 다크 테마를 기본으로 주입합니다.
    """
    base_qss = """
        /* 체크박스 디자인 통일 */
        QCheckBox { spacing: 8px; font-size: 9pt; }
        QCheckBox::indicator { width: 18px; height: 18px; border: 2px solid #4A4A4A; border-radius: 4px; background-color: #2E2E2E; }
        QCheckBox::indicator:hover { border: 2px solid #82C0FF; }
        QCheckBox::indicator:checked { background-color: #007BFF; border: 2px solid #007BFF; }
        
        /* 라디오 버튼 디자인 통일 */
        QRadioButton { spacing: 8px; font-size: 9pt; }
        QRadioButton::indicator { width: 18px; height: 18px; border: 2px solid #4A4A4A; border-radius: 9px; background-color: #2E2E2E; }
        QRadioButton::indicator:hover { border: 2px solid #82C0FF; }
        QRadioButton::indicator:checked { background-color: #007BFF; border: 2px solid #007BFF; }

        /* 그룹박스 및 텍스트 에딧 기본 스타일 */
        QGroupBox { font-size: 9pt; font-weight: bold; border: 1px solid #D0D0D0; border-radius: 5px; margin-top: 12px; }
        QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; left: 10px; }
        QTextEdit { background-color: #2E2E2E; color: #F0F0F0; border: 1px solid #4A4A4A; border-radius: 4px; padding: 5px; }
    """
    try:
        with open(resource_path("style.qss"), "r", encoding="utf-8") as f:
            return base_qss + f.read()
    except FileNotFoundError:
        return base_qss

def save_auth_process(queue: Queue):
    driver = None
    try:
        service = ChromeService(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        # [핵심 개선 1] Temp 폴더 대신 영구적인 LocalAppData 사용 (Win11 세션 휘발 방지)
        app_data_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "KeywordAppPro", "ChromeProfile")
        os.makedirs(app_data_path, exist_ok=True)
        options.add_argument(f'--user-data-dir={app_data_path}')

        driver = webdriver.Chrome(service=service, options=options)
        driver.get("https://nid.naver.com/nidlogin.login")
        
        WebDriverWait(driver, 300).until(
            lambda d: "nid.naver.com" not in d.current_url
        )
        
        storage_state = {"cookies": driver.get_cookies()}
        with open("auth.json", "w", encoding="utf-8") as f:
            json.dump(storage_state, f, ensure_ascii=False, indent=4)
        
        queue.put(("SUCCESS", "✅ 인증 정보(auth.json)가 성공적으로 갱신되었습니다!"))

    except Exception as e:
        queue.put(("ERROR", str(e)))
    finally:
        if driver:
            driver.quit()

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

# [핵심 개선 2] requests.Session() 주입을 통한 Connection Pooling (속도 향상)
def get_naver_ad_keywords(keyword: str, api_key: str, secret_key: str, customer_id: str, session: requests.Session = None):
    if not all([api_key, secret_key, customer_id]):
        raise ValueError("광고 API 키가 없습니다.")
    signature_generator = Signature()
    base_url, uri, method = "https://api.searchad.naver.com", "/keywordstool", "GET"
    timestamp = str(round(time.time() * 1000))
    signature = signature_generator.generate(timestamp, method, uri, secret_key)
    headers = {
        "Content-Type": "application/json; charset=UTF-8", "X-Timestamp": timestamp, 
        "X-API-KEY": api_key, "X-Customer": str(customer_id), "X-Signature": signature,
    }
    params = {"hintKeywords": keyword.replace(" ", ""), "showDetail": "1"}
    
    req_session = session or requests
    r = req_session.get(base_url + uri, params=params, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json().get("keywordList", [])

def get_blog_post_count(keyword: str, client_id: str, client_secret: str, session: requests.Session = None):
    if not all([client_id, client_secret]):
        raise ValueError("검색 API 키가 없습니다.")
    url = f"https://openapi.naver.com/v1/search/blog?query={quote(keyword)}"
    headers = {"X-Naver-Client-Id": client_id, "X-Naver-Client-Secret": client_secret}
    
    req_session = session or requests
    response = req_session.get(url, headers=headers)
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

class WeeklyCalendarWidget(QCalendarWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_week_start = None

    def set_selected_date(self, date):
        self.setSelectedDate(date)
        self.update_selection(date)

    def update_selection(self, date):
        start_of_week = date.addDays(-(date.dayOfWeek() - 1))
        self.selected_week_start = start_of_week
        self.updateCells()

    def paintCell(self, painter, rect, date):
        super().paintCell(painter, rect, date)
        if self.selected_week_start:
            end_of_week = self.selected_week_start.addDays(6)
            if self.selected_week_start <= date <= end_of_week:
                painter.setBrush(QColor(220, 235, 255, 100))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawRect(rect)

class MonthPickerDialog(QDialog):
    month_selected = pyqtSignal(QDate)

    def __init__(self, current_date, parent=None):
        super().__init__(parent)
        self.setWindowTitle("월 선택")
        self.current_year = current_date.year()
        self.selected_month = current_date.month()
        layout = QVBoxLayout(self)
        year_layout = QHBoxLayout()
        self.prev_year_btn = QPushButton("<")
        self.year_label = QLabel(str(self.current_year))
        self.year_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.next_year_btn = QPushButton(">")
        year_layout.addWidget(self.prev_year_btn)
        year_layout.addWidget(self.year_label)
        year_layout.addWidget(self.next_year_btn)
        layout.addLayout(year_layout)
        month_grid = QVBoxLayout()
        for r in range(4):
            row_layout = QHBoxLayout()
            for c in range(3):
                month = r * 3 + c + 1
                btn = QPushButton(f"{month}월")
                btn.clicked.connect(lambda _, m=month: self.select_month(m))
                row_layout.addWidget(btn)
            month_grid.addLayout(row_layout)
        layout.addLayout(month_grid)
        self.prev_year_btn.clicked.connect(self.prev_year)
        self.next_year_btn.clicked.connect(self.next_year)

    def prev_year(self):
        self.current_year -= 1; self.year_label.setText(str(self.current_year))

    def next_year(self):
        self.current_year += 1; self.year_label.setText(str(self.current_year))

    def select_month(self, month):
        self.month_selected.emit(QDate(self.current_year, month, 1)); self.accept()

class KeywordApp(QMainWindow):
    NAVER_TOPIC_TRENDS_API_URL = "https://creator-advisor.naver.com/api/v6/trend/category"
    NAVER_AGE_TRENDS_API_URL = "https://creator-advisor.naver.com/api/v6/trend/demo"
    AC_NAVER_URL = "https://ac.search.naver.com/nx/ac?q_enc=UTF-8&st=100&r_format=json&q="
    AC_GOOGLE_URL = "https://suggestqueries.google.com/complete/search?client=firefox&output=json&q="
    AC_DAUM_URL = "https://suggest.search.daum.net/sushi/opensearch/pc?q="
    BLOG_BASE_URL = "https://blog.naver.com"
    
    CATEGORIES = ["맛집", "국내여행", "세계여행", "비즈니스·경제", "패션·미용", "상품리뷰", "일상·생각", "건강·의학", "육아·결혼", "요리·레시피", "IT·컴퓨터", "교육·학문", "자동차", "인테리어·DIY", "스포츠", "취미", "방송", "게임", "스타·연예인", "영화", "공연·전시", "반려동물", "사회·정치", "드라마", "어학·외국어", "문학·책", "음악", "만화·애니", "좋은글·이미지", "미술·디자인", "원예·재배", "사진"]

    DEMO_CODES = ["f_05", "f_06", "f_04", "f_07", "f_03", "f_08", "m_07", "m_06", "m_05", "f_09", "m_08", "m_04", "m_09", "f_10", "f_11", "m_11", "m_03", "f_02", "m_10", "m_02", "f_01", "m_01"]
    
    DEMO_MAP = {
        'f_01': '0-12세 여자', 'f_02': '13-18세 여자', 'f_03': '19-24세 여자', 'f_04': '25-29세 여자', 'f_05': '30-34세 여자', 'f_06': '35-39세 여자', 'f_07': '40-44세 여자', 'f_08': '45-49세 여자', 'f_09': '50-54세 여자', 'f_10': '55-59세 여자', 'f_11': '60세- 여자',
        'm_01': '0-12세 남자', 'm_02': '13-18세 남자', 'm_03': '19-24세 남자', 'm_04': '25-29세 남자', 'm_05': '30-34세 남자', 'm_06': '35-39세 남자', 'm_07': '40-44세 남자', 'm_08': '45-49세 남자', 'm_09': '50-54세 남자', 'm_10': '55-59세 남자', 'm_11': '60세- 남자'
    }

    def __init__(self):
        super().__init__()
        self.current_version = get_current_version()
        self.setWindowTitle(f"키워드 분석기 Pro v{self.current_version}")
        self.update_checker = UpdateChecker(self.current_version)
        self.update_checker.update_available.connect(self.on_update_available)
        self.update_checker.error_occurred.connect(self.on_update_error)
        self.update_checker.start()
        self.setGeometry(100, 100, 1100, 800)
        self.setStyleSheet(load_stylesheet())
        load_dotenv("api.env")
        
        self.NAVER_ADS_API_KEY = os.getenv("NAVER_ADS_API_KEY")
        self.NAVER_ADS_API_SECRET = os.getenv("NAVER_ADS_API_SECRET")
        self.NAVER_ADS_CUSTOMER_ID = os.getenv("NAVER_ADS_CUSTOMER_ID")
        self.NAVER_SEARCH_CLIENT_ID = os.getenv("NAVER_SEARCH_CLIENT_ID")
        self.NAVER_SEARCH_CLIENT_SECRET = os.getenv("NAVER_SEARCH_CLIENT_SECRET")
        
        icon_path = resource_path("keyword_pro.ico")
        if os.path.exists(icon_path): self.setWindowIcon(QIcon(icon_path))
            
        self.thread, self.worker = None, None
        self.results_df, self.blog_views_df = None, None
        self.all_trend_data = []
        self.rank_sort_order = Qt.SortOrder.DescendingOrder
        self.currently_displayed_data = []
        self.bv_current_date = QDate.currentDate()
        self.bv_calendar_popup = None
        
        self.auth_process = None
        self.auth_queue = Queue()
        self.auth_check_timer = QTimer(self)
        self.auth_check_timer.timeout.connect(self.check_auth_process)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        top_level_layout = QVBoxLayout(central_widget)
        top_level_layout.setContentsMargins(5, 5, 5, 5)
        
        self.create_settings_bar(top_level_layout)
        self.tabs = QTabWidget()
        top_level_layout.addWidget(self.tabs)
        
        self.create_trend_fetch_tab()
        self.create_analysis_tab()
        self.create_autocomplete_tab()
        self.create_naver_main_tab()
        self.create_blog_views_tab()
        
        log_group_box = QGroupBox("📜 실시간 로그")
        log_layout = QVBoxLayout(log_group_box)
        log_layout.setContentsMargins(8, 8, 8, 8)
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setMinimumHeight(100)
        log_layout.addWidget(self.log_widget)
        top_level_layout.addWidget(log_group_box)

    def create_settings_bar(self, parent_layout):
        settings_frame = QWidget()
        settings_layout = QHBoxLayout(settings_frame)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        self.reset_button = QPushButton("화면 초기화")
        self.reset_button.clicked.connect(self.reset_ui)
        self.auth_button = QPushButton("인증 정보 갱신 (로그인)")
        self.auth_button.clicked.connect(self.start_auth_regeneration)
        settings_layout.addStretch()
        settings_layout.addWidget(self.reset_button)
        settings_layout.addWidget(self.auth_button)
        parent_layout.addWidget(settings_frame)

    def create_trend_fetch_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        control_widget = QWidget()
        control_layout = QHBoxLayout(control_widget)
        control_layout.setContentsMargins(0, 0, 0, 0)
        self.fetch_trends_button = QPushButton("주제별 트렌드")
        self.fetch_age_trends_button = QPushButton("연령별 트렌드")
        self.copy_to_analyzer_button = QPushButton("키워드 → 분석 탭으로 복사")
        self.category_filter_combo = QComboBox(); self.category_filter_combo.setFixedWidth(150)
        self.export_trends_excel_button = QPushButton("엑셀로 저장")
        
        self.copy_to_analyzer_button.setDisabled(True)
        self.category_filter_combo.setDisabled(True)
        self.export_trends_excel_button.setDisabled(True)
        
        control_layout.addWidget(self.fetch_trends_button)
        control_layout.addWidget(self.fetch_age_trends_button)
        control_layout.addWidget(self.copy_to_analyzer_button)
        control_layout.addWidget(QLabel("필터:"))
        control_layout.addWidget(self.category_filter_combo)
        control_layout.addWidget(self.export_trends_excel_button)
        control_layout.addStretch()
        
        status_container = QWidget(); status_container.setMinimumWidth(350)
        status_layout = QVBoxLayout(status_container); status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label_fetch = QLabel("버튼을 눌러 트렌드 키워드 수집을 시작하세요.")
        self.progress_bar_fetch = QProgressBar(); self.progress_bar_fetch.setFormat("수집 진행률: %p%")
        status_layout.addWidget(self.status_label_fetch)
        status_layout.addWidget(self.progress_bar_fetch)
        control_layout.addWidget(status_container)
        
        self.trend_table = QTableWidget()
        headers = ["카테고리", "키워드", "순위변동"]
        self.trend_table.setColumnCount(len(headers)); self.trend_table.setHorizontalHeaderLabels(headers)
        self.trend_table.setSortingEnabled(False)
        self.trend_table.horizontalHeader().sectionClicked.connect(self.sort_trend_table_by_rank_change)
        
        layout.addWidget(control_widget)
        layout.addWidget(self.trend_table)
        self.tabs.addTab(tab, "트렌드 키워드 수집")
        
        self.fetch_trends_button.clicked.connect(self.start_trend_fetching)
        self.fetch_age_trends_button.clicked.connect(self.start_age_trend_fetching)
        self.copy_to_analyzer_button.clicked.connect(self.copy_trends_to_analyzer)
        self.category_filter_combo.currentIndexChanged.connect(self.filter_trend_table)
        self.export_trends_excel_button.clicked.connect(self.export_trends_to_excel)

    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        placeholder_text = "--- 키워드를 입력하거나 붙여넣어 주세요 (한 줄에 하나씩) ---\n\n💡 '기회 지수'란?\n'월간 총검색량 ÷ 블로그 총문서수'로 계산되는 값으로,\n문서(공급) 대비 검색량(수요)이 얼마나 높은지를 나타내는 지표입니다."
        self.analysis_input_widget = QTextEdit()
        self.analysis_input_widget.setPlaceholderText(placeholder_text)
        
        control_layout = QHBoxLayout()
        self.analyze_button = QPushButton("기회지수 분석 시작")
        self.export_excel_button = QPushButton("엑셀로 저장"); self.export_excel_button.setDisabled(True)
        self.progress_bar_analysis = QProgressBar(); self.progress_bar_analysis.setFixedHeight(20)
        
        control_layout.addWidget(self.analyze_button); control_layout.addWidget(self.export_excel_button)
        control_layout.addStretch(); control_layout.addWidget(self.progress_bar_analysis)
        
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
        top_control_layout = QVBoxLayout(); top_control_layout.setContentsMargins(0, 0, 0, 10)
        
        input_layout = QHBoxLayout()
        self.autocomplete_input = QLineEdit(); self.autocomplete_input.setPlaceholderText("자동완성 키워드 입력...")
        input_layout.addWidget(QLabel("검색어:"), 0); input_layout.addWidget(self.autocomplete_input, 1)
        
        checkbox_layout = QHBoxLayout(); checkbox_layout.setContentsMargins(10, 5, 0, 5)
        checkbox_layout.addWidget(QLabel("검색 엔진:"), 0)
        self.cb_naver = QCheckBox("네이버"); self.cb_daum = QCheckBox("Daum"); self.cb_google = QCheckBox("Google")
        self.cb_naver.setChecked(True); self.cb_daum.setChecked(True); self.cb_google.setChecked(True)
        checkbox_layout.addWidget(self.cb_naver); checkbox_layout.addWidget(self.cb_daum); checkbox_layout.addWidget(self.cb_google)
        checkbox_layout.addStretch()
        
        button_layout = QHBoxLayout()
        self.autocomplete_search_button = QPushButton("자동완성 검색")
        self.autocomplete_copy_button = QPushButton("키워드 → 분석 탭으로 복사")
        button_layout.addWidget(self.autocomplete_search_button); button_layout.addWidget(self.autocomplete_copy_button); button_layout.addStretch()
        
        top_control_layout.addLayout(input_layout); top_control_layout.addLayout(checkbox_layout); top_control_layout.addLayout(button_layout)
        
        self.autocomplete_table = QTableWidget()
        self.autocomplete_table.setColumnCount(1); self.autocomplete_table.setHorizontalHeaderLabels(["자동완성 키워드"])
        self.autocomplete_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addLayout(top_control_layout); layout.addWidget(self.autocomplete_table)
        self.tabs.addTab(tab, "자동완성 키워드 수집")
        
        self.autocomplete_search_button.clicked.connect(self.start_autocomplete_search)
        self.autocomplete_input.returnPressed.connect(self.start_autocomplete_search)
        self.autocomplete_copy_button.clicked.connect(self.copy_autocomplete_to_analyzer)

    def create_naver_main_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        control_layout = QHBoxLayout()
        self.fetch_main_content_button = QPushButton("유입콘텐츠 가져오기")
        hint_label = QLabel("💡 더블클릭으로 해당 링크 이동"); hint_label.setStyleSheet("color: #6C757D; font-size: 9pt; padding-left: 10px;")
        control_layout.addWidget(self.fetch_main_content_button); control_layout.addWidget(hint_label); control_layout.addStretch()
        
        self.naver_main_table = QTableWidget()
        self.naver_main_table.setColumnCount(2); self.naver_main_table.setHorizontalHeaderLabels(["순위", "제목"])
        self.naver_main_table.verticalHeader().setVisible(False)
        self.naver_main_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.naver_main_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.naver_main_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        layout.addLayout(control_layout); layout.addWidget(self.naver_main_table)
        self.tabs.addTab(tab, "네이버 메인 유입 콘텐츠")
        
        self.fetch_main_content_button.clicked.connect(self.start_fetch_naver_main)
        self.naver_main_table.cellDoubleClicked.connect(self.open_browser_link)

    def create_blog_views_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        top_control_layout = QHBoxLayout(); top_control_layout.setContentsMargins(0, 0, 0, 10)
        self.bv_prev_btn = QPushButton("<"); self.bv_date_label = QLabel(""); self.bv_date_label.setFont(QFont("Arial", 10))
        self.bv_calendar_btn = QPushButton("📅"); self.bv_next_btn = QPushButton(">")
        self.bv_prev_btn.setFixedSize(30, 30); self.bv_next_btn.setFixedSize(30, 30); self.bv_calendar_btn.setFixedSize(30, 30)
        
        self.bv_mode_group = QButtonGroup(self)
        self.bv_radio_daily = QPushButton("일간"); self.bv_radio_weekly = QPushButton("주간"); self.bv_radio_monthly = QPushButton("월간")
        for btn, idx in zip([self.bv_radio_daily, self.bv_radio_weekly, self.bv_radio_monthly], [0, 1, 2]):
            btn.setCheckable(True); self.bv_mode_group.addButton(btn, idx)
            
        top_control_layout.addWidget(self.bv_prev_btn); top_control_layout.addWidget(self.bv_date_label)
        top_control_layout.addWidget(self.bv_calendar_btn); top_control_layout.addWidget(self.bv_next_btn); top_control_layout.addStretch(1)
        top_control_layout.addWidget(self.bv_radio_daily); top_control_layout.addWidget(self.bv_radio_weekly); top_control_layout.addWidget(self.bv_radio_monthly)
        
        bottom_control_layout = QHBoxLayout(); bottom_control_layout.setContentsMargins(0, 5, 0, 0)
        self.fetch_blog_views_button = QPushButton("조회수 순위 가져오기")
        self.export_blog_views_button = QPushButton("엑셀로 저장"); self.export_blog_views_button.setDisabled(True)
        bottom_control_layout.addWidget(self.fetch_blog_views_button); bottom_control_layout.addWidget(self.export_blog_views_button); bottom_control_layout.addStretch()
        
        status_container = QWidget(); status_container.setMinimumWidth(350)
        status_layout = QVBoxLayout(status_container); status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label_bv = QLabel("조회할 기간을 선택하고 버튼을 눌러주세요.")
        self.progress_bar_bv = QProgressBar(); self.progress_bar_bv.setFormat("진행률: %p%")
        status_layout.addWidget(self.status_label_bv); status_layout.addWidget(self.progress_bar_bv)
        bottom_control_layout.addWidget(status_container)
        
        self.blog_views_table = QTableWidget()
        self.blog_views_table.setColumnCount(4); self.blog_views_table.setHorizontalHeaderLabels(["날짜", "순위", "조회수", "제목"])
        
        layout.addLayout(top_control_layout); layout.addLayout(bottom_control_layout); layout.addWidget(self.blog_views_table)
        self.tabs.addTab(tab, "블로그 조회수 순위")
        
        self.bv_mode_group.buttonClicked.connect(self.bv_on_mode_changed)
        self.bv_prev_btn.clicked.connect(self.bv_navigate_prev)
        self.bv_next_btn.clicked.connect(self.bv_navigate_next)
        self.bv_calendar_btn.clicked.connect(self.bv_show_calendar_picker)
        self.fetch_blog_views_button.clicked.connect(self.start_fetch_blog_views)
        self.export_blog_views_button.clicked.connect(self.export_blog_views_to_excel)
        self.blog_views_table.cellDoubleClicked.connect(self.open_blog_view_link)
        self.bv_radio_daily.setChecked(True); self.bv_on_mode_changed()

    # --- UI Events & Helpers ---
    def bv_on_mode_changed(self):
        cid = self.bv_mode_group.checkedId()
        today = QDate.currentDate()
        if cid == 0: self.bv_current_date = today
        elif cid == 1: self.bv_current_date = today.addDays(-7)
        elif cid == 2: self.bv_current_date = today.addMonths(-1)
        self.bv_update_date_display()

    def bv_update_date_display(self):
        cid = self.bv_mode_group.checkedId()
        d = self.bv_current_date
        if cid == 0: self.bv_date_label.setText(d.toString("yyyy.MM.dd."))
        elif cid == 1:
            s = d.addDays(-(d.dayOfWeek() - 1))
            self.bv_date_label.setText(f"{s.toString('yyyy.MM.dd.')} ~ {s.addDays(6).toString('yyyy.MM.dd.')}")
        elif cid == 2: self.bv_date_label.setText(d.toString("yyyy.MM."))

    def bv_navigate_prev(self):
        cid = self.bv_mode_group.checkedId()
        self.bv_current_date = self.bv_current_date.addDays(-1) if cid == 0 else self.bv_current_date.addDays(-7) if cid == 1 else self.bv_current_date.addMonths(-1)
        self.bv_update_date_display()

    def bv_navigate_next(self):
        cid = self.bv_mode_group.checkedId()
        self.bv_current_date = self.bv_current_date.addDays(1) if cid == 0 else self.bv_current_date.addDays(7) if cid == 1 else self.bv_current_date.addMonths(1)
        self.bv_update_date_display()

    def bv_show_calendar_picker(self):
        if self.bv_mode_group.checkedId() == 2:
            dialog = MonthPickerDialog(self.bv_current_date, self)
            dialog.month_selected.connect(self.bv_on_date_selected); dialog.exec(); return
        if not self.bv_calendar_popup:
            self.bv_calendar_popup = WeeklyCalendarWidget()
            self.bv_calendar_popup.setWindowFlags(Qt.WindowType.Popup)
            self.bv_calendar_popup.clicked.connect(self.bv_on_date_selected)
        self.bv_calendar_popup.set_selected_date(self.bv_current_date)
        self.bv_calendar_popup.move(self.bv_calendar_btn.mapToGlobal(QPoint(0, self.bv_calendar_btn.height())))
        self.bv_calendar_popup.show()

    def bv_on_date_selected(self, date):
        self.bv_current_date = date; self.bv_update_date_display()
        if self.bv_calendar_popup: self.bv_calendar_popup.hide()

    def reset_ui(self):
        self.trend_table.setRowCount(0); self.all_trend_data = []; self.category_filter_combo.clear()
        self.category_filter_combo.setDisabled(True); self.export_trends_excel_button.setDisabled(True); self.copy_to_analyzer_button.setDisabled(True)
        self.rank_sort_order = Qt.SortOrder.DescendingOrder
        self.trend_table.horizontalHeader().setSortIndicatorShown(False)
        self.status_label_fetch.setText("버튼을 눌러 트렌드 키워드 수집을 시작하세요."); self.progress_bar_fetch.setValue(0)
        self.analysis_input_widget.clear(); self.result_table.setRowCount(0); self.progress_bar_analysis.setValue(0); self.export_excel_button.setDisabled(True)
        self.autocomplete_input.clear(); self.autocomplete_table.setRowCount(0)
        self.cb_naver.setChecked(True); self.cb_daum.setChecked(True); self.cb_google.setChecked(True)
        self.bv_on_mode_changed(); self.blog_views_table.setRowCount(0); self.status_label_bv.setText("조회할 기간을 선택하고 버튼을 눌러주세요."); self.progress_bar_bv.setValue(0); self.export_blog_views_button.setDisabled(True)
        self.log_message("INFO", "모든 작업 공간이 초기화되었습니다.")

    def run_worker(self, worker_fn, finish_slot, progress_bar=None, **kwargs):
        self.thread = QThread()
        self.worker = Worker(worker_fn, **kwargs)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(finish_slot)
        self.worker.error.connect(self.on_worker_error)
        if progress_bar: self.worker.progress.connect(progress_bar.setValue)
        self.worker.log.connect(self.log_message)
        self.worker.finished.connect(self.thread.quit); self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.error.connect(self.thread.quit); self.worker.error.connect(self.worker.deleteLater)
        self.thread.start()

    def start_trend_fetching(self):
        self.fetch_trends_button.setDisabled(True); self.fetch_age_trends_button.setDisabled(True); self.category_filter_combo.setDisabled(True)
        self.copy_to_analyzer_button.setDisabled(True); self.export_trends_excel_button.setDisabled(True)
        self.status_label_fetch.setText("트렌드 수집 중..."); self.trend_table.setRowCount(0); self.progress_bar_fetch.setValue(0)
        self.run_worker(self.fetch_trends_worker, self.on_trend_fetching_finished, progress_bar=self.progress_bar_fetch)

    def start_age_trend_fetching(self):
        self.fetch_trends_button.setDisabled(True); self.fetch_age_trends_button.setDisabled(True); self.category_filter_combo.setDisabled(True)
        self.copy_to_analyzer_button.setDisabled(True); self.export_trends_excel_button.setDisabled(True)
        self.status_label_fetch.setText("트렌드 수집 중..."); self.trend_table.setRowCount(0); self.progress_bar_fetch.setValue(0)
        self.run_worker(self.fetch_age_trends_worker, self.on_age_trend_fetching_finished, progress_bar=self.progress_bar_fetch)

    def start_competition_analysis(self):
        if not all([self.NAVER_ADS_API_KEY, self.NAVER_ADS_API_SECRET, self.NAVER_ADS_CUSTOMER_ID, self.NAVER_SEARCH_CLIENT_ID, self.NAVER_SEARCH_CLIENT_SECRET]):
            QMessageBox.critical(self, "API 키 오류", "하나 이상의 API 키가 없습니다. 'api.env' 파일을 확인해주세요.")
            return
        keywords = [kw.strip() for kw in self.analysis_input_widget.toPlainText().strip().split("\n") if kw.strip()]
        if not keywords: QMessageBox.warning(self, "경고", "분석할 키워드를 입력하거나 붙여넣어 주세요."); return
        self.analyze_button.setDisabled(True); self.export_excel_button.setDisabled(True)
        self.result_table.setRowCount(0); self.progress_bar_analysis.setValue(0)
        self.run_worker(self.analyze_competition_worker, self.on_analysis_finished, progress_bar=self.progress_bar_analysis, keywords=keywords)

    def start_auth_regeneration(self):
        self.auth_button.setDisabled(True)
        self.log_message("INFO", "🔒 사용자 인증 갱신 프로세스를 시작합니다...")
        if self.auth_process and self.auth_process.is_alive(): self.auth_process.terminate()
        self.auth_process = Process(target=save_auth_process, args=(self.auth_queue,))
        self.auth_process.start()
        self.auth_check_timer.start(1000)

    def check_auth_process(self):
        if not self.auth_queue.empty():
            status, message = self.auth_queue.get()
            if status == "SUCCESS":
                self.log_message("SUCCESS", message); QMessageBox.information(self, "성공", message)
            else:
                self.log_message("ERROR", f"인증 중 오류 발생: {message}"); QMessageBox.critical(self, "인증 오류", message)
            self.auth_check_timer.stop(); self.auth_button.setDisabled(False)
        elif self.auth_process and not self.auth_process.is_alive():
            self.log_message("ERROR", "인증 프로세스가 비정상 종료됨."); QMessageBox.warning(self, "실패", "프로세스 완료 실패"); self.auth_check_timer.stop(); self.auth_button.setDisabled(False)

    def start_autocomplete_search(self):
        kw = self.autocomplete_input.text().strip()
        if not kw: QMessageBox.warning(self, "입력 오류", "검색어를 입력해주세요."); return
        engines = [name for cb, name in [(self.cb_naver, "naver"), (self.cb_daum, "daum"), (self.cb_google, "google")] if cb.isChecked()]
        if not engines: QMessageBox.warning(self, "선택 오류", "검색 엔진을 하나 이상 선택해주세요."); return
        self.autocomplete_search_button.setDisabled(True); self.autocomplete_table.setRowCount(0)
        self.run_worker(self.autocomplete_worker, self.on_autocomplete_finished, keyword=kw, engines=engines)

    def start_fetch_naver_main(self):
        self.fetch_main_content_button.setDisabled(True); self.log_message("INFO", "네이버 메인 수집 시작..."); self.naver_main_table.setRowCount(0)
        self.run_worker(self.fetch_naver_main_worker, self.on_naver_main_finished)

    def start_fetch_blog_views(self):
        cid = self.bv_mode_group.checkedId()
        time_dim = {0: "DATE", 1: "WEEK", 2: "MONTH"}[cid]
        d = self.bv_current_date
        if cid == 0: sd = ed = d.toPyDate()
        elif cid == 1:
            sw = d.addDays(-(d.dayOfWeek() - 1))
            sd, ed = sw.toPyDate(), sw.addDays(6).toPyDate()
        elif cid == 2:
            sd, ed = QDate(d.year(), d.month(), 1).toPyDate(), QDate(d.year(), d.month(), d.daysInMonth()).toPyDate()
        self.fetch_blog_views_button.setDisabled(True); self.export_blog_views_button.setDisabled(True)
        self.status_label_bv.setText(f"수집 중..."); self.blog_views_table.setRowCount(0); self.progress_bar_bv.setValue(0)
        self.run_worker(self.fetch_blog_views_worker, self.on_fetch_blog_views_finished, progress_bar=self.progress_bar_bv, start_date=sd, end_date=ed, time_dimension=time_dim)

    # --- Workers ---
    def fetch_trends_worker(self, worker_instance):
        worker_instance.log.emit("INFO", "📈 주제별 트렌드 키워드 수집을 시작합니다...")
        cookies = load_cookies_from_auth_file()
        if not cookies: raise ValueError("'auth.json' 파일을 찾을 수 없습니다. 인증 갱신 필요.")
        target_date_str = (datetime.now() - timedelta(days=2 if datetime.now().hour < 8 else 1)).strftime("%Y-%m-%d")
        
        # [핵심 개선 2 적용] 세션을 통한 커넥션 유지
        with requests.Session() as session:
            try:
                resp = session.get(f"{self.NAVER_TOPIC_TRENDS_API_URL}?categories={quote(self.CATEGORIES[0])}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=1&service=naver_blog", cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"}, timeout=10)
                if resp.status_code != 200: raise ValueError(f"인증 확인 실패. HTTP {resp.status_code}")
            except Exception as e: raise ValueError(f"API 네트워크 오류: {e}")
            
            all_trends_data = []
            for i, cat in enumerate(self.CATEGORIES):
                worker_instance.progress.emit(int((i + 1) / len(self.CATEGORIES) * 100))
                try:
                    resp = session.get(f"{self.NAVER_TOPIC_TRENDS_API_URL}?categories={quote(cat)}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=20&service=naver_blog", cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"})
                    if resp.status_code == 200 and (d := resp.json().get("data")) and d[0].get("queryList"):
                        for item in d[0]["queryList"]:
                            rc = item.get("rankChange")
                            all_trends_data.append({"카테고리": cat, "키워드": item.get("query", "N/A"), "순위변동": int(rc) if rc is not None else None})
                except Exception: pass
                time.sleep(0.2)
        return all_trends_data

    def fetch_age_trends_worker(self, worker_instance):
        cookies = load_cookies_from_auth_file()
        if not cookies: raise ValueError("'auth.json' 에러. 인증 갱신 요망.")
        target_date_str = (datetime.now() - timedelta(days=2 if datetime.now().hour < 8 else 1)).strftime("%Y-%m-%d")
        all_age_trends = []
        
        with requests.Session() as session:
            for i, code in enumerate(self.DEMO_CODES):
                worker_instance.progress.emit(int((i + 1) / len(self.DEMO_CODES) * 100))
                gender, age_code = code.split('_')
                group_name = self.DEMO_MAP.get(code, code)
                params = {'age': age_code, 'date': target_date_str, 'gender': gender, 'hasRankChange': 'true', 'interval': 'day', 'limit': 20, 'metric': 'cv', 'service': 'naver_blog'}
                try:
                    resp = session.get(self.NAVER_AGE_TRENDS_API_URL, params=params, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"})
                    if resp.status_code == 200 and (ql := resp.json().get("data", [{}])[0].get("queryList")):
                        for item in ql:
                            rc = item.get("rankChange")
                            all_age_trends.append({"연령대": group_name, "키워드": item.get("query", "N/A"), "순위변동": int(rc) if rc is not None else None})
                except Exception: pass
                time.sleep(0.2)
        return all_age_trends

    def analyze_competition_worker(self, worker_instance, keywords):
        unique_kw = list(dict.fromkeys(keywords))
        analysis_results = []
        
        # [핵심 개선 2 적용] 세션을 통한 커넥션 유지로 속도 비약적 향상
        with requests.Session() as session:
            for i, original_kw in enumerate(unique_kw):
                worker_instance.progress.emit(int((i + 1) / len(unique_kw) * 100))
                kw_api = original_kw.replace(" ", "")
                if not kw_api: continue
                try:
                    ad_data = get_naver_ad_keywords(kw_api, self.NAVER_ADS_API_KEY, self.NAVER_ADS_API_SECRET, self.NAVER_ADS_CUSTOMER_ID, session)
                    post_count = get_blog_post_count(kw_api, self.NAVER_SEARCH_CLIENT_ID, self.NAVER_SEARCH_CLIENT_SECRET, session)
                    pc, mob = 0, 0
                    if ad_data and (m := next((it for it in ad_data if it["relKeyword"] == kw_api), None)):
                        pc_str, mob_str = str(m.get("monthlyPcQcCnt", 0)), str(m.get("monthlyMobileQcCnt", 0))
                        pc = 5 if "<" in pc_str else int(pc_str)
                        mob = 5 if "<" in mob_str else int(mob_str)
                    tot_search = pc + mob
                    opp_idx = (tot_search / post_count) if post_count > 0 else 0
                    cat = "🏆 황금" if opp_idx >= 0.2 else "✨ 매력" if opp_idx >= 0.05 and tot_search >= 1000 else "일반"
                    analysis_results.append({"분류": cat, "키워드": original_kw, "총검색량": tot_search, "총문서수": post_count, "기회지수": round(opp_idx, 2)})
                except Exception as e: worker_instance.log.emit("ERROR", f"'{original_kw}' 오류: {e}")
                time.sleep(0.15)
        return pd.DataFrame(analysis_results)

    def fetch_naver_main_worker(self, worker_instance):
        cookies = load_cookies_from_auth_file()
        if not cookies: raise ValueError("인증 필요.")
        url = "https://creator-advisor.naver.com/api/v6/trend/main-inflow-content-ranks"
        params = {"service": "naver_blog", "date": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d"), "interval": "day"}
        try:
            r = requests.get(url, params=params, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"}, timeout=10)
            r.raise_for_status()
            return [{"rank": str(i), "title": item.get("title"), "link": item.get("url")} for i, item in enumerate(r.json().get("data", []), 1)]
        except Exception as e: raise ValueError(f"API 요청 실패: {e}")

    def fetch_blog_views_worker(self, worker_instance, start_date, end_date, time_dimension):
        cookies = load_cookies_from_auth_file()
        if not cookies: raise ValueError("인증 필요.")
        dates = [start_date + timedelta(days=i) for i in range(0, (end_date - start_date).days + 1, 7 if time_dimension == "WEEK" else 1)] if time_dimension in ["DATE", "WEEK"] else [start_date]
        all_view = []
        with requests.Session() as session:
            for i, d in enumerate(dates):
                worker_instance.progress.emit(int((i + 1) / len(dates) * 100))
                ds = d.strftime("%Y-%m-%d")
                url = f"https://blog.stat.naver.com/api/blog/rank/cvContentPc?timeDimension={time_dimension}&startDate={ds}"
                try:
                    r = session.get(url, cookies=cookies, headers={"Referer": "https://blog.stat.naver.com/"}, timeout=10)
                    if r.status_code == 200 and (rows := r.json().get("result", {}).get("statDataList", [{}])[0].get("data", {}).get("rows")):
                        for dt, rank, cv, title, uri in zip(rows.get("date", []), rows.get("rank", []), rows.get("cv", []), rows.get("title", []), rows.get("uri", [])):
                            all_view.append({"날짜": dt, "순위": rank, "조회수": cv, "제목": title, "게시물_주소": uri if uri.startswith("http") else f"{self.BLOG_BASE_URL}{uri}"})
                except Exception: pass
                time.sleep(0.2)
        return all_view

    def autocomplete_worker(self, worker_instance, keyword, engines):
        res = set()
        with requests.Session() as s:
            if "naver" in engines:
                try:
                    r = s.get(self.AC_NAVER_URL + quote(keyword), headers={"User-Agent": "Mozilla"}, timeout=5)
                    if r.status_code == 200 and (items := r.json().get("items")):
                        for i in items[0]: res.add(i[0])
                except Exception: pass
            if "daum" in engines:
                try:
                    r = s.get(self.AC_DAUM_URL + quote(keyword), headers={"User-Agent": "Mozilla"}, timeout=5)
                    if "json" in r.headers.get("Content-Type", "").lower():
                        d = r.json()
                        if isinstance(d, list) and len(d) > 1:
                            for it in d[1]: res.add(it.strip())
                    else:
                        for it in ET.fromstring(r.content).findall(".//item/keyword"):
                            if it.text: res.add(it.text.strip())
                except Exception: pass
            if "google" in engines:
                try:
                    r = s.get(self.AC_GOOGLE_URL + quote(keyword), headers={"User-Agent": "Mozilla"}, timeout=5)
                    if r.status_code == 200 and isinstance((d := r.json()), list) and len(d) > 1:
                        for it in d[1]: res.add(it.strip())
                except Exception: pass
        return sorted(list(res))

    # --- Callbacks ---
    def on_trend_fetching_finished(self, trend_data):
        self._finish_trend_fetching_ui(trend_data, "카테고리")

    def on_age_trend_fetching_finished(self, age_trend_data):
        self._finish_trend_fetching_ui(age_trend_data, "연령대")

    def _finish_trend_fetching_ui(self, data, first_col):
        self.fetch_trends_button.setDisabled(False); self.fetch_age_trends_button.setDisabled(False); self.progress_bar_fetch.setValue(100)
        if not data: self.status_label_fetch.setText("❌ 수집 실패."); return
        self.all_trend_data = data; self.currently_displayed_data = data
        self.status_label_fetch.setText(f"✅ {len(data)}개 완료!"); self.trend_table.setHorizontalHeaderLabels([first_col, "키워드", "순위변동"])
        self.category_filter_combo.blockSignals(True); self.category_filter_combo.clear()
        self.category_filter_combo.addItem("전체 보기"); self.category_filter_combo.addItems(sorted(list(set(it[first_col] for it in data))))
        self.category_filter_combo.blockSignals(False); self.populate_trend_table(data)
        self.copy_to_analyzer_button.setDisabled(False); self.category_filter_combo.setDisabled(False); self.export_trends_excel_button.setDisabled(False)

    def populate_trend_table(self, data):
        self.trend_table.setRowCount(len(data))
        if not data: return
        fk = list(data[0].keys())[0]
        for row, it in enumerate(data):
            c_it, k_it, rc = QTableWidgetItem(str(it[fk])), QTableWidgetItem(str(it["키워드"])), it["순위변동"]
            r_it = QTableWidgetItem("NEW" if rc is None else ("-" if rc == 0 else f"{rc:g}"))
            r_it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if rc is None: r_it.setForeground(QColor("#28A745"))
            elif rc > 0: r_it.setForeground(QColor("#DC3545"))
            elif rc < 0: r_it.setForeground(QColor("#007BFF"))
            self.trend_table.setItem(row, 0, c_it); self.trend_table.setItem(row, 1, k_it); self.trend_table.setItem(row, 2, r_it)
        self.trend_table.resizeColumnsToContents()

    def sort_trend_table_by_rank_change(self, idx):
        if idx != 2 or not self.currently_displayed_data: return
        self.rank_sort_order = Qt.SortOrder.DescendingOrder if self.rank_sort_order == Qt.SortOrder.AscendingOrder else Qt.SortOrder.AscendingOrder
        new_items = [i for i in self.currently_displayed_data if i["순위변동"] is None]
        other = sorted([i for i in self.currently_displayed_data if i["순위변동"] is not None], key=lambda x: x["순위변동"], reverse=(self.rank_sort_order == Qt.SortOrder.DescendingOrder))
        self.populate_trend_table(new_items + other)
        self.trend_table.horizontalHeader().setSortIndicatorShown(True); self.trend_table.horizontalHeader().setSortIndicator(2, self.rank_sort_order)

    def filter_trend_table(self):
        cat = self.category_filter_combo.currentText()
        if not self.all_trend_data: return
        fk = list(self.all_trend_data[0].keys())[0]
        self.currently_displayed_data = self.all_trend_data if cat == "전체 보기" else [i for i in self.all_trend_data if i[fk] == cat]
        self.populate_trend_table(self.currently_displayed_data)

    def on_analysis_finished(self, df):
        self.analyze_button.setDisabled(False); self.progress_bar_analysis.setValue(100)
        if df is not None and not df.empty:
            self.results_df = df.sort_values(by="기회지수", ascending=False)
            self.result_table.setRowCount(len(self.results_df))
            for r, row in enumerate(self.results_df.itertuples()):
                self.result_table.setItem(r, 0, QTableWidgetItem(str(row.분류)))
                self.result_table.setItem(r, 1, QTableWidgetItem(str(row.키워드)))
                self.result_table.setItem(r, 2, QTableWidgetItem(f"{row.총검색량:,}"))
                self.result_table.setItem(r, 3, QTableWidgetItem(f"{row.총문서수:,}"))
                self.result_table.setItem(r, 4, QTableWidgetItem(f"{row.기회지수:,}"))
            self.result_table.resizeColumnsToContents(); self.export_excel_button.setDisabled(False)

    def on_autocomplete_finished(self, kw):
        self.autocomplete_search_button.setDisabled(False); self.autocomplete_table.setRowCount(len(kw))
        for r, k in enumerate(kw): self.autocomplete_table.setItem(r, 0, QTableWidgetItem(k))
        self.autocomplete_table.resizeColumnsToContents()

    def on_naver_main_finished(self, res):
        self.fetch_main_content_button.setDisabled(False); self.naver_main_table.setRowCount(len(res))
        for r, it in enumerate(res):
            ri, ti = QTableWidgetItem(it["rank"]), QTableWidgetItem(it["title"])
            ri.setTextAlignment(Qt.AlignmentFlag.AlignCenter); ti.setData(Qt.ItemDataRole.UserRole, it["link"])
            self.naver_main_table.setItem(r, 0, ri); self.naver_main_table.setItem(r, 1, ti)

    def on_fetch_blog_views_finished(self, data):
        self.fetch_blog_views_button.setDisabled(False); self.progress_bar_bv.setValue(100)
        self.blog_views_table.horizontalHeaderItem(0).setText("날짜" if self.bv_mode_group.checkedId() == 0 else "기간")
        if not data: self.status_label_bv.setText("❌ 결과 없음."); return
        self.blog_views_df = pd.DataFrame(data); self.status_label_bv.setText(f"✅ {len(data)}개 완료!")
        self.blog_views_table.setRowCount(len(data))
        for r, row in enumerate(self.blog_views_df.itertuples()):
            self.blog_views_table.setItem(r, 0, QTableWidgetItem(str(row.날짜)))
            self.blog_views_table.setItem(r, 1, QTableWidgetItem(str(row.순위)))
            self.blog_views_table.setItem(r, 2, QTableWidgetItem(f"{row.조회수:,}"))
            ti = QTableWidgetItem(str(row.제목)); ti.setData(Qt.ItemDataRole.UserRole, str(row.게시물_주소))
            self.blog_views_table.setItem(r, 3, ti)
        self.blog_views_table.resizeColumnsToContents(); self.blog_views_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.export_blog_views_button.setDisabled(False)

    def on_worker_error(self, err):
        self.log_message("ERROR", f"오류: {err.splitlines()[0]}"); QMessageBox.critical(self, "오류", err.splitlines()[0])
        for btn in [self.fetch_trends_button, self.fetch_age_trends_button, self.analyze_button, self.auth_button, self.autocomplete_search_button, self.fetch_main_content_button, self.fetch_blog_views_button]: btn.setDisabled(False)

    # --- Utils ---
    def open_browser_link(self, r, c):
        if c == 1 and (link := self.naver_main_table.item(r, c).data(Qt.ItemDataRole.UserRole)): webbrowser.open(link)

    def open_blog_view_link(self, r, c):
        if c == 3 and (link := self.blog_views_table.item(r, c).data(Qt.ItemDataRole.UserRole)): webbrowser.open(link)

    def copy_trends_to_analyzer(self):
        if self.trend_table.rowCount() > 0:
            self.analysis_input_widget.setPlainText("\n".join(self.trend_table.item(r, 1).text() for r in range(self.trend_table.rowCount())))
            self.tabs.setCurrentIndex(1); self.log_message("INFO", "복사 완료.")

    def copy_autocomplete_to_analyzer(self):
        if (rows := self.autocomplete_table.rowCount()) > 0:
            kws = "\n".join(self.autocomplete_table.item(r, 0).text() for r in range(rows))
            cur = self.analysis_input_widget.toPlainText().strip()
            self.analysis_input_widget.setPlainText(f"{cur}\n{kws}".strip()); self.tabs.setCurrentIndex(1)

    def export_trends_to_excel(self):
        if self.trend_table.rowCount() == 0: return
        os.makedirs("output", exist_ok=True)
        df = pd.DataFrame([{self.trend_table.horizontalHeaderItem(0).text(): self.trend_table.item(r, 0).text(), "키워드": self.trend_table.item(r, 1).text(), "순위변동": self.trend_table.item(r, 2).text()} for r in range(self.trend_table.rowCount())])
        df.to_excel(os.path.join("output", f"trend_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"), index=False); QMessageBox.information(self, "성공", "저장 완료.")

    def export_to_excel(self):
        if self.results_df is None or self.results_df.empty: return
        os.makedirs("output", exist_ok=True); self.results_df[self.results_df["분류"] != "일반"].to_excel(os.path.join("output", f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"), index=False); QMessageBox.information(self, "성공", "저장 완료.")

    def export_blog_views_to_excel(self):
        if getattr(self, "blog_views_df", None) is None or self.blog_views_df.empty: return
        os.makedirs("output", exist_ok=True); self.blog_views_df.to_excel(os.path.join("output", f"views_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"), index=False); QMessageBox.information(self, "성공", "저장 완료.")

    def log_message(self, level, msg):
        c = {"INFO": "#82C0FF", "SUCCESS": "#28A745", "WARNING": "orange", "ERROR": "#DC3545"}.get(level, "#E0E0E0")
        self.log_widget.append(f'<font color="{c}">[{datetime.now().strftime("%H:%M:%S")}] - {level} - {msg}</font>')

    def on_update_available(self, v): self.log_message("INFO", f"현재 버전: v{v}")
    def on_update_error(self, err): self.log_message("WARNING", f"업데이트 확인 오류: {err}")
    def closeEvent(self, e):
        if self.auth_process and self.auth_process.is_alive(): self.auth_process.terminate()
        e.accept()

if __name__ == "__main__":
    freeze_support()
    app = QApplication(sys.argv)
    window = KeywordApp()
    window.show()
    sys.exit(app.exec())