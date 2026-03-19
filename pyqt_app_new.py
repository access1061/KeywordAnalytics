import sys
import os
import time
import json
import hashlib
import hmac
import base64
import webbrowser
import random
import sqlite3
import threading
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
from multiprocessing import freeze_support

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QPushButton,
    QLabel,
    QTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QMessageBox,
    QLineEdit,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QRadioButton,
    QButtonGroup,
    QDialog,
    QCalendarWidget,
    QGroupBox,
)
from PyQt6.QtGui import QIcon, QColor, QFont
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal, QDate, QPoint, QTimer


def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

<<<<<<< HEAD

# OS 독립적인 앱 데이터 경로 생성
def get_app_data_path():
    if sys.platform == "win32":
        return os.path.join(
            os.getenv("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local")),
            "KeywordAppPro",
        )
    elif sys.platform == "darwin":
        return os.path.join(
            os.path.expanduser("~/Library/Application Support"), "KeywordAppPro"
        )
    else:
        return os.path.join(os.path.expanduser("~/.local/share"), "KeywordAppPro")


def load_stylesheet():
    base_qss = """
        QCheckBox { spacing: 8px; font-size: 9pt; }
        QCheckBox::indicator { width: 18px; height: 18px; border: 2px solid #4A4A4A; border-radius: 4px; background-color: #2E2E2E; }
        QCheckBox::indicator:hover { border: 2px solid #82C0FF; }
        QCheckBox::indicator:checked { background-color: #007BFF; border: 2px solid #007BFF; }
        QGroupBox { font-size: 9pt; font-weight: bold; border: 1px solid #D0D0D0; border-radius: 5px; margin-top: 12px; }
        QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; left: 10px; }
        QTextEdit { background-color: #2E2E2E; color: #F0F0F0; border: 1px solid #4A4A4A; border-radius: 4px; padding: 5px; }
        
        QPushButton[cached="true"] {
            background-color: #17A2B8;
            color: white;
            font-weight: bold;
        }
    """
=======
def load_stylesheet():
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
    try:
        with open(resource_path("style.qss"), "r", encoding="utf-8") as f:
            return base_qss + f.read()
    except FileNotFoundError:
        return ""

def save_auth_process(queue: Queue):
    driver = None
    try:
        # ▼▼▼ [수정] ChromeDriver를 자동으로 다운로드하고 경로를 설정합니다 ▼▼▼
        service = ChromeService(ChromeDriverManager().install())
        # ▲▲▲ 수정 완료 ▲▲▲
        
        options = webdriver.ChromeOptions()
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        temp_profile_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp", "ChromeProfileForKeywordApp")
        options.add_argument(f'--user-data-dir={temp_profile_path}')

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

# (이하 나머지 코드는 이전과 동일합니다)

# --- API 관련 헬퍼 클래스 및 함수 ---
class Signature:
    @staticmethod
    def generate(timestamp, method, uri, secret_key):
        message = f"{timestamp}.{method}.{uri}"
        hash_val = hmac.new(
            bytes(secret_key, "utf-8"), bytes(message, "utf-8"), hashlib.sha256
        )
        return base64.b64encode(hash_val.digest())


<<<<<<< HEAD
class ApiCallError(Exception):
    def __init__(self, message, status_code=None, original_exception=None):
        super().__init__(message)
        self.status_code = status_code
        self.original_exception = original_exception


# -----------------------------------------------------------------------------------------------------------------
# 2-Tier 캐시 매니저 (L1 Memory + L2 SQLite)
# -----------------------------------------------------------------------------------------------------------------
class KeywordCacheManager:
    def __init__(self, db_dir):
        os.makedirs(db_dir, exist_ok=True)
        self.db_path = os.path.join(db_dir, "keyword_cache.db")
        self._local = threading.local()
        self._lock = threading.Lock()
        self.l1_cache = {}
        self._init_db()

    def _get_conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def close_current_thread(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def _init_db(self):
        with sqlite3.connect(self.db_path, timeout=5) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS keyword_metrics (
                    keyword TEXT PRIMARY KEY,
                    pc INTEGER NOT NULL DEFAULT 0,
                    mobile INTEGER NOT NULL DEFAULT 0,
                    post_count INTEGER NOT NULL DEFAULT 0,
                    search_updated_at TEXT,
                    doc_updated_at TEXT
                )
                """
            )
            conn.commit()

    def prune_expired(self, search_ttl_hours=72, doc_ttl_hours=24):
        now = datetime.now()
        search_cutoff = (now - timedelta(hours=search_ttl_hours * 4)).isoformat()
        doc_cutoff = (now - timedelta(hours=doc_ttl_hours * 4)).isoformat()
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                """
                DELETE FROM keyword_metrics
                WHERE (search_updated_at IS NULL OR search_updated_at < ?)
                  AND (doc_updated_at IS NULL OR doc_updated_at < ?)
                """,
                (search_cutoff, doc_cutoff),
            )
            conn.commit()

    def _parse_ts(self, value):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def get_metrics(self, keyword, search_ttl_hours=72, doc_ttl_hours=24):
        now = datetime.now()
        cached = self.l1_cache.get(keyword)
        if cached:
            search_ok = cached.get("search_updated_at") and (
                now - cached["search_updated_at"] < timedelta(hours=search_ttl_hours)
            )
            doc_ok = cached.get("doc_updated_at") and (
                now - cached["doc_updated_at"] < timedelta(hours=doc_ttl_hours)
            )
            if search_ok and doc_ok:
                return {
                    "pc": cached["pc"],
                    "mobile": cached["mobile"],
                    "post_count": cached["post_count"],
                    "search_fresh": True,
                    "doc_fresh": True,
                }

        conn = self._get_conn()
        row = conn.execute(
            """
            SELECT pc, mobile, post_count, search_updated_at, doc_updated_at
            FROM keyword_metrics
            WHERE keyword = ?
            """,
            (keyword,),
        ).fetchone()
        if not row:
            return None

        search_updated_at = self._parse_ts(row["search_updated_at"])
        doc_updated_at = self._parse_ts(row["doc_updated_at"])
        data = {
            "pc": int(row["pc"] or 0),
            "mobile": int(row["mobile"] or 0),
            "post_count": int(row["post_count"] or 0),
            "search_updated_at": search_updated_at,
            "doc_updated_at": doc_updated_at,
        }
        self.l1_cache[keyword] = data

        return {
            "pc": data["pc"],
            "mobile": data["mobile"],
            "post_count": data["post_count"],
            "search_fresh": bool(
                search_updated_at
                and (now - search_updated_at < timedelta(hours=search_ttl_hours))
            ),
            "doc_fresh": bool(
                doc_updated_at
                and (now - doc_updated_at < timedelta(hours=doc_ttl_hours))
            ),
        }

    def upsert_search_volume(self, keyword, pc, mobile):
        now = datetime.now()
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                """
                INSERT INTO keyword_metrics (keyword, pc, mobile, search_updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(keyword) DO UPDATE SET
                    pc=excluded.pc,
                    mobile=excluded.mobile,
                    search_updated_at=excluded.search_updated_at
                """,
                (keyword, int(pc), int(mobile), now.isoformat()),
            )
            conn.commit()
        existing = self.l1_cache.get(keyword, {})
        self.l1_cache[keyword] = {
            "pc": int(pc),
            "mobile": int(mobile),
            "post_count": int(existing.get("post_count", 0)),
            "search_updated_at": now,
            "doc_updated_at": existing.get("doc_updated_at"),
        }

    def upsert_post_count(self, keyword, post_count):
        now = datetime.now()
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                """
                INSERT INTO keyword_metrics (keyword, post_count, doc_updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(keyword) DO UPDATE SET
                    post_count=excluded.post_count,
                    doc_updated_at=excluded.doc_updated_at
                """,
                (keyword, int(post_count), now.isoformat()),
            )
            conn.commit()
        existing = self.l1_cache.get(keyword, {})
        self.l1_cache[keyword] = {
            "pc": int(existing.get("pc", 0)),
            "mobile": int(existing.get("mobile", 0)),
            "post_count": int(post_count),
            "search_updated_at": existing.get("search_updated_at"),
            "doc_updated_at": now,
        }


def get_naver_ad_keywords(keyword, api_key, secret_key, customer_id, session=None):
=======
def load_cookies_from_auth_file(path="auth.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            storage_state = json.load(f)
        return {cookie["name"]: cookie["value"] for cookie in storage_state["cookies"]}
    except FileNotFoundError:
        return None


def get_naver_ad_keywords(
    keyword: str, api_key: str, secret_key: str, customer_id: str
):
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
    if not all([api_key, secret_key, customer_id]):
        raise ValueError("광고 API 키가 없습니다.")

    signature_generator = Signature()
    base_url, uri, method = "https://api.searchad.naver.com", "/keywordstool", "GET"
    timestamp = str(round(time.time() * 1000))
    signature = signature_generator.generate(timestamp, method, uri, secret_key)
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-Timestamp": timestamp, "X-API-KEY": api_key,
        "X-Customer": str(customer_id), "X-Signature": signature,
    }
    params = {"hintKeywords": keyword.replace(" ", ""), "showDetail": "1"}
<<<<<<< HEAD
    req_session = session or requests
    try:
        r = req_session.get(base_url + uri, params=params, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json().get("keywordList", [])
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else None
        raise ApiCallError(
            f"광고 API HTTP 오류: {status_code}",
            status_code=status_code,
            original_exception=e,
        ) from e
    except requests.exceptions.Timeout as e:
        raise ApiCallError("광고 API timeout", original_exception=e) from e
    except requests.exceptions.RequestException as e:
        raise ApiCallError(f"광고 API 호출 실패: {e}", original_exception=e) from e
=======
    r = requests.get(base_url + uri, params=params, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json().get("keywordList", [])
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b


def get_blog_post_count(keyword: str, client_id: str, client_secret: str):
    if not all([client_id, client_secret]):
        raise ValueError("검색 API 키가 설정되지 않았습니다.")
    url = f"https://openapi.naver.com/v1/search/blog?query={quote(keyword)}"
    headers = {"X-Naver-Client-Id": client_id, "X-Naver-Client-Secret": client_secret}
<<<<<<< HEAD
    req_session = session or requests
    try:
        response = req_session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get("total", 0)
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else None
        raise ApiCallError(
            f"블로그 검색 API HTTP 오류: {status_code}",
            status_code=status_code,
            original_exception=e,
        ) from e
    except requests.exceptions.Timeout as e:
        raise ApiCallError("블로그 검색 API timeout", original_exception=e) from e
    except requests.exceptions.RequestException as e:
        raise ApiCallError(
            f"블로그 검색 API 호출 실패: {e}", original_exception=e
        ) from e
=======
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("total", 0)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b


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
        self.month_selected.emit(QDate(self.current_year, month, 1))
        self.accept()
        

<<<<<<< HEAD

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


# -----------------------------------------------------------------------------------------------------------------
# BackgroundWorker
# -----------------------------------------------------------------------------------------------------------------
class BackgroundWorker(QObject):
    log = pyqtSignal(str, str)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)

    browser_opened = pyqtSignal()
    driver_closed = pyqtSignal()

    trends_done = pyqtSignal(list)
    age_trends_done = pyqtSignal(list)
    main_inflow_done = pyqtSignal(list)
    blog_views_done = pyqtSignal(list)
    analysis_done = pyqtSignal(object)
    autocomplete_done = pyqtSignal(list)

    CATEGORIES = [
        "맛집",
        "국내여행",
        "세계여행",
        "비즈니스·경제",
        "패션·미용",
        "상품리뷰",
        "일상·생각",
        "건강·의학",
        "육아·결혼",
        "요리·레시피",
        "IT·컴퓨터",
        "교육·학문",
        "자동차",
        "인테리어·DIY",
        "스포츠",
        "취미",
        "방송",
        "게임",
        "스타·연예인",
        "영화",
        "공연·전시",
        "반려동물",
        "사회·정치",
        "드라마",
        "어학·외국어",
        "문학·책",
        "음악",
        "만화·애니",
        "좋은글·이미지",
        "미술·디자인",
        "원예·재배",
        "사진",
    ]
    DEMO_CODES = [
        "f_05",
        "f_06",
        "f_04",
        "f_07",
        "f_03",
        "f_08",
        "m_07",
        "m_06",
        "m_05",
        "f_09",
        "m_08",
        "m_04",
        "m_09",
        "f_10",
        "f_11",
        "m_11",
        "m_03",
        "f_02",
        "m_10",
        "m_02",
        "f_01",
        "m_01",
    ]
    DEMO_MAP = {
        "f_01": "0-12세 여자",
        "f_02": "13-18세 여자",
        "f_03": "19-24세 여자",
        "f_04": "25-29세 여자",
        "f_05": "30-34세 여자",
        "f_06": "35-39세 여자",
        "f_07": "40-44세 여자",
        "f_08": "45-49세 여자",
        "f_09": "50-54세 여자",
        "f_10": "55-59세 여자",
        "f_11": "60세- 여자",
        "m_01": "0-12세 남자",
        "m_02": "13-18세 남자",
        "m_03": "19-24세 남자",
        "m_04": "25-29세 남자",
        "m_05": "30-34세 남자",
        "m_06": "35-39세 남자",
        "m_07": "40-44세 남자",
        "m_08": "45-49세 남자",
        "m_09": "50-54세 남자",
        "m_10": "55-59세 남자",
        "m_11": "60세- 남자",
    }

    def __init__(self):
        super().__init__()
        self.driver = None
        # 워커 스레드 내에서 캐시 매니저 초기화
        self.cache_manager = KeywordCacheManager(get_app_data_path())

    def _get_fetch_script(self, url):
        return f"""
        var done = arguments[0];
        fetch("{url}")
            .then(r => {{
                if (!r.ok) return r.text().then(t => done(JSON.stringify({{__fetch_error__: true, status: r.status, body: t.slice(0, 300)}})));
                return r.text().then(t => done(t));
            }})
            .catch(e => done(JSON.stringify({{__fetch_error__: true, message: String(e)}})));
        """

    def _validate_response(self, res_text):
        if not res_text:
            raise ValueError("응답이 비어있습니다.")
        try:
            d = json.loads(res_text)
            if isinstance(d, dict) and d.get("__fetch_error__"):
                raise ValueError(
                    f"HTTP 통신 에러 (Status: {d.get('status')}) - {d.get('body', '')}"
                )
            if not isinstance(d, dict):
                raise ValueError("응답이 JSON 객체가 아닙니다.")
            if "data" not in d or not isinstance(d["data"], list):
                raise ValueError("네이버 API의 data 구조가 예상과 다릅니다.")
            return d
        except json.JSONDecodeError:
            raise ValueError(f"JSON 파싱 실패 (응답 일부: {res_text[:100]}...)")

    def _validate_blog_views_response(self, res_text):
        if not res_text:
            raise ValueError("응답이 비어있습니다.")
        try:
            d = json.loads(res_text)
        except json.JSONDecodeError:
            raise ValueError(f"JSON 파싱 실패: {res_text[:100]}")
        if isinstance(d, dict) and d.get("__fetch_error__"):
            raise ValueError(f"HTTP 에러: {d.get('status')} - {d.get('body', '')}")
        if not isinstance(d, dict) or "result" not in d:
            raise ValueError("조회수 API 응답 구조가 변경되었습니다.")
        return d

    def _parse_rank_change(self, rc):
        if rc is None:
            return None
        try:
            return int(rc)
        except (ValueError, TypeError):
            return None

    def _check_browser_ready(self, target_domain):
        if not self.driver:
            raise ValueError("브라우저가 열려있지 않습니다.")
        if "nid.naver.com" in self.driver.current_url:
            raise ValueError(
                "네이버 로그인 창에 머물러 있습니다. 로그인을 완료해주세요."
            )
        if target_domain not in self.driver.current_url:
            self.driver.get(f"https://{target_domain}/")
            time.sleep(2)

    @pyqtSlot()
    def open_browser(self):
        try:
            if self.driver:
                self.driver.current_url
                self.driver.get("https://creator-advisor.naver.com/")
                self.log.emit("INFO", "이미 열려있는 브라우저를 사용합니다.")
                self.browser_opened.emit()
                return
        except Exception:
            pass

        self.log.emit("INFO", "🌐 네이버 전용 브라우저를 엽니다...")
        try:
            service = ChromeService(ChromeDriverManager().install())
            options = webdriver.ChromeOptions()
            options.add_experimental_option("excludeSwitches", ["enable-logging"])
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            app_data_path = os.path.join(get_app_data_path(), "ChromeProfile")
            os.makedirs(app_data_path, exist_ok=True)
            options.add_argument(f"--user-data-dir={app_data_path}")

            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.get(
                "https://nid.naver.com/nidlogin.login?url=https://creator-advisor.naver.com/"
            )
            self.browser_opened.emit()
        except Exception as e:
            self.error.emit(f"브라우저 열기 실패: {e}")

    @pyqtSlot()
    def fetch_trends(self):
        try:
            self._check_browser_ready("creator-advisor.naver.com")
            self.log.emit("INFO", "🚀 주제별 트렌드 데이터를 수집합니다...")
            target_date_str = (
                datetime.now() - timedelta(days=2 if datetime.now().hour < 8 else 1)
            ).strftime("%Y-%m-%d")
            self.driver.set_script_timeout(10)
            all_trends_data = []

            for i, cat in enumerate(self.CATEGORIES):
                self.progress.emit(int((i + 1) / len(self.CATEGORIES) * 100))
                url = f"https://creator-advisor.naver.com/api/v6/trend/category?categories={quote(cat)}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=20&service=naver_blog"
                res_text = self.driver.execute_async_script(self._get_fetch_script(url))
                try:
                    d = self._validate_response(res_text)
                    if (
                        d["data"]
                        and isinstance(d["data"][0], dict)
                        and "queryList" in d["data"][0]
                    ):
                        for r_idx, item in enumerate(d["data"][0]["queryList"], 1):
                            rc = self._parse_rank_change(item.get("rankChange"))
                            all_trends_data.append(
                                {
                                    "카테고리": cat,
                                    "순위": r_idx,
                                    "키워드": item.get("query", "N/A"),
                                    "순위변동": rc,
                                }
                            )
                except Exception as e:
                    self.log.emit("WARNING", f"[{cat}] 파싱/통신 실패: {e}")
                time.sleep(0.3)
            self.trends_done.emit(all_trends_data)
        except Exception as e:
            self.error.emit(f"수집 실패: {e}")

    @pyqtSlot()
    def fetch_age_trends(self):
        try:
            self._check_browser_ready("creator-advisor.naver.com")
            self.log.emit("INFO", "🚀 연령별 트렌드 데이터를 수집합니다...")
            target_date_str = (
                datetime.now() - timedelta(days=2 if datetime.now().hour < 8 else 1)
            ).strftime("%Y-%m-%d")
            self.driver.set_script_timeout(10)
            all_age_trends = []

            for i, code in enumerate(self.DEMO_CODES):
                self.progress.emit(int((i + 1) / len(self.DEMO_CODES) * 100))
                gender, age_code = code.split("_")
                group_name = self.DEMO_MAP.get(code, code)
                url = f"https://creator-advisor.naver.com/api/v6/trend/demo?age={age_code}&date={target_date_str}&gender={gender}&hasRankChange=true&interval=day&limit=20&metric=cv&service=naver_blog"
                res_text = self.driver.execute_async_script(self._get_fetch_script(url))
                try:
                    d = self._validate_response(res_text)
                    if (
                        d["data"]
                        and isinstance(d["data"][0], dict)
                        and "queryList" in d["data"][0]
                    ):
                        for r_idx, item in enumerate(d["data"][0]["queryList"], 1):
                            rc = self._parse_rank_change(item.get("rankChange"))
                            all_age_trends.append(
                                {
                                    "연령대": group_name,
                                    "순위": r_idx,
                                    "키워드": item.get("query", "N/A"),
                                    "순위변동": rc,
                                }
                            )
                except Exception as e:
                    self.log.emit("WARNING", f"[{group_name}] 파싱/통신 실패: {e}")
                time.sleep(0.3)
            self.age_trends_done.emit(all_age_trends)
        except Exception as e:
            self.error.emit(f"수집 실패: {e}")

    @pyqtSlot()
    def fetch_naver_main(self):
        try:
            self._check_browser_ready("creator-advisor.naver.com")
            self.log.emit("INFO", "🚀 메인 유입 데이터를 수집합니다...")
            params_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
            url = f"https://creator-advisor.naver.com/api/v6/trend/main-inflow-content-ranks?service=naver_blog&date={params_date}&interval=day"
            self.driver.set_script_timeout(10)
            res_text = self.driver.execute_async_script(self._get_fetch_script(url))
            d = self._validate_response(res_text)
            results = [
                {"rank": str(i), "title": item.get("title"), "link": item.get("url")}
                for i, item in enumerate(d.get("data", []), 1)
            ]
            self.main_inflow_done.emit(results)
        except Exception as e:
            self.error.emit(f"수집 실패: {e}")

    @pyqtSlot(object, object, str)
    def fetch_blog_views(self, start_date, end_date, time_dimension):
        try:
            self._check_browser_ready("blog.stat.naver.com")
            self.log.emit("INFO", "🚀 블로그 조회수 데이터를 수집합니다...")
            dates = (
                [
                    start_date + timedelta(days=i)
                    for i in range(
                        0,
                        (end_date - start_date).days + 1,
                        7 if time_dimension == "WEEK" else 1,
                    )
                ]
                if time_dimension in ["DATE", "WEEK"]
                else [start_date]
            )
            all_view = []
            self.driver.set_script_timeout(10)

            for i, d in enumerate(dates):
                self.progress.emit(int((i + 1) / len(dates) * 100))
                ds = d.strftime("%Y-%m-%d")
                url = f"https://blog.stat.naver.com/api/blog/rank/cvContentPc?timeDimension={time_dimension}&startDate={ds}"
                res_text = self.driver.execute_async_script(self._get_fetch_script(url))
                try:
                    r_json = self._validate_blog_views_response(res_text)
                    if "result" in r_json and (
                        rows := r_json["result"]
                        .get("statDataList", [{}])[0]
                        .get("data", {})
                        .get("rows")
                    ):
                        for dt, rank, cv, title, uri in zip(
                            rows.get("date", []),
                            rows.get("rank", []),
                            rows.get("cv", []),
                            rows.get("title", []),
                            rows.get("uri", []),
                        ):
                            all_view.append(
                                {
                                    "날짜": dt,
                                    "순위": rank,
                                    "조회수": cv,
                                    "제목": title,
                                    "게시물_주소": (
                                        uri
                                        if uri.startswith("http")
                                        else f"https://blog.naver.com{uri}"
                                    ),
                                }
                            )
                except Exception as e:
                    self.log.emit("WARNING", f"조회수 파싱 오류: {e}")
                time.sleep(0.3)
            self.blog_views_done.emit(all_view)
        except Exception as e:
            self.error.emit(f"수집 실패: {e}")

    # 백오프(Backoff) 처리용 헬퍼 함수들
    def _safe_pause_after_api_call(self):
        time.sleep(random.uniform(0.2, 0.45))

    def _backoff_sleep(self, attempt, base_seconds, cap_seconds):
        wait = min(cap_seconds, base_seconds * (2**attempt)) + random.uniform(0.15, 0.6)
        time.sleep(wait)
        return wait

    def _extract_search_volume(self, ad_data, keyword):
        pc, mob = 0, 0
        if ad_data and (
            matched := next(
                (it for it in ad_data if it.get("relKeyword") == keyword), None
            )
        ):
            pc_str = str(matched.get("monthlyPcQcCnt", 0))
            mob_str = str(matched.get("monthlyMobileQcCnt", 0))
            pc = 5 if "<" in pc_str else int(pc_str)
            mob = 5 if "<" in mob_str else int(mob_str)
        return pc, mob

    def _call_api_with_backoff(self, func, api_name, original_kw, max_retries=3):
        for attempt in range(max_retries):
            try:
                return func()
            except ApiCallError as e:
                status_code = e.status_code
                if status_code == 401:
                    raise
                if status_code == 403:
                    raise
                if status_code == 429:
                    wait = self._backoff_sleep(attempt, 2.5, 15)
                    self.log.emit(
                        "WARNING",
                        f"'{original_kw}' {api_name} 호출 제한(429) - {wait:.1f}초 후 재시도합니다.",
                    )
                    continue
                if "timeout" in str(e).lower():
                    wait = self._backoff_sleep(attempt, 1.5, 8)
                    self.log.emit(
                        "WARNING",
                        f"'{original_kw}' {api_name} 응답 지연 - {wait:.1f}초 후 재시도합니다.",
                    )
                    continue
                if attempt < max_retries - 1:
                    wait = self._backoff_sleep(attempt, 1.2, 6)
                    self.log.emit(
                        "WARNING",
                        f"'{original_kw}' {api_name} 일시 오류 - {wait:.1f}초 후 재시도합니다.",
                    )
                    continue
                raise
        raise ApiCallError(f"{api_name} 재시도 한도 초과")

    @pyqtSlot(list, dict)
    def fetch_analysis(self, keywords, api_keys):
        unique_kw = list(dict.fromkeys(keywords))
        analysis_results = []
        self.cache_manager.prune_expired(search_ttl_hours=72, doc_ttl_hours=24)

        with requests.Session() as session:
            session.headers.update({"Connection": "keep-alive"})
            for i, original_kw in enumerate(unique_kw):
                self.progress.emit(int((i + 1) / len(unique_kw) * 100))
                kw_api = original_kw.replace(" ", "")
                if not kw_api:
                    continue

                api_called = False
                try:
                    cached = self.cache_manager.get_metrics(
                        kw_api, search_ttl_hours=72, doc_ttl_hours=24
                    ) or {
                        "pc": 0,
                        "mobile": 0,
                        "post_count": 0,
                        "search_fresh": False,
                        "doc_fresh": False,
                    }

                    pc = cached["pc"]
                    mob = cached["mobile"]
                    post_count = cached["post_count"]

                    if cached["search_fresh"]:
                        self.log.emit("INFO", f"'{original_kw}' 검색량 캐시 ⚡ 사용")
                    else:
                        ad_data = self._call_api_with_backoff(
                            lambda: get_naver_ad_keywords(
                                kw_api,
                                api_keys["ads_key"],
                                api_keys["ads_secret"],
                                api_keys["customer_id"],
                                session,
                            ),
                            "광고 API",
                            original_kw,
                        )
                        pc, mob = self._extract_search_volume(ad_data, kw_api)
                        self.cache_manager.upsert_search_volume(kw_api, pc, mob)
                        api_called = True

                    if cached["doc_fresh"]:
                        self.log.emit("INFO", f"'{original_kw}' 문서수 캐시 ⚡ 사용")
                    else:
                        post_count = self._call_api_with_backoff(
                            lambda: get_blog_post_count(
                                kw_api,
                                api_keys["client_id"],
                                api_keys["client_secret"],
                                session,
                            ),
                            "블로그 검색 API",
                            original_kw,
                        )
                        self.cache_manager.upsert_post_count(kw_api, post_count)
                        api_called = True

                    tot_search = pc + mob
                    opp_idx = (tot_search / post_count) if post_count > 0 else 0
                    cat = (
                        "🏆 황금"
                        if opp_idx >= 0.2
                        else (
                            "✨ 매력"
                            if opp_idx >= 0.05 and tot_search >= 1000
                            else "일반"
                        )
                    )

                    analysis_results.append(
                        {
                            "분류": cat,
                            "키워드": original_kw,
                            "총검색량": tot_search,
                            "총문서수": post_count,
                            "기회지수": round(opp_idx, 2),
                        }
                    )
                except ApiCallError as e:
                    if e.status_code == 401:
                        self.log.emit(
                            "ERROR",
                            f"'{original_kw}' 오류: API 키/시크릿이 잘못되었습니다 (401).",
                        )
                    elif e.status_code == 403:
                        self.log.emit(
                            "ERROR", f"'{original_kw}' 오류: API 권한이 없습니다 (403)."
                        )
                    elif e.status_code == 429:
                        self.log.emit(
                            "WARNING",
                            f"'{original_kw}' 오류: 호출 제한이 계속 발생하여 이번 키워드는 건너뜁니다.",
                        )
                    else:
                        self.log.emit("ERROR", f"'{original_kw}' 분석 오류: {e}")
                except Exception as e:
                    self.log.emit("ERROR", f"'{original_kw}' 분석 오류: {e}")
                finally:
                    if api_called:
                        self._safe_pause_after_api_call()

        self.analysis_done.emit(pd.DataFrame(analysis_results))

    @pyqtSlot(str, list)
    def fetch_autocomplete(self, keyword, engines):
        res = set()
        with requests.Session() as s:
            if "naver" in engines:
                try:
                    r = s.get(
                        f"https://ac.search.naver.com/nx/ac?q_enc=UTF-8&st=100&r_format=json&q={quote(keyword)}",
                        headers={"User-Agent": "Mozilla"},
                        timeout=5,
                    )
                    r.raise_for_status()
                    if items := r.json().get("items"):
                        for i in items[0]:
                            res.add(i[0])
                except Exception as e:
                    self.log.emit("WARNING", f"네이버 자동완성 오류: {e}")
            if "daum" in engines:
                try:
                    r = s.get(
                        f"https://suggest.search.daum.net/sushi/opensearch/pc?q={quote(keyword)}",
                        headers={"User-Agent": "Mozilla"},
                        timeout=5,
                    )
                    r.raise_for_status()
                    if "json" in r.headers.get("Content-Type", "").lower():
                        d = r.json()
                        if isinstance(d, list) and len(d) > 1:
                            for it in d[1]:
                                res.add(it.strip())
                    else:
                        for it in ET.fromstring(r.content).findall(".//item/keyword"):
                            if it.text:
                                res.add(it.text.strip())
                except Exception as e:
                    self.log.emit("WARNING", f"Daum 자동완성 오류: {e}")
            if "google" in engines:
                try:
                    r = s.get(
                        f"https://suggestqueries.google.com/complete/search?client=firefox&output=json&q={quote(keyword)}",
                        headers={"User-Agent": "Mozilla"},
                        timeout=5,
                    )
                    r.raise_for_status()
                    if isinstance((d := r.json()), list) and len(d) > 1:
                        for it in d[1]:
                            res.add(it.strip())
                except Exception as e:
                    self.log.emit("WARNING", f"Google 자동완성 오류: {e}")
        self.autocomplete_done.emit(sorted(list(res)))

    @pyqtSlot()
    def close_driver(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                self.log.emit("WARNING", f"드라이버 종료 지연: {e}")
            self.driver = None
        self.driver_closed.emit()


# -----------------------------------------------------------------------------------------------------------------
# 메인 GUI 앱
# -----------------------------------------------------------------------------------------------------------------
=======
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
class KeywordApp(QMainWindow):
    NAVER_TOPIC_TRENDS_API_URL = "https://creator-advisor.naver.com/api/v6/trend/category"
    NAVER_AGE_TRENDS_API_URL = "https://creator-advisor.naver.com/api/v6/trend/demo"
    AC_NAVER_URL = "https://ac.search.naver.com/nx/ac?q_enc=UTF-8&st=100&r_format=json&q="
    AC_GOOGLE_URL = "https://suggestqueries.google.com/complete/search?client=firefox&output=json&q="
    AC_DAUM_URL = "https://suggest.search.daum.net/sushi/opensearch/pc?q="
    BLOG_BASE_URL = "https://blog.naver.com"
    
    CATEGORIES = [
        "맛집", "국내여행", "세계여행", "비즈니스·경제", "패션·미용", "상품리뷰",
        "일상·생각", "건강·의학", "육아·결혼", "요리·레시피", "IT·컴퓨터", "교육·학문",
        "자동차", "인테리어·DIY", "스포츠", "취미", "방송", "게임",
        "스타·연예인", "영화", "공연·전시", "반려동물", "사회·정치", "드라마",
        "어학·외국어", "문학·책", "음악", "만화·애니", "좋은글·이미지",
        "미술·디자인", "원예·재배", "사진",
    ]

    DEMO_CODES = [
        "f_05", "f_06", "f_04", "f_07", "f_03", "f_08", "m_07", "m_06",
        "m_05", "f_09", "m_08", "m_04", "m_09", "f_10", "f_11", "m_11",
        "m_03", "f_02", "m_10", "m_02", "f_01", "m_01"
    ]
    
    DEMO_MAP = {
        'f_01': '0-12세 여자', 'f_02': '13-18세 여자', 'f_03': '19-24세 여자',
        'f_04': '25-29세 여자', 'f_05': '30-34세 여자', 'f_06': '35-39세 여자',
        'f_07': '40-44세 여자', 'f_08': '45-49세 여자', 'f_09': '50-54세 여자',
        'f_10': '55-59세 여자', 'f_11': '60세- 여자',
        'm_01': '0-12세 남자', 'm_02': '13-18세 남자', 'm_03': '19-24세 남자',
        'm_04': '25-29세 남자', 'm_05': '30-34세 남자', 'm_06': '35-39세 남자',
        'm_07': '40-44세 남자', 'm_08': '45-49세 남자', 'm_09': '50-54세 남자',
        'm_10': '55-59세 남자', 'm_11': '60세- 남자',
    }


    def __init__(self):
        super().__init__()
        self.current_version = get_current_version()
        self.setWindowTitle(f"키워드 분석기 Pro v{self.current_version}")

        self.is_working = False
        self._closing = False
        self.current_task = ""

        self.cached_data = {
            "trends": None,
            "age_trends": None,
            "main_inflow": None,
            "blog_views": {},
            "analysis": {},
            "auto": {},
        }
        self.current_views_cache_key = ""
        self.current_analysis_cache_key = None
        self.current_auto_cache_key = ""

        self.all_trend_data = []
        self.rank_sort_order = Qt.SortOrder.DescendingOrder
        self.currently_displayed_data = []
        self.bv_current_date = QDate.currentDate()
        self.bv_calendar_popup = None

        self.update_checker = UpdateChecker(self.current_version)
        self.update_checker.update_available.connect(self.on_update_available)
        self.update_checker.error_occurred.connect(self.on_update_error)
        self.update_checker.start()

        self.setGeometry(100, 100, 1100, 800)
        self.setStyleSheet(load_stylesheet())
<<<<<<< HEAD

        if getattr(sys, "frozen", False):
            app_dir = os.path.dirname(sys.executable)
        else:
            app_dir = os.path.dirname(os.path.abspath(__file__))

        env_path = os.path.join(app_dir, "api.env")
        load_dotenv(env_path)

        self.API_KEYS = {
            "ads_key": os.getenv("NAVER_ADS_API_KEY"),
            "ads_secret": os.getenv("NAVER_ADS_API_SECRET"),
            "customer_id": os.getenv("NAVER_ADS_CUSTOMER_ID"),
            "client_id": os.getenv("NAVER_SEARCH_CLIENT_ID"),
            "client_secret": os.getenv("NAVER_SEARCH_CLIENT_SECRET"),
        }

=======
        load_dotenv("api.env")
        self.NAVER_ADS_API_KEY = os.getenv("NAVER_ADS_API_KEY")
        self.NAVER_ADS_API_SECRET = os.getenv("NAVER_ADS_API_SECRET")
        self.NAVER_ADS_CUSTOMER_ID = os.getenv("NAVER_ADS_CUSTOMER_ID")
        self.NAVER_SEARCH_CLIENT_ID = os.getenv("NAVER_SEARCH_CLIENT_ID")
        self.NAVER_SEARCH_CLIENT_SECRET = os.getenv("NAVER_SEARCH_CLIENT_SECRET")
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        icon_path = resource_path("keyword_pro.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.thread = None
        self.worker = None
        self.results_df = None
        self.blog_views_df = None
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

        self.bg_thread = QThread()
        self.bg_worker = BackgroundWorker()
        self.bg_worker.moveToThread(self.bg_thread)

        self.bg_thread.finished.connect(self.bg_worker.deleteLater)
        self.bg_thread.finished.connect(self.bg_thread.deleteLater)

        self.req_open_browser.connect(self.bg_worker.open_browser)
        self.req_fetch_trends.connect(self.bg_worker.fetch_trends)
        self.req_fetch_age_trends.connect(self.bg_worker.fetch_age_trends)
        self.req_fetch_main.connect(self.bg_worker.fetch_naver_main)
        self.req_fetch_views.connect(self.bg_worker.fetch_blog_views)
        self.req_fetch_analysis.connect(self.bg_worker.fetch_analysis)
        self.req_fetch_autocomplete.connect(self.bg_worker.fetch_autocomplete)
        self.req_close_driver.connect(self.bg_worker.close_driver)

        self.bg_worker.log.connect(self.log_message)
        self.bg_worker.progress.connect(self.update_progress_bar)
        self.bg_worker.error.connect(self.on_worker_error)

        self.bg_worker.browser_opened.connect(self.on_browser_opened)
        self.bg_worker.driver_closed.connect(self.final_quit)

        self.bg_worker.trends_done.connect(self.on_trend_fetching_finished)
        self.bg_worker.age_trends_done.connect(self.on_age_trend_fetching_finished)
        self.bg_worker.main_inflow_done.connect(self.on_naver_main_finished)
        self.bg_worker.blog_views_done.connect(self.on_fetch_blog_views_finished)
        self.bg_worker.analysis_done.connect(self.on_analysis_finished)
        self.bg_worker.autocomplete_done.connect(self.on_autocomplete_finished)

        self.bg_thread.start()

        missing_keys = [k for k, v in self.API_KEYS.items() if not v]
        if missing_keys:
            self.log_message(
                "ERROR",
                f"❌ api.env 파일 인식 오류: 다음 키가 누락되었습니다 -> {', '.join(missing_keys)}",
            )
            self.log_message("WARNING", f"📁 인식된 env 경로: {env_path}")
            self.log_message(
                "WARNING",
                "해당 경로에 api.env 파일이 존재하는지, 내용이 정확한지 확인해주세요.",
            )
        else:
            self.log_message("SUCCESS", "✅ 모든 API 키가 정상적으로 로드되었습니다.")

    def _finish_task_state(self):
        self.is_working = False
        self.current_task = ""
        self.set_all_buttons_disabled(False)

    def _add_to_cache(self, cache_dict, key, value, limit=30):
        cache_dict[key] = value
        if len(cache_dict) > limit:
            first_key = next(iter(cache_dict))
            del cache_dict[first_key]

    def update_button_style(self, btn, is_cached, original_text, default_style=""):
        btn.setProperty("cached", "true" if is_cached else "false")
        btn.style().unpolish(btn)
        btn.style().polish(btn)
        btn.setText(f"{original_text} (캐시됨)" if is_cached else original_text)

    def check_views_cache_state(self):
        cid = self.bv_mode_group.checkedId()
        time_dim = {0: "DATE", 1: "WEEK", 2: "MONTH"}[cid]
        d = self.bv_current_date
        if cid == 0:
            sd, ed = d.toPyDate(), d.toPyDate()
        elif cid == 1:
            sw = d.addDays(-(d.dayOfWeek() - 1))
            sd, ed = sw.toPyDate(), sw.addDays(6).toPyDate()
        elif cid == 2:
            sd, ed = (
                QDate(d.year(), d.month(), 1).toPyDate(),
                QDate(d.year(), d.month(), d.daysInMonth()).toPyDate(),
            )

        cache_key = f"{sd}_{ed}_{time_dim}"
        is_cached = cache_key in self.cached_data.get("blog_views", {})
        self.update_button_style(
            self.fetch_blog_views_button, is_cached, "켜진 창에서 조회수 순위 가져오기"
        )

    def check_analysis_cache_state(self):
        keywords = [
            kw.strip()
            for kw in self.analysis_input_widget.toPlainText().strip().split("\n")
            if kw.strip()
        ]
        cache_key = tuple(sorted(list(set(keywords))))
        is_cached = bool(keywords) and cache_key in self.cached_data.get("analysis", {})
        self.update_button_style(self.analyze_button, is_cached, "기회지수 분석 시작")

    def check_auto_cache_state(self):
        kw = self.autocomplete_input.text().strip()
        engines = [
            name
            for cb, name in [("naver", "naver"), ("daum", "daum"), ("google", "google")]
            if getattr(self, f"cb_{cb}").isChecked()
        ]
        cache_key = f"{kw}_{'-'.join(sorted(engines))}"
        is_cached = (
            bool(kw) and bool(engines) and cache_key in self.cached_data.get("auto", {})
        )
        self.update_button_style(
            self.autocomplete_search_button, is_cached, "자동완성 검색"
        )

    def set_all_buttons_disabled(self, disabled):
        self.auth_button.setDisabled(disabled)
        self.fetch_trends_button.setDisabled(disabled)
        self.fetch_age_trends_button.setDisabled(disabled)
        self.fetch_main_content_button.setDisabled(disabled)
        self.fetch_blog_views_button.setDisabled(disabled)
        self.analyze_button.setDisabled(disabled)
        self.autocomplete_search_button.setDisabled(disabled)

    def update_progress_bar(self, val):
        if self.current_task in ["trends", "age"]:
            self.progress_bar_fetch.setValue(val)
        elif self.current_task == "analysis":
            self.progress_bar_analysis.setValue(val)
        elif self.current_task == "views":
            self.progress_bar_bv.setValue(val)

    def log_message(self, level, msg):
        if self.log_widget.document().blockCount() > 1000:
            cursor = self.log_widget.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.select(cursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()

        c = {
            "INFO": "#82C0FF",
            "SUCCESS": "#28A745",
            "WARNING": "orange",
            "ERROR": "#DC3545",
        }.get(level, "#E0E0E0")
        self.log_widget.append(
            f'<font color="{c}">[{datetime.now().strftime("%H:%M:%S")}] - {level} - {msg}</font>'
        )

    def create_settings_bar(self, parent_layout):
        settings_frame = QWidget()
        settings_layout = QHBoxLayout(settings_frame)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        self.reset_button = QPushButton("화면 초기화")
        self.reset_button.clicked.connect(self.reset_ui)
<<<<<<< HEAD
        self.auth_button = QPushButton("1. 네이버 연결 (브라우저 열기)")
        self.auth_button.setObjectName("primaryBtn")
        self.auth_button.setStyleSheet(
            "background-color: #007BFF; font-weight: bold; padding: 8px;"
        )
        self.auth_button.clicked.connect(self.start_open_browser)
=======
        self.auth_button = QPushButton("인증 정보 갱신 (로그인)")
        self.auth_button.setObjectName("AuthButton")
        self.auth_button.clicked.connect(self.start_auth_regeneration)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
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
        self.fetch_trends_button.setObjectName("TrendButton")
        self.fetch_age_trends_button = QPushButton("연령별 트렌드")
        self.fetch_age_trends_button.setObjectName("TrendButton")
        self.copy_to_analyzer_button = QPushButton("키워드 → 분석 탭으로 복사")
        self.copy_to_analyzer_button.setObjectName("CopyButton")
        self.category_filter_combo = QComboBox()
<<<<<<< HEAD
        self.category_filter_combo.setFixedWidth(160)
        self.trend_search_input = QLineEdit()
        self.trend_search_input.setPlaceholderText("결과 내 검색...")
        self.trend_search_input.setFixedWidth(140)
=======
        self.category_filter_combo.setFixedWidth(150)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.export_trends_excel_button = QPushButton("엑셀로 저장")
        self.export_trends_excel_button.setObjectName("ExcelButton")
        self.copy_to_analyzer_button.setDisabled(True)
        self.category_filter_combo.setDisabled(True)
        self.trend_search_input.setDisabled(True)
        self.export_trends_excel_button.setDisabled(True)
<<<<<<< HEAD

=======
        
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        control_layout.addWidget(self.fetch_trends_button)
        control_layout.addWidget(self.fetch_age_trends_button)
        control_layout.addWidget(self.copy_to_analyzer_button)
        control_layout.addWidget(QLabel("필터:"))
        control_layout.addWidget(self.category_filter_combo)
        control_layout.addWidget(self.trend_search_input)
        control_layout.addWidget(self.export_trends_excel_button)
        control_layout.addStretch()

        status_container = QWidget()
        status_container.setMinimumWidth(350)
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label_fetch = QLabel("버튼을 눌러 트렌드 키워드 수집을 시작하세요.")
        self.progress_bar_fetch = QProgressBar()
        self.progress_bar_fetch.setFormat("수집 진행률: %p%")
        status_layout.addWidget(self.status_label_fetch)
        status_layout.addWidget(self.progress_bar_fetch)
        control_layout.addWidget(status_container)
<<<<<<< HEAD

=======
        
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.trend_table = QTableWidget()
        headers = ["카테고리", "키워드", "순위변동"]
        self.trend_table.setColumnCount(len(headers))
        self.trend_table.setHorizontalHeaderLabels(headers)
        self.trend_table.setSortingEnabled(False)
<<<<<<< HEAD
        self.trend_table.horizontalHeader().sectionClicked.connect(
            self.sort_trend_table
        )

        layout.addLayout(control_layout)
        layout.addWidget(self.trend_table)
        self.tabs.addTab(tab, "트렌드 키워드 수집")

=======
        self.trend_table.horizontalHeader().sectionClicked.connect(self.sort_trend_table_by_rank_change)
        layout.addWidget(control_widget)
        layout.addWidget(self.trend_table)
        self.tabs.addTab(tab, "트렌드 키워드 수집")
        
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.fetch_trends_button.clicked.connect(self.start_trend_fetching)
        self.fetch_age_trends_button.clicked.connect(self.start_age_trend_fetching)
        self.copy_to_analyzer_button.clicked.connect(self.copy_trends_to_analyzer)
        self.category_filter_combo.currentIndexChanged.connect(self.filter_trend_table)
        self.trend_search_input.textChanged.connect(self.filter_trend_table)
        self.export_trends_excel_button.clicked.connect(self.export_trends_to_excel)

    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        placeholder_text = "--- 키워드를 입력하거나 붙여넣어 주세요 (한 줄에 하나씩) ---\n\n💡 '기회 지수'란?\n'월간 총검색량 ÷ 블로그 총문서수'로 계산되는 값으로,\n문서(공급) 대비 검색량(수요)이 얼마나 높은지를 나타내는 지표입니다."
        self.analysis_input_widget = QTextEdit()
        self.analysis_input_widget.setPlaceholderText(placeholder_text)
<<<<<<< HEAD
        self.analysis_input_widget.textChanged.connect(self.check_analysis_cache_state)

=======
        
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        control_layout = QHBoxLayout()
        self.analyze_button = QPushButton("기회지수 분석 시작")
        self.analyze_button.setObjectName("AnalyzeButton")
        self.export_excel_button = QPushButton("엑셀로 저장")
        self.export_excel_button.setObjectName("ExcelButton")
        self.export_excel_button.setDisabled(True)
        self.progress_bar_analysis = QProgressBar()
        self.progress_bar_analysis.setFixedHeight(20)
        self.progress_bar_analysis.setTextVisible(True)
        self.progress_bar_analysis.setFormat("%p%")
        control_layout.addWidget(self.analyze_button)
        control_layout.addWidget(self.export_excel_button)
        control_layout.addStretch()
        control_layout.addWidget(self.progress_bar_analysis)
        self.result_table = QTableWidget()
        headers = ["분류", "키워드", "총검색량", "총문서수", "기회지수"]
        self.result_table.setColumnCount(len(headers))
        self.result_table.setHorizontalHeaderLabels(headers)
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
        self.autocomplete_input = QLineEdit()
<<<<<<< HEAD
        self.autocomplete_input.setPlaceholderText("자동완성 키워드 입력...")
        self.autocomplete_input.textChanged.connect(
            lambda _: self.check_auto_cache_state()
        )

=======
        self.autocomplete_input.setPlaceholderText("자동완성 키워드를 검색할 단어를 입력하세요...")
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        input_layout.addWidget(QLabel("검색어:"), 0)
        input_layout.addWidget(self.autocomplete_input, 1)
        checkbox_layout = QHBoxLayout()
        checkbox_layout.setContentsMargins(10, 5, 0, 5)
        checkbox_layout.addWidget(QLabel("검색 엔진:"), 0)
<<<<<<< HEAD
        self.cb_naver = QCheckBox("네이버")
        self.cb_daum = QCheckBox("Daum")
        self.cb_google = QCheckBox("Google")
        self.cb_naver.setChecked(True)
        self.cb_daum.setChecked(True)
        self.cb_google.setChecked(True)

        self.cb_naver.stateChanged.connect(lambda _: self.check_auto_cache_state())
        self.cb_daum.stateChanged.connect(lambda _: self.check_auto_cache_state())
        self.cb_google.stateChanged.connect(lambda _: self.check_auto_cache_state())

        checkbox_layout.addWidget(self.cb_naver)
        checkbox_layout.addWidget(self.cb_daum)
        checkbox_layout.addWidget(self.cb_google)
=======
        self.cb_naver = QCheckBox("네이버"); self.cb_daum = QCheckBox("Daum"); self.cb_google = QCheckBox("Google")
        self.cb_naver.setChecked(True); self.cb_daum.setChecked(True); self.cb_google.setChecked(True)
        checkbox_layout.addWidget(self.cb_naver); checkbox_layout.addWidget(self.cb_daum); checkbox_layout.addWidget(self.cb_google)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        checkbox_layout.addStretch()
        
        button_layout = QHBoxLayout()
        self.autocomplete_search_button = QPushButton("자동완성 검색")
        self.autocomplete_copy_button = QPushButton("키워드 → 분석 탭으로 복사")
        self.autocomplete_copy_button.setObjectName("AutocompleteCopyButton")
        button_layout.addWidget(self.autocomplete_search_button)
        button_layout.addWidget(self.autocomplete_copy_button)
        button_layout.addStretch()
        top_control_layout.addLayout(input_layout)
        top_control_layout.addLayout(checkbox_layout)
        top_control_layout.addLayout(button_layout)
        self.autocomplete_table = QTableWidget()
        headers = ["자동완성 키워드"]
        self.autocomplete_table.setColumnCount(len(headers))
        self.autocomplete_table.setHorizontalHeaderLabels(headers)
        self.autocomplete_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addLayout(top_control_layout)
        layout.addWidget(self.autocomplete_table)
        self.tabs.addTab(tab, "자동완성 키워드 수집")
        
        self.autocomplete_search_button.clicked.connect(self.start_autocomplete_search)
        self.autocomplete_input.returnPressed.connect(self.start_autocomplete_search)
        self.autocomplete_copy_button.clicked.connect(
            self.copy_autocomplete_to_analyzer
        )

    def create_naver_main_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        control_layout = QHBoxLayout()
        self.fetch_main_content_button = QPushButton("유입콘텐츠 가져오기")
        self.fetch_main_content_button.setObjectName("TrendButton")
        hint_label = QLabel("💡 더블클릭으로 해당 링크 이동")
        hint_label.setStyleSheet("color: #6C757D; font-size: 9pt; padding-left: 10px;")
        control_layout.addWidget(self.fetch_main_content_button)
        control_layout.addWidget(hint_label)
        control_layout.addStretch()
        self.naver_main_table = QTableWidget()
        headers = ["순위", "제목"]
        self.naver_main_table.setColumnCount(len(headers))
        self.naver_main_table.setHorizontalHeaderLabels(headers)
        self.naver_main_table.verticalHeader().setVisible(False)
        self.naver_main_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.naver_main_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
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
        self.bv_radio_daily = QPushButton("일간")
        self.bv_radio_weekly = QPushButton("주간")
        self.bv_radio_monthly = QPushButton("월간")
        self.bv_radio_daily.setCheckable(True)
        self.bv_radio_weekly.setCheckable(True)
        self.bv_radio_monthly.setCheckable(True)
        self.bv_mode_group.addButton(self.bv_radio_daily, 0)
        self.bv_mode_group.addButton(self.bv_radio_weekly, 1)
        self.bv_mode_group.addButton(self.bv_radio_monthly, 2)
        top_control_layout.addWidget(self.bv_prev_btn)
        top_control_layout.addWidget(self.bv_date_label)
        top_control_layout.addWidget(self.bv_calendar_btn)
        top_control_layout.addWidget(self.bv_next_btn)
        top_control_layout.addStretch(1)
        top_control_layout.addWidget(self.bv_radio_daily)
        top_control_layout.addWidget(self.bv_radio_weekly)
        top_control_layout.addWidget(self.bv_radio_monthly)
        bottom_control_layout = QHBoxLayout()
        bottom_control_layout.setContentsMargins(0, 5, 0, 0)
<<<<<<< HEAD
        self.fetch_blog_views_button = QPushButton("켜진 창에서 조회수 순위 가져오기")
        self.update_button_style(
            self.fetch_blog_views_button,
            False,
            "켜진 창에서 조회수 순위 가져오기",
            "background-color: #28A745; font-weight: bold;",
        )
=======
        self.fetch_blog_views_button = QPushButton("조회수 순위 가져오기")
        self.fetch_blog_views_button.setObjectName("TrendButton")
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.export_blog_views_button = QPushButton("엑셀로 저장")
        self.export_blog_views_button.setObjectName("ExcelButton")
        self.export_blog_views_button.setDisabled(True)
        bottom_control_layout.addWidget(self.fetch_blog_views_button)
        bottom_control_layout.addWidget(self.export_blog_views_button)
        bottom_control_layout.addStretch()
        self.blog_views_table = QTableWidget()
        headers = ["날짜", "순위", "조회수", "제목"]
        self.blog_views_table.setColumnCount(len(headers))
        self.blog_views_table.setHorizontalHeaderLabels(headers)
        status_container = QWidget()
        status_container.setMinimumWidth(350)
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label_bv = QLabel("조회할 기간을 선택하고 버튼을 눌러주세요.")
        self.progress_bar_bv = QProgressBar(); self.progress_bar_bv.setFormat("진행률: %p%")
        status_layout.addWidget(self.status_label_bv); status_layout.addWidget(self.progress_bar_bv)
        bottom_control_layout.addWidget(status_container)
        layout.addLayout(top_control_layout)
        layout.addLayout(bottom_control_layout)
        layout.addWidget(self.blog_views_table)
        self.tabs.addTab(tab, "블로그 조회수 순위")
        self.bv_mode_group.buttonClicked.connect(self.bv_on_mode_changed)
        self.bv_prev_btn.clicked.connect(self.bv_navigate_prev)
        self.bv_next_btn.clicked.connect(self.bv_navigate_next)
        self.bv_calendar_btn.clicked.connect(self.bv_show_calendar_picker)
        self.fetch_blog_views_button.clicked.connect(self.start_fetch_blog_views)
        self.export_blog_views_button.clicked.connect(self.export_blog_views_to_excel)
        self.blog_views_table.cellDoubleClicked.connect(self.open_blog_view_link)
        self.bv_radio_daily.setChecked(True); self.bv_on_mode_changed()

    def bv_on_mode_changed(self):
        checked_id = self.bv_mode_group.checkedId()
        today = QDate.currentDate()
        if checked_id == 0: self.bv_current_date = today
        elif checked_id == 1: self.bv_current_date = today.addDays(-7)
        elif checked_id == 2: self.bv_current_date = today.addMonths(-1)
        self.bv_update_date_display()

    def bv_update_date_display(self):
<<<<<<< HEAD
        cid = self.bv_mode_group.checkedId()
        d = self.bv_current_date
        if cid == 0:
            self.bv_date_label.setText(d.toString("yyyy.MM.dd."))
        elif cid == 1:
            s = d.addDays(-(d.dayOfWeek() - 1))
            self.bv_date_label.setText(
                f"{s.toString('yyyy.MM.dd.')} ~ {s.addDays(6).toString('yyyy.MM.dd.')}"
            )
        elif cid == 2:
            self.bv_date_label.setText(d.toString("yyyy.MM."))
        self.check_views_cache_state()
=======
        checked_id = self.bv_mode_group.checkedId()
        date = self.bv_current_date
        if checked_id == 0: self.bv_date_label.setText(date.toString("yyyy.MM.dd."))
        elif checked_id == 1:
            start_of_week = date.addDays(-(date.dayOfWeek() - 1))
            end_of_week = start_of_week.addDays(6)
            self.bv_date_label.setText(f"{start_of_week.toString('yyyy.MM.dd.')} ~ {end_of_week.toString('yyyy.MM.dd.')}")
        elif checked_id == 2: self.bv_date_label.setText(date.toString("yyyy.MM."))
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b

    def bv_navigate_prev(self):
        checked_id = self.bv_mode_group.checkedId()
        if checked_id == 0: self.bv_current_date = self.bv_current_date.addDays(-1)
        elif checked_id == 1: self.bv_current_date = self.bv_current_date.addDays(-7)
        elif checked_id == 2: self.bv_current_date = self.bv_current_date.addMonths(-1)
        self.bv_update_date_display()

    def bv_navigate_next(self):
        checked_id = self.bv_mode_group.checkedId()
        if checked_id == 0: self.bv_current_date = self.bv_current_date.addDays(1)
        elif checked_id == 1: self.bv_current_date = self.bv_current_date.addDays(7)
        elif checked_id == 2: self.bv_current_date = self.bv_current_date.addMonths(1)
        self.bv_update_date_display()

    def bv_show_calendar_picker(self):
        if self.bv_mode_group.checkedId() == 2:
            dialog = MonthPickerDialog(self.bv_current_date, self)
            dialog.month_selected.connect(self.bv_on_date_selected)
            dialog.exec()
            return
        if self.bv_calendar_popup is None:
            self.bv_calendar_popup = WeeklyCalendarWidget()
            self.bv_calendar_popup.setWindowFlags(Qt.WindowType.Popup)
            self.bv_calendar_popup.clicked.connect(self.bv_on_date_selected)
        self.bv_calendar_popup.set_selected_date(self.bv_current_date)
        global_pos = self.bv_calendar_btn.mapToGlobal(QPoint(0, self.bv_calendar_btn.height()))
        self.bv_calendar_popup.move(global_pos)
        self.bv_calendar_popup.show()

    def bv_on_date_selected(self, date):
        self.bv_current_date = date
        self.bv_update_date_display()
        if self.bv_calendar_popup and self.bv_calendar_popup.isVisible():
            self.bv_calendar_popup.hide()

    def reset_ui(self):
<<<<<<< HEAD
        self.cached_data = {
            "trends": None,
            "age_trends": None,
            "main_inflow": None,
            "blog_views": {},
            "analysis": {},
            "auto": {},
        }
        self.results_df = None
        self.blog_views_df = None
=======
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.trend_table.setRowCount(0)
        self.all_trend_data = []
        self.category_filter_combo.blockSignals(True)
        self.category_filter_combo.clear()
        self.category_filter_combo.blockSignals(False)
        self.trend_search_input.clear()

        self.category_filter_combo.setDisabled(True)
        self.trend_search_input.setDisabled(True)
        self.export_trends_excel_button.setDisabled(True)
        self.copy_to_analyzer_button.setDisabled(True)
        self.rank_sort_order = Qt.SortOrder.DescendingOrder
        self.trend_table.horizontalHeader().setSortIndicatorShown(False)
        self.status_label_fetch.setText("버튼을 눌러 트렌드 키워드 수집을 시작하세요.")
        self.progress_bar_fetch.setValue(0)
        self.analysis_input_widget.clear()
        self.result_table.setRowCount(0)
        self.progress_bar_analysis.setValue(0)
        self.export_excel_button.setDisabled(True)
        self.autocomplete_input.clear()
        self.autocomplete_table.setRowCount(0)
        self.cb_naver.setChecked(True)
        self.cb_daum.setChecked(True)
        self.cb_google.setChecked(True)
        self.bv_on_mode_changed()
        self.blog_views_table.setRowCount(0)
        self.status_label_bv.setText("조회할 기간을 선택하고 버튼을 눌러주세요.")
        self.progress_bar_bv.setValue(0)
        self.export_blog_views_button.setDisabled(True)

<<<<<<< HEAD
        self.update_button_style(
            self.fetch_trends_button,
            False,
            "2-1. 켜진 창에서 주제별 수집",
            "background-color: #28A745; font-weight: bold;",
        )
        self.update_button_style(
            self.fetch_age_trends_button,
            False,
            "2-2. 켜진 창에서 연령별 수집",
            "background-color: #28A745; font-weight: bold;",
        )
        self.update_button_style(
            self.fetch_main_content_button,
            False,
            "켜진 창에서 메인 유입콘텐츠 가져오기",
            "background-color: #28A745; font-weight: bold;",
        )
        self.check_views_cache_state()
        self.check_analysis_cache_state()
        self.check_auto_cache_state()

        self.log_message("INFO", "화면 및 메모리 캐시가 모두 초기화되었습니다.")

    def start_open_browser(self):
        if self.is_working:
            return
        self.is_working = True
        self.set_all_buttons_disabled(True)
        self.req_open_browser.emit()

    @pyqtSlot()
    def on_browser_opened(self):
        self._finish_task_state()
        QMessageBox.information(
            self,
            "안내",
            "브라우저가 열렸습니다!\n로그인 후 창을 끄지 말고 프로그램의 수집 버튼을 눌러주세요.",
        )

    def start_trend_fetching(self):
        if self.is_working:
            return
        if self.cached_data.get("trends"):
            QMessageBox.information(
                self,
                "캐시 적용됨",
                "💡 이미 데이터가 수집되어 화면에 표시되어 있습니다.\n(최신 데이터로 갱신하려면 '화면 초기화' 후 진행하세요)",
            )
            return
        self.is_working = True
        self.current_task = "trends"
        self.set_all_buttons_disabled(True)
        self.status_label_fetch.setText("수집 중...")
=======
    def run_worker(self, worker_fn, finish_slot, progress_bar=None, **kwargs):
        self.thread = QThread()
        self.worker = Worker(worker_fn, **kwargs)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(finish_slot)
        self.worker.error.connect(self.on_worker_error)
        if progress_bar:
            self.worker.progress.connect(progress_bar.setValue)
        self.worker.log.connect(self.log_message)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.error.connect(self.thread.quit)
        self.worker.error.connect(self.worker.deleteLater)
        self.thread.start()

    def _prepare_trend_fetch(self):
        self.fetch_trends_button.setDisabled(True)
        self.fetch_age_trends_button.setDisabled(True)
        self.category_filter_combo.setDisabled(True)
        self.copy_to_analyzer_button.setDisabled(True)
        self.export_trends_excel_button.setDisabled(True)
        self.status_label_fetch.setText("트렌드 수집 중...")
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.trend_table.setRowCount(0)
        self.progress_bar_fetch.setValue(0)
        
    def start_trend_fetching(self):
        self._prepare_trend_fetch()
        self.run_worker(self.fetch_trends_worker, self.on_trend_fetching_finished, progress_bar=self.progress_bar_fetch)

    def start_age_trend_fetching(self):
<<<<<<< HEAD
        if self.is_working:
            return
        if self.cached_data.get("age_trends"):
            QMessageBox.information(
                self,
                "캐시 적용됨",
                "💡 이미 데이터가 수집되어 화면에 표시되어 있습니다.\n(최신 데이터로 갱신하려면 '화면 초기화' 후 진행하세요)",
            )
            return
        self.is_working = True
        self.current_task = "age"
        self.set_all_buttons_disabled(True)
        self.status_label_fetch.setText("수집 중...")
        self.trend_table.setRowCount(0)
        self.progress_bar_fetch.setValue(0)
        self.req_fetch_age_trends.emit()

    def start_fetch_naver_main(self):
        if self.is_working:
            return
        if self.cached_data.get("main_inflow"):
            QMessageBox.information(
                self,
                "캐시 적용됨",
                "💡 이미 데이터가 수집되어 화면에 표시되어 있습니다.\n(최신 데이터로 갱신하려면 '화면 초기화' 후 진행하세요)",
            )
            return
        self.is_working = True
        self.current_task = "main"
        self.set_all_buttons_disabled(True)
        self.log_message("INFO", "네이버 메인 수집 시작...")
        self.naver_main_table.setRowCount(0)
        self.req_fetch_main.emit()

    def start_fetch_blog_views(self):
        if self.is_working:
            return
        cid = self.bv_mode_group.checkedId()
        time_dim = {0: "DATE", 1: "WEEK", 2: "MONTH"}[cid]
        d = self.bv_current_date
        if cid == 0:
            sd = ed = d.toPyDate()
        elif cid == 1:
            sw = d.addDays(-(d.dayOfWeek() - 1))
            sd, ed = sw.toPyDate(), sw.addDays(6).toPyDate()
        elif cid == 2:
            sd, ed = (
                QDate(d.year(), d.month(), 1).toPyDate(),
                QDate(d.year(), d.month(), d.daysInMonth()).toPyDate(),
            )

        cache_key = f"{sd}_{ed}_{time_dim}"
        if cache_key in self.cached_data["blog_views"]:
            if getattr(self, "current_views_cache_key", None) == cache_key:
                QMessageBox.information(
                    self,
                    "캐시 적용됨",
                    "💡 선택하신 기간의 데이터가 이미 화면에 표시되어 있습니다.",
                )
                return
            else:
                self.current_views_cache_key = cache_key
                self.log_message(
                    "SUCCESS", "💡 [메모리 캐시] 저장된 조회수 데이터를 즉시 띄웁니다."
                )
                self.current_task = "views"
                self.on_fetch_blog_views_finished(
                    self.cached_data["blog_views"][cache_key]
                )
                return

        self.current_views_cache_key = cache_key
        self.is_working = True
        self.current_task = "views"
        self.set_all_buttons_disabled(True)
        self.status_label_bv.setText(f"수집 중...")
        self.blog_views_table.setRowCount(0)
        self.progress_bar_bv.setValue(0)
        self.req_fetch_views.emit(sd, ed, time_dim)
=======
        self._prepare_trend_fetch()
        self.run_worker(self.fetch_age_trends_worker, self.on_age_trend_fetching_finished, progress_bar=self.progress_bar_fetch)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b

    def start_competition_analysis(self):
        if not all([self.NAVER_ADS_API_KEY, self.NAVER_ADS_API_SECRET, self.NAVER_ADS_CUSTOMER_ID, self.NAVER_SEARCH_CLIENT_ID, self.NAVER_SEARCH_CLIENT_SECRET]):
            error_msg = "하나 이상의 API 키가 없습니다. 'api.env' 파일을 확인해주세요."
            self.log_message("ERROR", error_msg)
            QMessageBox.critical(self, "API 키 오류", error_msg)
            return
<<<<<<< HEAD
        if not all(self.API_KEYS.values()):
            QMessageBox.critical(
                self,
                "API 키 오류",
                "하나 이상의 API 키가 없습니다. 'api.env' 파일을 확인해주세요.\n(하단 로그 창에서 누락된 키를 확인하세요)",
            )
            return

        keywords = [
            kw.strip()
            for kw in self.analysis_input_widget.toPlainText().strip().split("\n")
            if kw.strip()
        ]
=======
        keywords = self.analysis_input_widget.toPlainText().strip().split("\n")
        keywords = [kw.strip() for kw in keywords if kw.strip()]
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        if not keywords:
            QMessageBox.warning(self, "경고", "분석할 키워드를 입력하거나 붙여넣어 주세요.")
            return
<<<<<<< HEAD

        cache_key = tuple(sorted(list(set(keywords))))
        if cache_key in self.cached_data["analysis"]:
            if getattr(self, "current_analysis_cache_key", None) == cache_key:
                QMessageBox.information(
                    self,
                    "캐시 적용됨",
                    "💡 동일한 키워드의 분석 결과가 이미 화면에 표시되어 있습니다.",
                )
                return
            else:
                self.current_analysis_cache_key = cache_key
                self.log_message(
                    "SUCCESS", "💡 [메모리 캐시] 저장된 분석 결과를 즉시 띄웁니다."
                )
                self.current_task = "analysis"
                self.on_analysis_finished(self.cached_data["analysis"][cache_key])
                return

        self.current_analysis_cache_key = cache_key
        self.is_working = True
        self.current_task = "analysis"
        self.set_all_buttons_disabled(True)
=======
        self.analyze_button.setDisabled(True)
        self.export_excel_button.setDisabled(True)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.result_table.setRowCount(0)
        self.progress_bar_analysis.setValue(0)
        self.run_worker(self.analyze_competition_worker, self.on_analysis_finished, progress_bar=self.progress_bar_analysis, keywords=keywords)

    def start_auth_regeneration(self):
        self.auth_button.setDisabled(True)
        self.log_message("INFO", "🔒 사용자 인증 갱신 프로세스를 시작합니다...")
        self.log_message("WARNING", "새 창에서 네이버 로그인을 진행해주세요. 완료되면 창이 자동으로 닫힙니다.")
        
        if self.auth_process and self.auth_process.is_alive():
            self.auth_process.terminate()

        self.auth_process = Process(target=save_auth_process, args=(self.auth_queue,))
        self.auth_process.start()
        self.auth_check_timer.start(1000)

    def check_auth_process(self):
        if not self.auth_queue.empty():
            status, message = self.auth_queue.get()
            if status == "SUCCESS":
                self.log_message("SUCCESS", message)
                QMessageBox.information(self, "성공", message)
            else:
                self.log_message("ERROR", f"인증 중 오류 발생: {message}")
                QMessageBox.critical(self, "인증 오류", f"인증 중 오류가 발생했습니다:\n{message}")
            
            self.auth_check_timer.stop()
            self.auth_button.setDisabled(False)

        elif self.auth_process and not self.auth_process.is_alive():
            self.log_message("ERROR", "인증 프로세스가 비정상적으로 종료되었습니다.")
            QMessageBox.warning(self, "인증 실패", "인증 프로세스가 완료되지 않았습니다. 다시 시도해주세요.")
            self.auth_check_timer.stop()
            self.auth_button.setDisabled(False)

    def start_autocomplete_search(self):
        keyword = self.autocomplete_input.text().strip()
        if not keyword:
            QMessageBox.warning(self, "입력 오류", "검색어를 입력해주세요.")
            return
<<<<<<< HEAD

        engines = [
            name
            for cb, name in [("naver", "naver"), ("daum", "daum"), ("google", "google")]
            if getattr(self, f"cb_{cb}").isChecked()
        ]
        if not engines:
            QMessageBox.warning(
                self, "선택 오류", "검색 엔진을 하나 이상 선택해주세요."
            )
            return

        cache_key = f"{kw}_{'-'.join(sorted(engines))}"
        if cache_key in self.cached_data["auto"]:
            if getattr(self, "current_auto_cache_key", None) == cache_key:
                QMessageBox.information(
                    self,
                    "캐시 적용됨",
                    "💡 동일한 조건의 자동완성 결과가 이미 화면에 표시되어 있습니다.",
                )
                return
            else:
                self.current_auto_cache_key = cache_key
                self.log_message(
                    "SUCCESS", "💡 [메모리 캐시] 저장된 자동완성 결과를 즉시 띄웁니다."
                )
                self.current_task = "auto"
                self.on_autocomplete_finished(self.cached_data["auto"][cache_key])
                return

        self.current_auto_cache_key = cache_key
        self.is_working = True
        self.current_task = "auto"
        self.set_all_buttons_disabled(True)
=======
        selected_engines = [name for cb, name in [(self.cb_naver, "naver"), (self.cb_daum, "daum"), (self.cb_google, "google")] if cb.isChecked()]
        if not selected_engines:
            QMessageBox.warning(self, "선택 오류", "하나 이상의 검색 엔진을 선택해주세요.")
            return
        self.autocomplete_search_button.setDisabled(True)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.autocomplete_table.setRowCount(0)
        self.run_worker(self.autocomplete_worker, self.on_autocomplete_finished, keyword=keyword, engines=selected_engines)

<<<<<<< HEAD
    def on_worker_error(self, err):
        self._finish_task_state()
        self.log_message("ERROR", f"오류 발생: {err.splitlines()[0]}")
        QMessageBox.critical(self, "오류", err.splitlines()[0])

    def on_trend_fetching_finished(self, data):
        self.update_progress_bar(100)
        self._finish_task_state()
        if data:
            self.cached_data["trends"] = data
            self.update_button_style(
                self.fetch_trends_button,
                True,
                "2-1. 켜진 창에서 주제별 수집",
                "background-color: #28A745; font-weight: bold;",
            )
        self._finish_trend_fetching_ui(data, "카테고리")

    def on_age_trend_fetching_finished(self, data):
        self.update_progress_bar(100)
        self._finish_task_state()
        if data:
            self.cached_data["age_trends"] = data
            self.update_button_style(
                self.fetch_age_trends_button,
                True,
                "2-2. 켜진 창에서 연령별 수집",
                "background-color: #28A745; font-weight: bold;",
            )
        self._finish_trend_fetching_ui(data, "연령대")

    def _finish_trend_fetching_ui(self, data, first_col):
        if not data:
            self.status_label_fetch.setText("❌ 수집 실패.")
            return
        self.all_trend_data = list(data)
        self.status_label_fetch.setText(f"✅ {len(data)}개 완료!")
        self.trend_table.setHorizontalHeaderLabels(
            [first_col, "키워드", "순위", "순위변동"]
        )
=======
    def start_fetch_naver_main(self):
        self.fetch_main_content_button.setDisabled(True)
        self.log_message("INFO", "네이버 메인 유입 콘텐츠 수집을 시작합니다...")
        self.naver_main_table.setRowCount(0)
        self.run_worker(self.fetch_naver_main_worker, self.on_naver_main_finished)

    def start_fetch_blog_views(self):
        checked_id = self.bv_mode_group.checkedId()
        time_dim_map = {0: "DATE", 1: "WEEK", 2: "MONTH"}
        time_dimension = time_dim_map[checked_id]
        date = self.bv_current_date
        if checked_id == 0: start_date = end_date = date.toPyDate()
        elif checked_id == 1:
            start_of_week = date.addDays(-(date.dayOfWeek() - 1))
            start_date = start_of_week.toPyDate()
            end_date = start_of_week.addDays(6).toPyDate()
        elif checked_id == 2:
            start_date = QDate(date.year(), date.month(), 1).toPyDate()
            end_date = QDate(date.year(), date.month(), date.daysInMonth()).toPyDate()
        self.fetch_blog_views_button.setDisabled(True)
        self.export_blog_views_button.setDisabled(True)
        self.status_label_bv.setText(f"블로그 {self.bv_mode_group.checkedButton().text()} 순위 수집 중...")
        self.blog_views_table.setRowCount(0)
        self.progress_bar_bv.setValue(0)
        self.run_worker(self.fetch_blog_views_worker, self.on_fetch_blog_views_finished, progress_bar=self.progress_bar_bv, start_date=start_date, end_date=end_date, time_dimension=time_dimension)

    def fetch_trends_worker(self, worker_instance):
        worker_instance.log.emit("INFO", "📈 주제별 트렌드 키워드 수집을 시작합니다...")
        cookies = load_cookies_from_auth_file()
        if not cookies: raise ValueError("'auth.json' 파일을 찾을 수 없습니다. '인증 정보 갱신' 버튼을 눌러주세요.")
        now = datetime.now()
        days_to_subtract = 2 if now.hour < 8 else 1
        target_date = now - timedelta(days=days_to_subtract)
        target_date_str = target_date.strftime("%Y-%m-%d")
        worker_instance.log.emit("INFO", f"🎯 검색 대상 날짜: {target_date_str}")
        try:
            test_category = self.CATEGORIES[0]
            test_api_url = f"{self.NAVER_TOPIC_TRENDS_API_URL}?categories={quote(test_category)}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=1&service=naver_blog"
            response = requests.get(test_api_url, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"}, timeout=10)
            if response.status_code != 200: raise ValueError(f"인증 확인 실패 (HTTP {response.status_code}). '인증 정보 갱신'이 필요할 수 있습니다.")
            data = response.json()
            if "data" not in data: raise ValueError(f"API 응답 구조가 예상과 다릅니다. 서버 응답: {data.get('message', '알 수 없음')}")
        except requests.RequestException as e: raise ConnectionError(f"인증 확인 중 네트워크 오류가 발생했습니다: {e}")
        except json.JSONDecodeError: raise ValueError("인증 정보가 유효하지 않습니다 (API 응답 오류). '인증 정보 갱신'을 해주세요.")
        worker_instance.log.emit("SUCCESS", "✅ 인증 정보가 유효합니다.")
        all_trends_data = []
        for i, category in enumerate(self.CATEGORIES):
            worker_instance.log.emit("INFO", f"   - '{category}' 카테고리 수집 중...")
            worker_instance.progress.emit(int((i + 1) / len(self.CATEGORIES) * 100))
            api_url = f"{self.NAVER_TOPIC_TRENDS_API_URL}?categories={quote(category)}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=20&service=naver_blog"
            try:
                response = requests.get(api_url, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"})
                if (response.status_code == 200 and (data := response.json()).get("data") and data["data"] and data["data"][0].get("queryList")):
                    for item in data["data"][0]["queryList"]:
                        rank_change = item.get("rankChange")
                        try:
                            if rank_change is not None: rank_change = int(rank_change)
                        except (ValueError, TypeError): rank_change = None
                        all_trends_data.append({"카테고리": category, "키워드": item.get("query", "N/A"), "순위변동": rank_change})
                else:
                    worker_instance.log.emit("WARNING", f"   - '{category}' 카테고리 요청 실패 (상태 코드: {response.status_code})")
                time.sleep(0.3)
            except Exception as e:
                worker_instance.log.emit("ERROR", f"   - '{category}' 처리 중 오류: {e}")
        return all_trends_data
        
    def fetch_age_trends_worker(self, worker_instance):
        worker_instance.log.emit("INFO", "📈 연령별 트렌드 키워드 수집을 시작합니다... (JSON 방식)")
        cookies = load_cookies_from_auth_file()
        if not cookies:
            raise ValueError("'auth.json' 파일을 찾을 수 없습니다. '인증 정보 갱신' 버튼을 눌러주세요.")

        now = datetime.now()
        days_to_subtract = 2 if now.hour < 8 else 1
        target_date = now - timedelta(days=days_to_subtract)
        target_date_str = target_date.strftime("%Y-%m-%d")
        worker_instance.log.emit("INFO", f"🎯 검색 대상 날짜: {target_date_str}")
        
        all_age_trends = []
        total_codes = len(self.DEMO_CODES)

        for i, code in enumerate(self.DEMO_CODES):
            worker_instance.progress.emit(int((i + 1) / total_codes * 100))
            
            gender, age_code = code.split('_')
            age_group_name = self.DEMO_MAP.get(code, code)
            worker_instance.log.emit("INFO", f"   - '{age_group_name}' 그룹 수집 중...")

            params = {
                'age': age_code, 'date': target_date_str, 'gender': gender,
                'hasRankChange': 'true', 'interval': 'day', 'limit': 20,
                'metric': 'cv', 'service': 'naver_blog'
            }
            
            try:
                response = requests.get(self.NAVER_AGE_TRENDS_API_URL, params=params, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"})
                response.raise_for_status() 

                data = response.json()
                if (query_list := data.get("data", [{}])[0].get("queryList")):
                    for item in query_list:
                        rank_change = item.get("rankChange")
                        try:
                            if rank_change is not None: rank_change = int(rank_change)
                        except (ValueError, TypeError): rank_change = None
                        
                        all_age_trends.append({
                            "연령대": age_group_name,
                            "키워드": item.get("query", "N/A"),
                            "순위변동": rank_change
                        })
                else:
                     worker_instance.log.emit("WARNING", f"   - '{age_group_name}' 그룹에 데이터가 없습니다.")

            except requests.exceptions.HTTPError as e:
                 worker_instance.log.emit("ERROR", f"   - '{age_group_name}' 그룹 요청 실패 (HTTP {e.response.status_code}). 인증 만료 가능성이 있습니다.")
                 continue
            except json.JSONDecodeError:
                worker_instance.log.emit("ERROR", f"   - '{age_group_name}' 그룹 응답 분석 실패. 인증이 만료되었을 가능성이 높습니다.")
                continue
            except Exception as e:
                worker_instance.log.emit("ERROR", f"   - '{age_group_name}' 처리 중 오류: {e}")
                continue

            time.sleep(0.3) 

        return all_age_trends

    def analyze_competition_worker(self, worker_instance, keywords):
        worker_instance.log.emit("INFO", "🔬 키워드 기회지수 분석을 시작합니다 (0.15초 간격)...")
        unique_keywords = list(dict.fromkeys(keywords))
        analysis_results = []
        total = len(unique_keywords)
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
                    pc_count_str, mobile_count_str = str(exact_match.get("monthlyPcQcCnt", 0)), str(exact_match.get("monthlyMobileQcCnt", 0))
                    pc_search = 5 if "<" in pc_count_str else int(pc_count_str)
                    mobile_search = 5 if "<" in mobile_count_str else int(mobile_count_str)
                total_search = pc_search + mobile_search
                opportunity_index_float = (total_search / post_count) if post_count > 0 else 0
                category = "일반"
                if opportunity_index_float >= 0.2: category = "🏆 황금"
                elif opportunity_index_float >= 0.05 and total_search >= 1000: category = "✨ 매력"
                analysis_results.append({
                    "분류": category, "키워드": original_keyword, "총검색량": total_search,
                    "총문서수": post_count, "기회지수": round(opportunity_index_float, 2)
                })
            except Exception as e:
                worker_instance.log.emit("ERROR", f"'{original_keyword}' 분석 중 오류 발생: {e}")
            time.sleep(0.15)
        return pd.DataFrame(analysis_results)

    def verify_auth(self, worker_instance=None):
        cookies = load_cookies_from_auth_file()
        if not cookies:
            if worker_instance: worker_instance.log.emit("WARNING", "인증 파일을 찾을 수 없어 재인증을 시도합니다.")
            return self.save_auth_logic(worker_instance) if worker_instance else False
        test_url = "https://creator-advisor.naver.com/api/v6/trend/main-inflow-content-ranks"
        yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        params = {"service": "naver_blog", "date": yesterday_str, "interval": "day"}
        try:
            response = requests.get(test_url, params=params, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"}, timeout=10)
            if response.status_code == 200:
                try:
                    if 'data' in response.json():
                        if worker_instance: worker_instance.log.emit("SUCCESS", "✅ 인증이 유효합니다.")
                        return True
                except: pass
            if response.status_code == 401:
                if worker_instance: worker_instance.log.emit("WARNING", "인증이 만료되어 재인증이 필요합니다.")
                return self.save_auth_logic(worker_instance) if worker_instance else False
            if worker_instance: worker_instance.log.emit("WARNING", f"인증 확인 실패 (상태 코드: {response.status_code})")
            return False
        except requests.exceptions.RequestException as e:
            if worker_instance: worker_instance.log.emit("WARNING", f"인증 확인 중 네트워크 오류: {str(e)}")
            return False

    def fetch_naver_main_worker(self, worker_instance):
        worker_instance.log.emit("INFO", "네이버 메인 유입 콘텐츠 API를 호출합니다...")
        cookies = load_cookies_from_auth_file()
        if not cookies: raise ValueError("'auth.json' 파일을 찾을 수 없습니다. '인증 정보 갱신'을 먼저 실행해주세요.")
        if not self.verify_auth(worker_instance): raise ValueError("인증이 유효하지 않습니다. '인증 정보 갱신' 버튼을 눌러 다시 로그인해주세요.")
        yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        api_url = "https://creator-advisor.naver.com/api/v6/trend/main-inflow-content-ranks"
        params = {"service": "naver_blog", "date": yesterday_str, "interval": "day"}
        results = []
        try:
            response = requests.get(api_url, params=params, cookies=cookies, headers={"Referer": "https://creator-advisor.naver.com/"}, timeout=10)
            response.raise_for_status()
            data = response.json().get("data", [])
            for i, item in enumerate(data, start=1):
                results.append({"rank": str(i), "title": item.get("title"), "link": item.get("url")})
            worker_instance.log.emit("SUCCESS", f"API로부터 {len(results)}개의 인기 콘텐츠를 가져왔습니다.")
            return results
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                worker_instance.log.emit("WARNING", "인증이 만료되어 재인증을 시도합니다...")
                if self.verify_auth(worker_instance):
                    worker_instance.log.emit("SUCCESS", "재인증 성공! 데이터를 다시 가져옵니다.")
                    return self.fetch_naver_main_worker(worker_instance)
                else: raise ValueError("재인증 실패. '인증 정보 갱신' 버튼을 눌러 수동으로 인증해주세요.")
            worker_instance.log.emit("ERROR", f"API 요청 실패: {e}")
            raise ValueError(f"API 요청 실패: {e}")
        except Exception as e:
            worker_instance.log.emit("ERROR", f"네이버 메인 콘텐츠 API 호출 중 오류: {e}")
            raise e

    def fetch_blog_views_worker(self, worker_instance, start_date, end_date, time_dimension):
        worker_instance.log.emit("INFO", f"📈 블로그 {time_dimension} 순위 수집을 시작합니다...")
        cookies = load_cookies_from_auth_file()
        if not cookies: raise ValueError("'auth.json' 파일을 찾을 수 없습니다. '인증 정보 갱신'을 먼저 실행해주세요.")
        all_view_data = []
        dates_to_fetch = []
        if time_dimension in ["DATE", "WEEK"]:
            total_days = (end_date - start_date).days
            step = 7 if time_dimension == "WEEK" else 1
            for i in range(0, total_days + 1, step):
                dates_to_fetch.append(start_date + timedelta(days=i))
        else: dates_to_fetch.append(start_date)
        total_calls = len(dates_to_fetch)
        for i, current_date in enumerate(dates_to_fetch):
            date_str = current_date.strftime("%Y-%m-%d")
            worker_instance.log.emit("INFO", f"   - '{date_str}' 기준 데이터 수집 중...")
            worker_instance.progress.emit(int((i + 1) / total_calls * 100))
            api_url = f"https://blog.stat.naver.com/api/blog/rank/cvContentPc?timeDimension={time_dimension}&startDate={date_str}"
            try:
                response = requests.get(api_url, cookies=cookies, headers={"Referer": "https://blog.stat.naver.com/"}, timeout=10)
                response.raise_for_status()
                j = response.json()
                if j.get("statusCode") == 200:
                    rows = j.get("result", {}).get("statDataList")[0].get("data", {}).get("rows")
                    if not rows or not rows.get("date"):
                        worker_instance.log.emit("WARNING", f"   - '{date_str}'에 데이터가 없습니다.")
                        continue
                    zipped_data = zip(rows.get("date", []), rows.get("rank", []), rows.get("cv", []), rows.get("title", []), rows.get("uri", []))
                    for date, rank, cv, title, uri in zipped_data:
                        post_url = uri if uri.startswith("http") else f"{self.BLOG_BASE_URL}{uri}"
                        all_view_data.append({"날짜": date, "순위": rank, "조회수": cv, "제목": title, "게시물_주소": post_url})
                else:
                    worker_instance.log.emit("WARNING", f"   - '{date_str}' 데이터 요청 실패 (상태코드: {j.get('statusCode')})")
                time.sleep(0.2)
            except Exception as e:
                worker_instance.log.emit("ERROR", f"   - '{date_str}' 처리 중 오류: {e}")
        return all_view_data
    
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
            if "json" in resp.headers.get("Content-Type", "").lower():
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    for item in data[1]: all_results.add(item.strip())
                elif isinstance(data, dict) and (items := data.get("items", {}).get("s")):
                    for item in items:
                        if len(item) > 1: all_results.add(item[1])
            else:
                root = ET.fromstring(resp.content)
                for item in root.findall(".//item/keyword"):
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
        if "naver" in engines: self._fetch_naver_autocomplete(worker_instance, keyword, all_results)
        if "daum" in engines: self._fetch_daum_autocomplete(worker_instance, keyword, all_results)
        if "google" in engines: self._fetch_google_autocomplete(worker_instance, keyword, all_results)
        worker_instance.log.emit("SUCCESS", f"✅ 총 {len(all_results)}개의 키워드를 찾았습니다.")
        return sorted(list(all_results))

    def populate_trend_table(self, data_to_show):
        self.trend_table.setRowCount(0)
        if not data_to_show: return
        first_key = list(data_to_show[0].keys())[0]
        self.trend_table.setRowCount(len(data_to_show))
        for row_idx, item in enumerate(data_to_show):
            category_item = QTableWidgetItem(str(item[first_key]))
            keyword_item = QTableWidgetItem(str(item["키워드"]))
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

    def _finish_trend_fetching_ui(self, trend_data, first_column_name):
        self.fetch_trends_button.setDisabled(False)
        self.fetch_age_trends_button.setDisabled(False)
        self.progress_bar_fetch.setValue(100)
        if not trend_data:
            self.status_label_fetch.setText(f"❌ 수집된 {first_column_name}별 트렌드 키워드가 없습니다.")
            return
        self.all_trend_data = trend_data
        self.currently_displayed_data = self.all_trend_data  # 정렬에 사용될 현재 표시 데이터를 즉시 갱신
        self.status_label_fetch.setText(f"✅ {len(self.all_trend_data)}개 트렌드 키워드 수집 완료!")
        self.log_message("SUCCESS", f"{first_column_name}별 트렌드 키워드 수집이 완료되었습니다.")
        self.trend_table.setHorizontalHeaderLabels([first_column_name, "키워드", "순위변동"])
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.category_filter_combo.blockSignals(True)
        self.category_filter_combo.clear()
        
        categories = sorted(list(set(item[first_column_name] for item in self.all_trend_data)))

        self.category_filter_combo.addItem("전체 보기")
<<<<<<< HEAD
        self.category_filter_combo.addItem("✨ 신규 진입(NEW) 전체")
        self.category_filter_combo.addItem("🔥 최상위 신규 진입(1~5위 내 NEW)")
        self.category_filter_combo.addItem("🚀 급상승 키워드(+5 계단 이상)")
        self.category_filter_combo.addItems(
            sorted(list(set(str(it.get(first_col, "")) for it in data)))
        )
        self.category_filter_combo.blockSignals(False)
        self.trend_search_input.blockSignals(True)
        self.trend_search_input.clear()
        self.trend_search_input.blockSignals(False)
        self.populate_trend_table(data)
=======
        self.category_filter_combo.addItems(categories)
        self.category_filter_combo.blockSignals(False)
        self.populate_trend_table(self.all_trend_data)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.copy_to_analyzer_button.setDisabled(False)
        self.category_filter_combo.setDisabled(False)
        self.trend_search_input.setDisabled(False)
        self.export_trends_excel_button.setDisabled(False)

<<<<<<< HEAD
    def populate_trend_table(self, data):
        self.trend_table.setUpdatesEnabled(False)
        self.trend_table.setRowCount(len(data))
        if not data:
            self.trend_table.setUpdatesEnabled(True)
            return
        fk = "카테고리" if "카테고리" in data[0] else "연령대"
        for row, it in enumerate(data):
            c_it = QTableWidgetItem(str(it.get(fk, "")))
            k_it = QTableWidgetItem(str(it.get("키워드", "")))
            rank_it = QTableWidgetItem(str(it.get("순위", "")))
            rank_it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            rc = it.get("순위변동")
            r_it = QTableWidgetItem(
                "NEW" if rc is None else ("-" if rc == 0 else f"{rc:g}")
            )
            r_it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if rc is None:
                r_it.setForeground(QColor("#28A745"))
            elif rc > 0:
                r_it.setForeground(QColor("#DC3545"))
            elif rc < 0:
                r_it.setForeground(QColor("#007BFF"))
            self.trend_table.setItem(row, 0, c_it)
            self.trend_table.setItem(row, 1, k_it)
            self.trend_table.setItem(row, 2, rank_it)
            self.trend_table.setItem(row, 3, r_it)
        self.trend_table.resizeColumnsToContents()
        self.trend_table.setUpdatesEnabled(True)
        self.filter_trend_table()

    def sort_trend_table(self, idx):
        if idx not in [2, 3] or not self.all_trend_data:
            return
        self.rank_sort_order = (
            Qt.SortOrder.DescendingOrder
            if self.rank_sort_order == Qt.SortOrder.AscendingOrder
            else Qt.SortOrder.AscendingOrder
        )
        if idx == 2:
            self.all_trend_data.sort(
                key=lambda x: x["순위"],
                reverse=(self.rank_sort_order == Qt.SortOrder.DescendingOrder),
            )
        elif idx == 3:
            new_items = [i for i in self.all_trend_data if i["순위변동"] is None]
            other = sorted(
                [i for i in self.all_trend_data if i["순위변동"] is not None],
                key=lambda x: x["순위변동"],
                reverse=(self.rank_sort_order == Qt.SortOrder.DescendingOrder),
            )
            self.all_trend_data = new_items + other
        self.populate_trend_table(self.all_trend_data)
        self.trend_table.horizontalHeader().setSortIndicatorShown(True)
        self.trend_table.horizontalHeader().setSortIndicator(idx, self.rank_sort_order)

    def filter_trend_table(self):
        selected_filter = self.category_filter_combo.currentText()
        search_text = self.trend_search_input.text().strip().lower()
        if self.trend_table.rowCount() == 0:
            return
        for row in range(self.trend_table.rowCount()):
            cat_text = self.trend_table.item(row, 0).text()
            kwd_text = self.trend_table.item(row, 1).text().lower()
            rank_text = self.trend_table.item(row, 2).text()
            rc_text = self.trend_table.item(row, 3).text()
            hide_row = False
            if selected_filter and selected_filter != "전체 보기":
                if selected_filter == "✨ 신규 진입(NEW) 전체":
                    if rc_text != "NEW":
                        hide_row = True
                elif selected_filter == "🔥 최상위 신규 진입(1~5위 내 NEW)":
                    if rc_text != "NEW" or int(rank_text) > 5:
                        hide_row = True
                elif selected_filter == "🚀 급상승 키워드(+5 계단 이상)":
                    if rc_text in ["NEW", "-"] or int(rc_text) < 5:
                        hide_row = True
                else:
                    if cat_text != selected_filter:
                        hide_row = True
            if search_text and search_text not in kwd_text:
                hide_row = True
            self.trend_table.setRowHidden(row, hide_row)
=======
    def on_trend_fetching_finished(self, trend_data):
        self._finish_trend_fetching_ui(trend_data, "카테고리")
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b

    def on_age_trend_fetching_finished(self, age_trend_data):
        self._finish_trend_fetching_ui(age_trend_data, "연령대")
        
    def on_analysis_finished(self, df):
<<<<<<< HEAD
        self.update_progress_bar(100)
        self._finish_task_state()
=======
        self.analyze_button.setDisabled(False)
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        if df is not None and not df.empty:
            ck = getattr(self, "current_analysis_cache_key", None)
            if ck and ck not in self.cached_data["analysis"]:
                self._add_to_cache(self.cached_data["analysis"], ck, df, limit=30)
            self.check_analysis_cache_state()
            self.results_df = df.sort_values(by="기회지수", ascending=False)
            self.update_result_table(self.results_df)
            self.export_excel_button.setDisabled(False)
            self.log_message("SUCCESS", "🎉 모든 키워드의 기회지수 분석이 완료되었습니다.")
        else:
            self.log_message("WARNING", "분석된 결과가 없습니다.")
        self.progress_bar_analysis.setValue(100)

<<<<<<< HEAD
    def on_autocomplete_finished(self, kw):
        self._finish_task_state()
        if kw:
            ck = getattr(self, "current_auto_cache_key", None)
            if ck and ck not in self.cached_data["auto"]:
                self._add_to_cache(self.cached_data["auto"], ck, kw, limit=50)
            self.check_auto_cache_state()
        self.autocomplete_table.setUpdatesEnabled(False)
        self.autocomplete_table.setRowCount(len(kw))
        for r, k in enumerate(kw):
            self.autocomplete_table.setItem(r, 0, QTableWidgetItem(k))
=======
    def on_autocomplete_finished(self, keywords):
        self.autocomplete_table.setRowCount(len(keywords))
        for row_idx, keyword in enumerate(keywords):
            self.autocomplete_table.setItem(row_idx, 0, QTableWidgetItem(keyword))
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
        self.autocomplete_table.resizeColumnsToContents()
        self.autocomplete_search_button.setDisabled(False)

<<<<<<< HEAD
    def on_naver_main_finished(self, res):
        self._finish_task_state()
        if res:
            self.cached_data["main_inflow"] = res
            self.update_button_style(
                self.fetch_main_content_button,
                True,
                "켜진 창에서 메인 유입콘텐츠 가져오기",
                "background-color: #28A745; font-weight: bold;",
            )
        self.naver_main_table.setUpdatesEnabled(False)
        self.naver_main_table.setRowCount(len(res))
        for r, it in enumerate(res):
            ri, ti = QTableWidgetItem(it["rank"]), QTableWidgetItem(it["title"])
            ri.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ti.setData(Qt.ItemDataRole.UserRole, it["link"])
            self.naver_main_table.setItem(r, 0, ri)
            self.naver_main_table.setItem(r, 1, ti)
        self.naver_main_table.setUpdatesEnabled(True)
        if not res:
            self.log_message("WARNING", "메인 유입 데이터가 0건입니다.")

    def on_fetch_blog_views_finished(self, data):
        self.update_progress_bar(100)
        self._finish_task_state()
        if data:
            ck = getattr(self, "current_views_cache_key", None)
            if ck and ck not in self.cached_data["blog_views"]:
                self._add_to_cache(self.cached_data["blog_views"], ck, data, limit=30)
            self.check_views_cache_state()
        if not data:
            self.status_label_bv.setText("⚠️ 결과 0건 (또는 권한 필요).")
            self.log_message("WARNING", "블로그 조회수 데이터가 0건입니다.")
=======
    def on_naver_main_finished(self, results):
        self.fetch_main_content_button.setDisabled(False)
        self.naver_main_table.setRowCount(len(results))
        for row_idx, item in enumerate(results):
            rank_item, title_item = QTableWidgetItem(item["rank"]), QTableWidgetItem(item["title"])
            rank_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            title_item.setData(Qt.ItemDataRole.UserRole, item["link"])
            self.naver_main_table.setItem(row_idx, 0, rank_item)
            self.naver_main_table.setItem(row_idx, 1, title_item)

    def on_auth_finished(self, message):
        self.auth_button.setDisabled(False)
        self.log_message("SUCCESS", message)
        QMessageBox.information(self, "성공", message)

    def on_worker_error(self, error_message):
        concise_error = error_message.splitlines()[0]
        self.log_message("ERROR", f"작업 중 오류 발생: {concise_error}")
        QMessageBox.critical(self, "오류", f"오류가 발생했습니다:\n{concise_error}")
        self.fetch_trends_button.setDisabled(False)
        self.fetch_age_trends_button.setDisabled(False)
        self.analyze_button.setDisabled(False)
        self.auth_button.setDisabled(False)
        self.autocomplete_search_button.setDisabled(False)
        self.fetch_main_content_button.setDisabled(False)
        self.fetch_blog_views_button.setDisabled(False)

    def on_fetch_blog_views_finished(self, view_data):
        self.fetch_blog_views_button.setDisabled(False)
        self.progress_bar_bv.setValue(100)
        selected_id = self.bv_mode_group.checkedId()
        header_label = "날짜" if selected_id == 0 else "기간"
        self.blog_views_table.horizontalHeaderItem(0).setText(header_label)
        if not view_data:
            self.status_label_bv.setText("❌ 수집된 조회수 데이터가 없습니다.")
            self.log_message("WARNING", "블로그 조회수 순위 수집 결과가 없습니다.")
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
            return
        self.blog_views_df = pd.DataFrame(view_data)
        self.status_label_bv.setText(f"✅ {len(self.blog_views_df)}개 데이터 수집 완료!")
        self.log_message("SUCCESS", "블로그 조회수 순위 수집이 완료되었습니다.")
        self.populate_blog_views_table(self.blog_views_df)
        self.export_blog_views_button.setDisabled(False)

    def populate_blog_views_table(self, df):
        self.blog_views_table.setRowCount(len(df))
        for row_idx, row_data in enumerate(df.itertuples()):
            self.blog_views_table.setItem(row_idx, 0, QTableWidgetItem(str(row_data.날짜)))
            self.blog_views_table.setItem(row_idx, 1, QTableWidgetItem(str(row_data.순위)))
            self.blog_views_table.setItem(row_idx, 2, QTableWidgetItem(f"{row_data.조회수:,}"))
            title_item = QTableWidgetItem(str(row_data.제목))
            title_item.setData(Qt.ItemDataRole.UserRole, str(row_data.게시물_주소))
            self.blog_views_table.setItem(row_idx, 3, title_item)
        self.blog_views_table.resizeColumnsToContents()
        self.blog_views_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

    def open_browser_link(self, row, column):
        if column == 1:
            item = self.naver_main_table.item(row, column)
            if item and (link := item.data(Qt.ItemDataRole.UserRole)): webbrowser.open(link)

    def open_blog_view_link(self, row, column):
        if column == 3:
            item = self.blog_views_table.item(row, column)
            if item and (link := item.data(Qt.ItemDataRole.UserRole)):
                webbrowser.open(link)
                self.log_message("INFO", f"브라우저에서 링크를 엽니다: {link}")

    def sort_trend_table_by_rank_change(self, logicalIndex):
        if logicalIndex != 2 or not self.currently_displayed_data: return
        self.rank_sort_order = Qt.SortOrder.DescendingOrder if self.rank_sort_order == Qt.SortOrder.AscendingOrder else Qt.SortOrder.AscendingOrder
        new_items = [item for item in self.currently_displayed_data if item["순위변동"] is None]
        other_items = [item for item in self.currently_displayed_data if item["순위변동"] is not None]
        is_descending = self.rank_sort_order == Qt.SortOrder.DescendingOrder
        other_items.sort(key=lambda x: x["순위변동"], reverse=is_descending)
        sorted_data = new_items + other_items
        self.populate_trend_table(sorted_data)
        self.trend_table.horizontalHeader().setSortIndicatorShown(True)
        self.trend_table.horizontalHeader().setSortIndicator(2, self.rank_sort_order)

    def filter_trend_table(self):
        selected_category = self.category_filter_combo.currentText()
        if not self.all_trend_data: return
        key_to_filter = list(self.all_trend_data[0].keys())[0]
        if selected_category == "전체 보기":
            self.currently_displayed_data = self.all_trend_data
        else:
            self.currently_displayed_data = [item for item in self.all_trend_data if item[key_to_filter] == selected_category]
        self.populate_trend_table(self.currently_displayed_data)
        
    def copy_trends_to_analyzer(self):
        if self.trend_table.rowCount() > 0:
<<<<<<< HEAD
            kws = [
                self.trend_table.item(r, 1).text()
                for r in range(self.trend_table.rowCount())
                if not self.trend_table.isRowHidden(r)
            ]
            if not kws:
                self.log_message("WARNING", "복사할 데이터가 없습니다 (필터링 0건).")
                return
            existing = [
                x.strip()
                for x in self.analysis_input_widget.toPlainText().splitlines()
                if x.strip()
            ]
            merged = list(dict.fromkeys(existing + kws))
            self.analysis_input_widget.setPlainText("\n".join(merged))
=======
            keywords = [self.trend_table.item(row, 1).text() for row in range(self.trend_table.rowCount())]
            self.analysis_input_widget.setPlainText("\n".join(keywords))
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
            self.tabs.setCurrentIndex(1)
            self.log_message(
                "INFO", f"중복 제거 후 총 {len(merged)}개 키워드 복사 완료."
            )

    def copy_autocomplete_to_analyzer(self):
<<<<<<< HEAD
        rows = self.autocomplete_table.rowCount()
        if rows > 0:
            kws = [self.autocomplete_table.item(r, 0).text() for r in range(rows)]
            existing = [
                x.strip()
                for x in self.analysis_input_widget.toPlainText().splitlines()
                if x.strip()
            ]
            merged = list(dict.fromkeys(existing + kws))
            self.analysis_input_widget.setPlainText("\n".join(merged))
=======
        if (rows := self.autocomplete_table.rowCount()) > 0:
            keywords = [self.autocomplete_table.item(row, 0).text() for row in range(rows)]
            current_text = self.analysis_input_widget.toPlainText().strip()
            new_text = "\n".join(keywords)
            final_text = f"{current_text}\n{new_text}" if current_text else new_text
            self.analysis_input_widget.setPlainText(final_text.strip())
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
            self.tabs.setCurrentIndex(1)
            self.log_message(
                "INFO", f"중복 제거 후 총 {len(merged)}개 키워드 복사 완료."
            )

    def export_trends_to_excel(self):
        if self.trend_table.rowCount() == 0:
            QMessageBox.warning(self, "경고", "엑셀로 내보낼 데이터가 없습니다.")
            return
<<<<<<< HEAD
        os.makedirs("output", exist_ok=True)
        data = []
        for r in range(self.trend_table.rowCount()):
            if not self.trend_table.isRowHidden(r):
                data.append(
                    {
                        self.trend_table.horizontalHeaderItem(0)
                        .text(): self.trend_table.item(r, 0)
                        .text(),
                        "키워드": self.trend_table.item(r, 1).text(),
                        "순위": int(self.trend_table.item(r, 2).text()),
                        "순위변동": self.trend_table.item(r, 3).text(),
                    }
                )
        if not data:
            QMessageBox.warning(
                self, "경고", "저장할 데이터가 없습니다 (필터링 결과 0건)."
            )
            return
        df = pd.DataFrame(data)
        df.to_excel(
            os.path.join(
                "output", f"trend_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            ),
            index=False,
        )
        QMessageBox.information(
            self, "성공", f"현재 화면의 {len(data)}개 데이터 엑셀 저장 완료."
        )
=======
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        first_header = self.trend_table.horizontalHeaderItem(0).text()
        data_to_export = [{first_header: self.trend_table.item(row, 0).text(), "키워드": self.trend_table.item(row, 1).text(), "순위변동": self.trend_table.item(row, 2).text()} for row in range(self.trend_table.rowCount())]
        df = pd.DataFrame(data_to_export)
        filename = f"trend_keywords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        filepath = os.path.join(output_dir, filename)
        try:
            with pd.ExcelWriter(filepath, engine="xlsxwriter") as writer:
                df.to_excel(writer, index=False, sheet_name="TrendKeywords")
                workbook, worksheet = writer.book, writer.sheets["TrendKeywords"]
                header_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#4F81BD', 'align': 'center', 'valign': 'vcenter', 'border': 1})
                for col_num, value in enumerate(df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                for idx, col in enumerate(df):
                    max_len = max((df[col].astype(str).map(len).max(), len(str(df[col].name)))) + 2
                    if col == "키워드": max_len = 50
                    worksheet.set_column(idx, idx, max_len)
            self.log_message("SUCCESS", f"✅ 성공! '{filename}' 파일이 저장되었습니다.")
            QMessageBox.information(self, "성공", f"'{filename}' 파일이 성공적으로 저장되었습니다.")
        except Exception as e:
            QMessageBox.critical(self, "오류", f"엑셀 파일 저장 중 오류가 발생했습니다:\n{e}")
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b

    def export_to_excel(self):
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "경고", "엑셀로 내보낼 데이터가 없습니다.")
            return
        if (filtered_df := self.results_df[self.results_df["분류"] != "일반"]).empty:
            QMessageBox.information(self, "알림", "저장할 키워드가 없습니다. '일반' 분류만 존재합니다.")
            return
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        filename = f"keyword_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        filepath = os.path.join(output_dir, filename)
        try:
            with pd.ExcelWriter(filepath, engine="xlsxwriter") as writer:
                filtered_df.to_excel(writer, index=False, sheet_name="KeywordAnalysis")
                workbook, worksheet = writer.book, writer.sheets["KeywordAnalysis"]
                header_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#157C66', 'align': 'center', 'valign': 'vcenter', 'border': 1})
                for col_num, value in enumerate(filtered_df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                for idx, col in enumerate(filtered_df):
                    max_len = max((filtered_df[col].astype(str).map(len).max(), len(str(filtered_df[col].name)))) + 2
                    if col == "키워드": max_len = 50
                    worksheet.set_column(idx, idx, max_len)
            self.log_message("SUCCESS", f"✅ 성공! '{filename}' 파일이 저장되었습니다.")
            QMessageBox.information(self, "성공", f"'{filename}' 파일이 성공적으로 저장되었습니다.")
        except Exception as e:
            QMessageBox.critical(self, "오류", f"엑셀 파일 저장 중 오류가 발생했습니다:\n{e}")

    def export_blog_views_to_excel(self):
        if not hasattr(self, "blog_views_df") or self.blog_views_df.empty:
            QMessageBox.warning(self, "경고", "엑셀로 내보낼 데이터가 없습니다.")
            return
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        filename = f"blog_views_rank_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        filepath = os.path.join(output_dir, filename)
        try:
            with pd.ExcelWriter(filepath, engine="xlsxwriter") as writer:
                self.blog_views_df.to_excel(writer, index=False, sheet_name="BlogViewRank")
                workbook = writer.book
                worksheet = writer.sheets["BlogViewRank"]
                header_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#007BFF', 'align': 'center', 'valign': 'vcenter', 'border': 1})
                for col_num, value in enumerate(self.blog_views_df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                for idx, col in enumerate(self.blog_views_df):
                    max_len = max(self.blog_views_df[col].astype(str).map(len).max(), len(str(col))) + 2
                    if col == "제목": max_len = 60
                    if col == "게시물 주소": max_len = 50
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

    def on_update_available(self, current_version):
        self.log_message("INFO", f"현재 프로그램 버전: v{current_version}")

<<<<<<< HEAD
    def closeEvent(self, e):
        if self._closing:
            e.ignore()
            return
        if getattr(self, "is_working", False):
            reply = QMessageBox.question(
                self,
                "종료 경고",
                "수집 작업이 진행 중입니다. 강제 종료하시겠습니까?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                e.ignore()
                return
        self._closing = True
        self.hide()
        e.ignore()
        self.req_close_driver.emit()

    @pyqtSlot()
    def final_quit(self):
        self.bg_thread.quit()
        if not self.bg_thread.wait(3000):
            print("Background thread did not terminate in time. Forcing quit.")
        QApplication.quit()
=======
    def on_update_error(self, error_message):
        self.log_message("WARNING", f"버전 확인 중 오류 발생: {error_message}")

    def closeEvent(self, event):
        if self.auth_process and self.auth_process.is_alive():
            self.auth_process.terminate()
        event.accept()
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b


if __name__ == "__main__":
    freeze_support()
    app = QApplication(sys.argv)
    window = KeywordApp()
    window.show()
    sys.exit(app.exec())
