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

# 사용자의 로컬 환경에 update_checker.py가 있어야 작동합니다.
from update_checker import UpdateChecker, get_current_version

import xml.etree.ElementTree as ET

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from multiprocessing import freeze_support

# Gemini AI SDK
from google import genai
from google.genai import types

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QMessageBox, QLineEdit, QCheckBox, QComboBox, QButtonGroup,
    QDialog, QCalendarWidget, QGroupBox, QSplitter
)
from PyQt6.QtGui import QIcon, QColor, QFont
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal, QDate, QPoint, pyqtSlot


def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def get_app_data_path():
    if sys.platform == "win32":
        return os.path.join(os.getenv("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local")), "KeywordStudio")
    elif sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~/Library/Application Support"), "KeywordStudio")
    else:
        return os.path.join(os.path.expanduser("~/.local/share"), "KeywordStudio")

def load_stylesheet():
    base_qss = """
        * { 
            font-family: 'Pretendard', 'Apple SD Gothic Neo', 'Malgun Gothic', sans-serif; 
            font-size: 10pt;
            color: #343A40;
        }
        QMainWindow, QWidget { background-color: #F8F9FA; }

        QTabWidget::pane { 
            border: 1px solid #DEE2E6; 
            background-color: #FFFFFF; 
            border-radius: 8px; 
            margin-top: -1px;
        }
        QTabBar::tab { 
            background: transparent; color: #868E96; padding: 10px 20px; font-weight: bold; border-bottom: 3px solid transparent; 
        }
        QTabBar::tab:hover { color: #495057; }
        QTabBar::tab:selected { color: #6F42C1; border-bottom: 3px solid #6F42C1; }

        QPushButton { 
            background-color: #FFFFFF; border: 1px solid #CED4DA; border-radius: 6px; padding: 8px 12px; font-weight: bold; color: #495057;
        }
        QPushButton:hover { background-color: #F1F3F5; border: 1px solid #ADB5BD; }
        QPushButton:disabled { background-color: #E9ECEF; color: #ADB5BD; border: 1px solid #E9ECEF; }

        QPushButton#primaryBtn, QPushButton[objectName="TrendButton"] { 
            background-color: #339AF0; color: white; border: none; 
        }
        QPushButton#primaryBtn:hover, QPushButton[objectName="TrendButton"]:hover { background-color: #228BE6; }

        QPushButton#AiButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8E2DE2, stop:1 #4A00E0);
            color: white; border: none; font-size: 10pt;
        }
        QPushButton#AiButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7B2CBF, stop:1 #3B00B3);
        }

        QLineEdit, QTextEdit { 
            background-color: #FFFFFF; border: 1px solid #CED4DA; border-radius: 6px; padding: 8px; color: #495057;
        }
        QLineEdit:focus, QTextEdit:focus { border: 1px solid #6F42C1; }
        
        QCheckBox { spacing: 8px; font-weight: 500; }
        QCheckBox::indicator { width: 16px; height: 16px; border: 2px solid #CED4DA; border-radius: 4px; background-color: #FFFFFF; }
        QCheckBox::indicator:hover { border: 2px solid #6F42C1; }
        QCheckBox::indicator:checked { background-color: #6F42C1; border: 2px solid #6F42C1; image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik05IDE2LjE3TDQuODMgMTIgMy40MSAxMy40MSA5IDE5IDIxIDcgMTkuNTkgNS41OXoiLz48L3N2Zz4=); }

        QTableWidget { 
            border: 1px solid #E9ECEF; background-color: #FFFFFF; alternate-background-color: #F8F9FA; 
            selection-background-color: #E5DBFF; selection-color: #495057; gridline-color: transparent; 
            outline: 0; border-radius: 6px;
        }
        QHeaderView::section { 
            background-color: #FFFFFF; border: none; border-bottom: 2px solid #DEE2E6; padding: 8px; font-weight: bold; color: #868E96; 
        }
        QTableWidget::item { border-bottom: 1px solid #F1F3F5; padding: 5px; }

        QProgressBar { 
            border: 1px solid #CED4DA; background-color: #F8F9FA; border-radius: 6px; 
            text-align: center; color: #495057; font-weight: bold; min-height: 18px; 
        }
        QProgressBar::chunk { 
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4FACFE, stop:1 #00F2FE); border-radius: 5px; 
        }

        QSplitter::handle { background-color: #DEE2E6; margin: 2px; border-radius: 2px; }
        QSplitter::handle:horizontal { width: 4px; }
        QSplitter::handle:vertical { height: 4px; }

        QGroupBox { font-weight: bold; border: 1px solid #DEE2E6; border-radius: 8px; margin-top: 14px; background-color: #FFFFFF;}
        QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 8px; left: 12px; color: #495057;}
        QTextEdit#LogWindow { background-color: #212529; color: #F8F9FA; border: none; font-family: 'Consolas', monospace; font-size: 9pt;}
    """
    try:
        with open(resource_path("style.qss"), "r", encoding="utf-8") as f:
            return base_qss + f.read()
    except FileNotFoundError:
        return base_qss

class Signature:
    @staticmethod
    def generate(timestamp, method, uri, secret_key):
        message = f"{timestamp}.{method}.{uri}"
        hash_val = hmac.new(bytes(secret_key, "utf-8"), bytes(message, "utf-8"), hashlib.sha256)
        return base64.b64encode(hash_val.digest()).decode("utf-8")

class ApiCallError(Exception):
    def __init__(self, message, status_code=None, original_exception=None):
        super().__init__(message)
        self.status_code = status_code
        self.original_exception = original_exception

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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS keyword_metrics (
                    keyword TEXT PRIMARY KEY, pc INTEGER NOT NULL DEFAULT 0, mobile INTEGER NOT NULL DEFAULT 0,
                    post_count INTEGER NOT NULL DEFAULT 0, search_updated_at TEXT, doc_updated_at TEXT
                )
            """)
            conn.commit()

    def prune_expired(self, search_ttl_hours=72, doc_ttl_hours=24):
        now = datetime.now()
        search_cutoff = (now - timedelta(hours=search_ttl_hours * 4)).isoformat()
        doc_cutoff = (now - timedelta(hours=doc_ttl_hours * 4)).isoformat()
        conn = self._get_conn()
        with self._lock:
            conn.execute("""
                DELETE FROM keyword_metrics WHERE (search_updated_at IS NULL OR search_updated_at < ?)
                  AND (doc_updated_at IS NULL OR doc_updated_at < ?)
            """, (search_cutoff, doc_cutoff))
            conn.commit()

    @staticmethod
    def _parse_ts(value):
        if not value: return None
        try: return datetime.fromisoformat(value)
        except ValueError: return None

    def get_metrics(self, keyword, search_ttl_hours=72, doc_ttl_hours=24):
        now = datetime.now()
        cached = self.l1_cache.get(keyword)
        if cached:
            search_ok = cached.get("search_updated_at") and (now - cached["search_updated_at"] < timedelta(hours=search_ttl_hours))
            doc_ok = cached.get("doc_updated_at") and (now - cached["doc_updated_at"] < timedelta(hours=doc_ttl_hours))
            if search_ok and doc_ok:
                return {"pc": cached["pc"], "mobile": cached["mobile"], "post_count": cached["post_count"], "search_fresh": True, "doc_fresh": True}

        conn = self._get_conn()
        row = conn.execute("SELECT pc, mobile, post_count, search_updated_at, doc_updated_at FROM keyword_metrics WHERE keyword = ?", (keyword,)).fetchone()
        if not row: return None

        search_up = self._parse_ts(row["search_updated_at"])
        doc_up = self._parse_ts(row["doc_updated_at"])
        data = {"pc": int(row["pc"] or 0), "mobile": int(row["mobile"] or 0), "post_count": int(row["post_count"] or 0), "search_updated_at": search_up, "doc_updated_at": doc_up}
        self.l1_cache[keyword] = data
        return {"pc": data["pc"], "mobile": data["mobile"], "post_count": data["post_count"],
                "search_fresh": bool(search_up and (now - search_up < timedelta(hours=search_ttl_hours))),
                "doc_fresh": bool(doc_up and (now - doc_up < timedelta(hours=doc_ttl_hours)))}

    def upsert_search_volume(self, keyword, pc, mobile):
        now = datetime.now()
        conn = self._get_conn()
        with self._lock:
            conn.execute("""
                INSERT INTO keyword_metrics (keyword, pc, mobile, search_updated_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(keyword) DO UPDATE SET pc=excluded.pc, mobile=excluded.mobile, search_updated_at=excluded.search_updated_at
            """, (keyword, int(pc), int(mobile), now.isoformat()))
            conn.commit()
        existing = self.l1_cache.get(keyword, {})
        self.l1_cache[keyword] = {"pc": int(pc), "mobile": int(mobile), "post_count": int(existing.get("post_count", 0)), "search_updated_at": now, "doc_updated_at": existing.get("doc_updated_at")}

    def upsert_post_count(self, keyword, post_count):
        now = datetime.now()
        conn = self._get_conn()
        with self._lock:
            conn.execute("""
                INSERT INTO keyword_metrics (keyword, post_count, doc_updated_at) VALUES (?, ?, ?)
                ON CONFLICT(keyword) DO UPDATE SET post_count=excluded.post_count, doc_updated_at=excluded.doc_updated_at
            """, (keyword, int(post_count), now.isoformat()))
            conn.commit()
        existing = self.l1_cache.get(keyword, {})
        self.l1_cache[keyword] = {"pc": int(existing.get("pc", 0)), "mobile": int(existing.get("mobile", 0)), "post_count": int(post_count), "search_updated_at": existing.get("search_updated_at"), "doc_updated_at": now}

def get_naver_ad_keywords(keyword, api_key, secret_key, customer_id, session=None):
    if not all([api_key, secret_key, customer_id]): raise ValueError("광고 API 키가 설정되지 않았습니다.")
    signature_generator = Signature()
    base_url, uri, method = "https://api.searchad.naver.com", "/keywordstool", "GET"
    timestamp = str(round(time.time() * 1000))
    signature = signature_generator.generate(timestamp, method, uri, secret_key)
    headers = {"Content-Type": "application/json; charset=UTF-8", "X-Timestamp": timestamp, "X-API-KEY": api_key, "X-Customer": str(customer_id), "X-Signature": signature}
    params = {"hintKeywords": keyword.replace(" ", ""), "showDetail": "1"}
    req_session = session or requests
    try:
        r = req_session.get(base_url + uri, params=params, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json().get("keywordList", [])
    except requests.exceptions.HTTPError as e:
        raise ApiCallError(f"광고 API HTTP 오류", status_code=e.response.status_code if e.response is not None else None, original_exception=e) from e
    except Exception as e:
        raise ApiCallError(f"광고 API 호출 실패: {e}", original_exception=e) from e

def get_blog_post_count(keyword, client_id, client_secret, session=None):
    if not all([client_id, client_secret]): raise ValueError("검색 API 키가 설정되지 않았습니다.")
    url = f"https://openapi.naver.com/v1/search/blog?query={quote(keyword)}"
    headers = {"X-Naver-Client-Id": client_id, "X-Naver-Client-Secret": client_secret}
    req_session = session or requests
    try:
        response = req_session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get("total", 0)
    except requests.exceptions.HTTPError as e:
        raise ApiCallError(f"블로그 검색 API HTTP 오류", status_code=e.response.status_code if e.response is not None else None, original_exception=e) from e
    except Exception as e:
        raise ApiCallError(f"블로그 검색 API 호출 실패: {e}", original_exception=e) from e

class MonthPickerDialog(QDialog):
    month_selected = pyqtSignal(QDate)
    def __init__(self, current_date, parent=None):
        super().__init__(parent)
        self.setWindowTitle("월 선택")
        self.current_year, self.selected_month = current_date.year(), current_date.month()
        layout = QVBoxLayout(self)
        year_layout = QHBoxLayout()
        self.prev_year_btn, self.next_year_btn = QPushButton("<"), QPushButton(">")
        self.year_label = QLabel(str(self.current_year))
        self.year_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        year_layout.addWidget(self.prev_year_btn); year_layout.addWidget(self.year_label); year_layout.addWidget(self.next_year_btn)
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

    def prev_year(self): self.current_year -= 1; self.year_label.setText(str(self.current_year))
    def next_year(self): self.current_year += 1; self.year_label.setText(str(self.current_year))
    def select_month(self, month): self.month_selected.emit(QDate(self.current_year, month, 1)); self.accept()

class WeeklyCalendarWidget(QCalendarWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_week_start = None
    def set_selected_date(self, date): self.setSelectedDate(date); self.update_selection(date)
    def update_selection(self, date):
        self.selected_week_start = date.addDays(-(date.dayOfWeek() - 1))
        self.updateCells()
    def paintCell(self, painter, rect, date):
        super().paintCell(painter, rect, date)
        if self.selected_week_start:
            if self.selected_week_start <= date <= self.selected_week_start.addDays(6):
                painter.setBrush(QColor(220, 235, 255, 100)); painter.setPen(Qt.PenStyle.NoPen); painter.drawRect(rect)

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
    ai_extract_done = pyqtSignal(list)

    CATEGORIES = [
        "맛집", "국내여행", "세계여행", "비즈니스·경제", "패션·미용", "상품리뷰", "일상·생각", "건강·의학", "육아·결혼", "요리·레시피",
        "IT·컴퓨터", "교육·학문", "자동차", "인테리어·DIY", "스포츠", "취미", "방송", "게임", "스타·연예인", "영화",
        "공연·전시", "반려동물", "사회·정치", "드라마", "어학·외국어", "문학·책", "음악", "만화·애니", "좋은글·이미지", "미술·디자인",
        "원예·재배", "사진"
    ]
    DEMO_CODES = ["f_05", "f_06", "f_04", "f_07", "f_03", "f_08", "m_07", "m_06", "m_05", "f_09", "m_08", "m_04", "m_09", "f_10", "f_11", "m_11", "m_03", "f_02", "m_10", "m_02", "f_01", "m_01"]
    DEMO_MAP = {
        "f_01": "0-12세 여자", "f_02": "13-18세 여자", "f_03": "19-24세 여자", "f_04": "25-29세 여자", "f_05": "30-34세 여자", "f_06": "35-39세 여자", "f_07": "40-44세 여자", "f_08": "45-49세 여자", "f_09": "50-54세 여자", "f_10": "55-59세 여자", "f_11": "60세- 여자",
        "m_01": "0-12세 남자", "m_02": "13-18세 남자", "m_03": "19-24세 남자", "m_04": "25-29세 남자", "m_05": "30-34세 남자", "m_06": "35-39세 남자", "m_07": "40-44세 남자", "m_08": "45-49세 남자", "m_09": "50-54세 남자", "m_10": "55-59세 남자", "m_11": "60세- 남자",
    }

    def __init__(self):
        super().__init__()
        self.driver = None
        self.cache_manager = KeywordCacheManager(get_app_data_path())

    @staticmethod
    def _get_fetch_script(url):
        return f"""
        var done = arguments[0];
        fetch("{url}")
            .then(r => {{
                if (!r.ok) return r.text().then(t => done(JSON.stringify({{__fetch_error__: true, status: r.status, body: t.slice(0, 300)}})));
                return r.text().then(t => done(t));
            }})
            .catch(e => done(JSON.stringify({{__fetch_error__: true, message: String(e)}})));
        """

    @staticmethod
    def _validate_response(res_text):
        if not res_text: raise ValueError("응답이 비어있습니다.")
        try:
            d = json.loads(res_text)
            if isinstance(d, dict) and d.get("__fetch_error__"): raise ValueError(f"HTTP 통신 에러 (Status: {d.get('status')}) - {d.get('body', '')}")
            if not isinstance(d, dict) or "data" not in d or not isinstance(d["data"], list): raise ValueError("네이버 API의 data 구조가 예상과 다릅니다.")
            return d
        except json.JSONDecodeError: raise ValueError(f"JSON 파싱 실패 (응답 일부: {res_text[:100]}...)")

    @staticmethod
    def _validate_blog_views_response(res_text):
        if not res_text: raise ValueError("응답이 비어있습니다.")
        try: d = json.loads(res_text)
        except json.JSONDecodeError: raise ValueError(f"JSON 파싱 실패: {res_text[:100]}")
        if isinstance(d, dict) and d.get("__fetch_error__"): raise ValueError(f"HTTP 에러: {d.get('status')} - {d.get('body', '')}")
        if not isinstance(d, dict) or "result" not in d: raise ValueError("조회수 API 응답 구조가 변경되었습니다.")
        return d

    @staticmethod
    def _parse_rank_change(rc):
        if rc is None: return None
        try: return int(rc)
        except (ValueError, TypeError): return None

    def _check_browser_ready(self, target_domain):
        if not self.driver: raise ValueError("브라우저가 열려있지 않습니다.")
        if "nid.naver.com" in self.driver.current_url: raise ValueError("네이버 로그인 창에 머물러 있습니다. 로그인을 완료해주세요.")
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
        except Exception: pass

        self.log.emit("INFO", "🌐 네이버 전용 브라우저를 엽니다...")
        try:
            service = ChromeService(ChromeDriverManager().install())
            options = webdriver.ChromeOptions()
            options.add_experimental_option("excludeSwitches", ["enable-logging"])
            options.add_argument("--disable-gpu"); options.add_argument("--no-sandbox"); options.add_argument("--disable-dev-shm-usage")
            app_data_path = os.path.join(get_app_data_path(), "ChromeProfile")
            os.makedirs(app_data_path, exist_ok=True)
            options.add_argument(f"--user-data-dir={app_data_path}")

            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.get("https://nid.naver.com/nidlogin.login?url=https://creator-advisor.naver.com/")
            self.browser_opened.emit()
        except Exception as e:
            self.error.emit(f"브라우저 열기 실패: {e}")

    @pyqtSlot()
    def fetch_trends(self):
        try:
            self._check_browser_ready("creator-advisor.naver.com")
            self.log.emit("INFO", "🚀 주제별 트렌드 데이터를 수집합니다...")
            target_date_str = (datetime.now() - timedelta(days=2 if datetime.now().hour < 8 else 1)).strftime("%Y-%m-%d")
            self.driver.set_script_timeout(10)
            all_trends_data = []

            for i, cat in enumerate(self.CATEGORIES):
                self.progress.emit(int((i + 1) / len(self.CATEGORIES) * 100))
                url = f"https://creator-advisor.naver.com/api/v6/trend/category?categories={quote(cat)}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=20&service=naver_blog"
                res_text = self.driver.execute_async_script(self._get_fetch_script(url))
                try:
                    d = self._validate_response(res_text)
                    if d["data"] and isinstance(d["data"][0], dict) and "queryList" in d["data"][0]:
                        for r_idx, item in enumerate(d["data"][0]["queryList"], 1):
                            rc = self._parse_rank_change(item.get("rankChange"))
                            all_trends_data.append({"카테고리": cat, "순위": r_idx, "키워드": item.get("query", "N/A"), "순위변동": rc})
                except Exception as e: self.log.emit("WARNING", f"[{cat}] 파싱/통신 실패: {e}")
                time.sleep(0.3)
            self.trends_done.emit(all_trends_data)
        except Exception as e: self.error.emit(f"수집 실패: {e}")

    @pyqtSlot()
    def fetch_age_trends(self):
        try:
            self._check_browser_ready("creator-advisor.naver.com")
            self.log.emit("INFO", "🚀 연령별 트렌드 데이터를 수집합니다...")
            target_date_str = (datetime.now() - timedelta(days=2 if datetime.now().hour < 8 else 1)).strftime("%Y-%m-%d")
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
                    if d["data"] and isinstance(d["data"][0], dict) and "queryList" in d["data"][0]:
                        for r_idx, item in enumerate(d["data"][0]["queryList"], 1):
                            rc = self._parse_rank_change(item.get("rankChange"))
                            all_age_trends.append({"연령대": group_name, "순위": r_idx, "키워드": item.get("query", "N/A"), "순위변동": rc})
                except Exception as e: self.log.emit("WARNING", f"[{group_name}] 파싱/통신 실패: {e}")
                time.sleep(0.3)
            self.age_trends_done.emit(all_age_trends)
        except Exception as e: self.error.emit(f"수집 실패: {e}")

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
            results = [{"rank": str(i), "title": item.get("title"), "link": item.get("url")} for i, item in enumerate(d.get("data", []), 1)]
            self.main_inflow_done.emit(results)
        except Exception as e: self.error.emit(f"수집 실패: {e}")

    @pyqtSlot(object, object, str)
    def fetch_blog_views(self, start_date, end_date, time_dimension):
        try:
            self._check_browser_ready("blog.stat.naver.com")
            self.log.emit("INFO", "🚀 블로그 조회수 데이터를 수집합니다...")
            dates = ([start_date + timedelta(days=i) for i in range(0, (end_date - start_date).days + 1, 7 if time_dimension == "WEEK" else 1)]
                if time_dimension in ["DATE", "WEEK"] else [start_date])
            all_view = []
            self.driver.set_script_timeout(10)

            for i, d in enumerate(dates):
                self.progress.emit(int((i + 1) / len(dates) * 100))
                ds = d.strftime("%Y-%m-%d")
                url = f"https://blog.stat.naver.com/api/blog/rank/cvContentPc?timeDimension={time_dimension}&startDate={ds}"
                res_text = self.driver.execute_async_script(self._get_fetch_script(url))
                try:
                    r_json = self._validate_blog_views_response(res_text)
                    if "result" in r_json and (rows := r_json["result"].get("statDataList", [{}])[0].get("data", {}).get("rows")):
                        for dt, rank, cv, title, uri in zip(rows.get("date", []), rows.get("rank", []), rows.get("cv", []), rows.get("title", []), rows.get("uri", [])):
                            all_view.append({
                                "날짜": dt, "순위": rank, "조회수": cv, "제목": title,
                                "게시물_주소": (uri if uri.startswith("http") else f"https://blog.naver.com{uri}"),
                            })
                except Exception as e: self.log.emit("WARNING", f"조회수 파싱 오류: {e}")
                time.sleep(0.3)
            self.blog_views_done.emit(all_view)
        except Exception as e: self.error.emit(f"수집 실패: {e}")

    @staticmethod
    def _safe_pause_after_api_call(): time.sleep(random.uniform(0.2, 0.45))
    @staticmethod
    def _backoff_sleep(attempt, base_seconds, cap_seconds):
        wait = min(cap_seconds, base_seconds * (2 ** attempt)) + random.uniform(0.15, 0.6)
        time.sleep(wait)
        return wait
    @staticmethod
    def _extract_search_volume(ad_data, keyword):
        pc, mob = 0, 0
        if ad_data and (matched := next((it for it in ad_data if it.get("relKeyword") == keyword), None)):
            pc_str, mob_str = str(matched.get("monthlyPcQcCnt", 0)), str(matched.get("monthlyMobileQcCnt", 0))
            pc, mob = (5 if "<" in pc_str else int(pc_str)), (5 if "<" in mob_str else int(mob_str))
        return pc, mob
    def _call_api_with_backoff(self, func, api_name, original_kw, max_retries=3):
        for attempt in range(max_retries):
            try: return func()
            except ApiCallError as e:
                status_code = e.status_code
                if status_code in [401, 403]: raise
                if status_code == 429:
                    wait = self._backoff_sleep(attempt, 2.5, 15)
                    self.log.emit("WARNING", f"'{original_kw}' {api_name} 호출 제한(429) - {wait:.1f}초 후 재시도합니다.")
                    continue
                if "timeout" in str(e).lower():
                    wait = self._backoff_sleep(attempt, 1.5, 8)
                    self.log.emit("WARNING", f"'{original_kw}' {api_name} 응답 지연 - {wait:.1f}초 후 재시도합니다.")
                    continue
                if attempt < max_retries - 1:
                    wait = self._backoff_sleep(attempt, 1.2, 6)
                    self.log.emit("WARNING", f"'{original_kw}' {api_name} 일시 오류 - {wait:.1f}초 후 재시도합니다.")
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
                if not kw_api: continue

                api_called = False
                try:
                    cached = self.cache_manager.get_metrics(kw_api, search_ttl_hours=72, doc_ttl_hours=24) or {
                        "pc": 0, "mobile": 0, "post_count": 0, "search_fresh": False, "doc_fresh": False,
                    }

                    pc, mob, post_count = cached["pc"], cached["mobile"], cached["post_count"]

                    if cached["search_fresh"]: self.log.emit("INFO", f"'{original_kw}' 검색량 캐시 ⚡ 사용")
                    else:
                        ad_data = self._call_api_with_backoff(lambda: get_naver_ad_keywords(kw_api, api_keys["ads_key"], api_keys["ads_secret"], api_keys["customer_id"], session), "광고 API", original_kw)
                        pc, mob = self._extract_search_volume(ad_data, kw_api)
                        self.cache_manager.upsert_search_volume(kw_api, pc, mob)
                        api_called = True

                    if cached["doc_fresh"]: self.log.emit("INFO", f"'{original_kw}' 문서수 캐시 ⚡ 사용")
                    else:
                        post_count = self._call_api_with_backoff(lambda: get_blog_post_count(kw_api, api_keys["client_id"], api_keys["client_secret"], session), "블로그 검색 API", original_kw)
                        self.cache_manager.upsert_post_count(kw_api, post_count)
                        api_called = True

                    tot_search = pc + mob
                    opp_idx = (tot_search / post_count) if post_count > 0 else 0
                    cat = "🏆 황금" if opp_idx >= 0.2 else ("✨ 매력" if opp_idx >= 0.05 and tot_search >= 1000 else "일반")
                    
                    analysis_results.append({"분류": cat, "키워드": original_kw, "총검색량": tot_search, "총문서수": post_count, "기회지수": round(opp_idx, 2)})
                except ApiCallError as e:
                    if e.status_code == 401: self.log.emit("ERROR", f"'{original_kw}' 오류: API 키/시크릿이 잘못되었습니다 (401).")
                    elif e.status_code == 403: self.log.emit("ERROR", f"'{original_kw}' 오류: API 권한이 없습니다 (403).")
                    elif e.status_code == 429: self.log.emit("WARNING", f"'{original_kw}' 오류: 호출 제한이 계속 발생하여 이번 키워드는 건너뜁니다.")
                    else: self.log.emit("ERROR", f"'{original_kw}' 분석 오류: {e}")
                except Exception as e: self.log.emit("ERROR", f"'{original_kw}' 분석 오류: {e}")
                finally:
                    if api_called: self._safe_pause_after_api_call()

        self.analysis_done.emit(pd.DataFrame(analysis_results))

    @pyqtSlot(str, list)
    def fetch_autocomplete(self, keyword, engines):
        res = set()
        with requests.Session() as s:
            if "naver" in engines:
                try:
                    r = s.get(f"https://ac.search.naver.com/nx/ac?q_enc=UTF-8&st=100&r_format=json&q={quote(keyword)}", headers={"User-Agent": "Mozilla"}, timeout=5)
                    r.raise_for_status()
                    if items := r.json().get("items"):
                        for i in items[0]: res.add(i[0])
                except Exception as e: self.log.emit("WARNING", f"네이버 자동완성 오류: {e}")
            if "daum" in engines:
                try:
                    r = s.get(f"https://suggest.search.daum.net/sushi/opensearch/pc?q={quote(keyword)}", headers={"User-Agent": "Mozilla"}, timeout=5)
                    r.raise_for_status()
                    if "json" in r.headers.get("Content-Type", "").lower():
                        d = r.json()
                        if isinstance(d, list) and len(d) > 1:
                            for it in d[1]: res.add(it.strip())
                    else:
                        for it in ET.fromstring(r.content).findall(".//item/keyword"):
                            if it.text: res.add(it.text.strip())
                except Exception as e: self.log.emit("WARNING", f"Daum 자동완성 오류: {e}")
            if "google" in engines:
                try:
                    r = s.get(f"https://suggestqueries.google.com/complete/search?client=firefox&output=json&q={quote(keyword)}", headers={"User-Agent": "Mozilla"}, timeout=5)
                    r.raise_for_status()
                    if isinstance((d := r.json()), list) and len(d) > 1:
                        for it in d[1]: res.add(it.strip())
                except Exception as e: self.log.emit("WARNING", f"Google 자동완성 오류: {e}")
        self.autocomplete_done.emit(sorted(list(res)))

    @pyqtSlot(list, str, str)
    def extract_ai_keywords(self, raw_trends, api_key, model_name):
        if not api_key:
            self.error.emit("GEMINI_API_KEY가 설정되지 않았습니다. api.env를 확인하세요.")
            return

        self.log.emit("INFO", "🤖 Gemini AI가 맞춤형 롱테일 키워드를 추출 중입니다...")
        try:
            client = genai.Client(api_key=api_key)
            prompt = f"""
            당신은 한국 최고의 블로그 SEO 및 롱테일 키워드 추출 전문가입니다.
            다음 제공된 [트렌드 제목 목록]을 분석하여, 사람들이 네이버 검색창에 실제로 입력할 만한 '가치 있는 롱테일 명사 키워드'만 추출하세요.

            [엄격한 제약 규칙 - 반드시 준수할 것]
            1. 문맥에 맞지 않는 조사, 서술어, 부사(예: 10살, 자랑, 성사, 떴다 등)는 철저히 배제하세요.
            2. 한 문장에서 추출할 키워드가 없다면 억지로 만들지 말고 과감히 무시하세요. (0~3개 추출)
            3. 추출된 키워드에는 특수문자(기호, 쉼표, 괄호 등)가 절대 포함되어서는 안 되며 오직 한글, 영문, 숫자, 공백만 허용됩니다.

            [예시(Few-shot)]
            - 입력: "공효진, 10살 연하 남편 케빈오 자랑"
            - 출력: "공효진 남편", "케빈오", "공효진 케빈오"
            - 입력: "제니 샤넬쇼 망사 패션 빛났다"
            - 출력: "제니 패션", "제니 샤넬쇼", "샤넬쇼 망사"

            [트렌드 제목 목록]
            {json.dumps(raw_trends, ensure_ascii=False)}

            출력 형식은 반드시 아래 JSON 배열 포맷을 엄격히 지켜주세요. 다른 설명이나 인사말은 절대 추가하지 마세요.
            ["키워드1", "키워드2", "키워드3", ...]
            """
            response = client.models.generate_content(
                model=model_name or "gemini-3.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.2),
            )
            extracted = json.loads(response.text)
            self.ai_extract_done.emit(extracted)
        except Exception as e:
            self.error.emit(f"AI 추출 실패: {e}")

    @pyqtSlot()
    def close_driver(self):
        if self.driver:
            try: self.driver.quit()
            except Exception as e: self.log.emit("WARNING", f"드라이버 종료 지연: {e}")
            self.driver = None
        self.driver_closed.emit()


class KeywordApp(QMainWindow):
    req_open_browser = pyqtSignal()
    req_fetch_trends = pyqtSignal()
    req_fetch_age_trends = pyqtSignal()
    req_fetch_main = pyqtSignal()
    req_fetch_views = pyqtSignal(object, object, str)
    req_fetch_analysis = pyqtSignal(list, dict)
    req_fetch_autocomplete = pyqtSignal(str, list)
    req_ai_extract = pyqtSignal(list, str, str)
    req_close_driver = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.current_version = get_current_version()
        self.setWindowTitle(f"Keyword Studio (Powered by Gemini 3.1 Pro) v{self.current_version}")

        self.is_working = False
        self._closing = False
        self.current_task = ""

        self.cached_data = {"trends": None, "age_trends": None, "main_inflow": None, "blog_views": {}, "analysis": {}, "auto": {}}
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

        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet(load_stylesheet())

        if getattr(sys, "frozen", False): app_dir = os.path.dirname(sys.executable)
        else: app_dir = os.path.dirname(os.path.abspath(__file__))

        env_path = os.path.join(app_dir, "api.env")
        load_dotenv(env_path)

        self.API_KEYS = {
            "ads_key": os.getenv("NAVER_ADS_API_KEY"),
            "ads_secret": os.getenv("NAVER_ADS_API_SECRET"),
            "customer_id": os.getenv("NAVER_ADS_CUSTOMER_ID"),
            "client_id": os.getenv("NAVER_SEARCH_CLIENT_ID"),
            "client_secret": os.getenv("NAVER_SEARCH_CLIENT_SECRET"),
            "gemini_key": os.getenv("GEMINI_API_KEY"),
            "gemini_model": os.getenv("GEMINI_MODEL_NAME", "gemini-3.5-flash"),
        }

        icon_path = resource_path("keyword_pro.ico")
        if os.path.exists(icon_path): self.setWindowIcon(QIcon(icon_path))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        top_level_layout = QVBoxLayout(central_widget)
        top_level_layout.setContentsMargins(10, 10, 10, 10)

        self.create_settings_bar(top_level_layout)

        self.global_splitter = QSplitter(Qt.Orientation.Vertical)
        top_level_layout.addWidget(self.global_splitter)

        self.tabs = QTabWidget()
        self.global_splitter.addWidget(self.tabs)

        self.create_trend_fetch_tab()
        self.create_analysis_tab()
        self.create_autocomplete_tab()
        self.create_naver_main_tab()
        self.create_blog_views_tab()

        log_group_box = QGroupBox("📜 실시간 로그")
        log_layout = QVBoxLayout(log_group_box)
        log_layout.setContentsMargins(8, 8, 8, 8)
        self.log_widget = QTextEdit()
        self.log_widget.setObjectName("LogWindow")
        self.log_widget.setReadOnly(True)
        log_layout.addWidget(self.log_widget)
        self.global_splitter.addWidget(log_group_box)
        
        self.global_splitter.setSizes([600, 200])

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
        self.req_ai_extract.connect(self.bg_worker.extract_ai_keywords)
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
        self.bg_worker.ai_extract_done.connect(self.on_ai_extract_done)

        self.bg_thread.start()

        missing_keys = [k for k, v in self.API_KEYS.items() if not v and k != "gemini_model"]
        if missing_keys:
            self.log_message("ERROR", f"❌ api.env 파일 인식 오류: 다음 키가 누락되었습니다 -> {', '.join(missing_keys)}")
            self.log_message("WARNING", f"📁 인식된 env 경로: {env_path}")
        else:
            self.log_message("SUCCESS", "✅ 모든 API 키가 정상적으로 로드되었습니다.")

    def _finish_task_state(self):
        self.is_working = False
        self.current_task = ""
        self.set_all_buttons_disabled(False)

    @staticmethod
    def _add_to_cache(cache_dict, key, value, limit=30):
        cache_dict[key] = value
        if len(cache_dict) > limit:
            first_key = next(iter(cache_dict))
            del cache_dict[first_key]

    @staticmethod
    def update_button_style(btn, is_cached, original_text):
        btn.setProperty("cached", "true" if is_cached else "false")
        btn.style().unpolish(btn)
        btn.style().polish(btn)
        btn.setText(f"{original_text} (캐시됨)" if is_cached else original_text)

    def check_views_cache_state(self):
        cid = self.bv_mode_group.checkedId()
        time_dim = {0: "DATE", 1: "WEEK", 2: "MONTH"}[cid]
        d = self.bv_current_date
        if cid == 0: sd, ed = d.toPyDate(), d.toPyDate()
        elif cid == 1:
            sw = d.addDays(-(d.dayOfWeek() - 1))
            sd, ed = sw.toPyDate(), sw.addDays(6).toPyDate()
        elif cid == 2:
            sd, ed = (QDate(d.year(), d.month(), 1).toPyDate(), QDate(d.year(), d.month(), d.daysInMonth()).toPyDate())

        cache_key = f"{sd}_{ed}_{time_dim}"
        is_cached = cache_key in self.cached_data.get("blog_views", {})
        self.update_button_style(self.fetch_blog_views_button, is_cached, "조회수 순위 가져오기")

    def check_analysis_cache_state(self):
        keywords = [kw.strip() for kw in self.analysis_input_widget.toPlainText().strip().split("\n") if kw.strip()]
        cache_key = tuple(sorted(list(set(keywords))))
        is_cached = bool(keywords) and cache_key in self.cached_data.get("analysis", {})
        self.update_button_style(self.analyze_button, is_cached, "기회지수 분석 시작")

    def check_auto_cache_state(self):
        kw = self.autocomplete_input.text().strip()
        engines = [name for cb, name in [("naver", "naver"), ("daum", "daum"), ("google", "google")] if getattr(self, f"cb_{cb}").isChecked()]
        cache_key = f"{kw}_{'-'.join(sorted(engines))}"
        is_cached = bool(kw) and bool(engines) and cache_key in self.cached_data.get("auto", {})
        self.update_button_style(self.autocomplete_search_button, is_cached, "자동완성 검색")

    def set_all_buttons_disabled(self, disabled):
        self.auth_button.setDisabled(disabled)
        self.fetch_trends_button.setDisabled(disabled)
        self.fetch_age_trends_button.setDisabled(disabled)
        self.fetch_main_content_button.setDisabled(disabled)
        self.fetch_blog_views_button.setDisabled(disabled)
        self.analyze_button.setDisabled(disabled)
        self.autocomplete_search_button.setDisabled(disabled)
        self.copy_to_analyzer_button.setDisabled(disabled)
        self.ai_copy_button.setDisabled(disabled)

    def update_progress_bar(self, val):
        if self.current_task in ["trends", "age"]: self.progress_bar_fetch.setValue(val)
        elif self.current_task == "analysis": self.progress_bar_analysis.setValue(val)
        elif self.current_task == "views": self.progress_bar_bv.setValue(val)

    def log_message(self, level, msg):
        if self.log_widget.document().blockCount() > 1000:
            cursor = self.log_widget.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.select(cursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()

        c = {"INFO": "#82C0FF", "SUCCESS": "#28A745", "WARNING": "orange", "ERROR": "#DC3545"}.get(level, "#E0E0E0")
        self.log_widget.append(f'<font color="{c}">[{datetime.now().strftime("%H:%M:%S")}] - {level} - {msg}</font>')

    def create_settings_bar(self, parent_layout):
        settings_frame = QWidget()
        settings_layout = QHBoxLayout(settings_frame)
        settings_layout.setContentsMargins(0, 0, 0, 10)
        self.reset_button = QPushButton("화면 초기화")
        self.reset_button.clicked.connect(self.reset_ui)
        self.auth_button = QPushButton("1. 네이버 연결 (브라우저 열기)")
        self.auth_button.setObjectName("primaryBtn")
        self.auth_button.clicked.connect(self.start_open_browser)
        settings_layout.addStretch()
        settings_layout.addWidget(self.reset_button)
        settings_layout.addWidget(self.auth_button)
        parent_layout.addWidget(settings_frame)

    def create_trend_fetch_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        self.fetch_trends_button = QPushButton("2-1. 주제별 수집")
        self.fetch_trends_button.setObjectName("TrendButton")
        self.fetch_age_trends_button = QPushButton("2-2. 연령별 수집")
        self.fetch_age_trends_button.setObjectName("TrendButton")
        self.copy_to_analyzer_button = QPushButton("일반 복사 → 분석 탭")
        self.ai_copy_button = QPushButton("✨ AI 스마트 변환 복사")
        self.ai_copy_button.setObjectName("AiButton")
        self.category_filter_combo = QComboBox()
        self.trend_search_input = QLineEdit()
        self.trend_search_input.setPlaceholderText("결과 내 검색...")
        self.export_trends_excel_button = QPushButton("엑셀 저장")
        
        self.copy_to_analyzer_button.setDisabled(True)
        self.ai_copy_button.setDisabled(True)
        self.category_filter_combo.setDisabled(True)
        self.trend_search_input.setDisabled(True)
        self.export_trends_excel_button.setDisabled(True)

        left_layout.addWidget(self.fetch_trends_button)
        left_layout.addWidget(self.fetch_age_trends_button)
        left_layout.addWidget(QLabel("필터:"))
        left_layout.addWidget(self.category_filter_combo)
        left_layout.addWidget(self.trend_search_input)
        left_layout.addWidget(self.copy_to_analyzer_button)
        left_layout.addWidget(self.ai_copy_button)
        left_layout.addWidget(self.export_trends_excel_button)
        left_layout.addStretch()

        self.status_label_fetch = QLabel("먼저 [브라우저 열기]를 눌러 로그인 후 수집을 시작하세요.")
        self.status_label_fetch.setWordWrap(True)
        self.progress_bar_fetch = QProgressBar()
        self.progress_bar_fetch.setFormat("진행률: %p%")
        left_layout.addWidget(self.status_label_fetch)
        left_layout.addWidget(self.progress_bar_fetch)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.trend_table = QTableWidget()
        headers = ["카테고리", "원문(트렌드 내용)", "순위", "순위변동"]
        self.trend_table.setColumnCount(len(headers))
        self.trend_table.setHorizontalHeaderLabels(headers)
        self.trend_table.setSortingEnabled(False)
        self.trend_table.horizontalHeader().sectionClicked.connect(self.sort_trend_table)
        right_layout.addWidget(self.trend_table)

        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([200, 800])
        tab_layout.addWidget(main_splitter)
        self.tabs.addTab(tab, "🔥 트렌드 탐색")

        self.fetch_trends_button.clicked.connect(self.start_trend_fetching)
        self.fetch_age_trends_button.clicked.connect(self.start_age_trend_fetching)
        self.copy_to_analyzer_button.clicked.connect(self.copy_trends_to_analyzer)
        self.ai_copy_button.clicked.connect(self.start_ai_copy)
        self.category_filter_combo.currentIndexChanged.connect(self.filter_trend_table)
        self.trend_search_input.textChanged.connect(self.filter_trend_table)
        self.export_trends_excel_button.clicked.connect(self.export_trends_to_excel)

    def create_analysis_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        placeholder_text = "--- 키워드를 입력하거나 붙여넣어 주세요 ---\n\n💡 '기회 지수'란?\n'월간 총검색량 ÷ 블로그 총문서수'로 계산되는 값으로, 문서(공급) 대비 검색량(수요)이 얼마나 높은지를 나타내는 지표입니다."
        self.analysis_input_widget = QTextEdit()
        self.analysis_input_widget.setPlaceholderText(placeholder_text)
        self.analysis_input_widget.textChanged.connect(self.check_analysis_cache_state)

        self.analyze_button = QPushButton("기회지수 분석 시작")
        self.analyze_button.setObjectName("primaryBtn")
        
        # ✨ 엑셀 저장 관련 UI를 수평으로 배치
        export_layout = QHBoxLayout()
        self.export_include_normal_cb = QCheckBox("'일반' 포함")
        self.export_include_normal_cb.setToolTip("체크 시 기회지수가 낮은 '일반' 키워드도 엑셀에 함께 저장됩니다.")
        self.export_excel_button = QPushButton("엑셀로 저장")
        self.export_excel_button.setDisabled(True)
        export_layout.addWidget(self.export_include_normal_cb)
        export_layout.addWidget(self.export_excel_button)

        self.progress_bar_analysis = QProgressBar()
        self.progress_bar_analysis.setFormat("진행률: %p%")
        
        left_layout.addWidget(self.analysis_input_widget, stretch=1)
        left_layout.addWidget(self.analyze_button)
        left_layout.addLayout(export_layout) # 변경된 Layout 삽입
        left_layout.addWidget(self.progress_bar_analysis)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(5)
        self.result_table.setHorizontalHeaderLabels(["분류", "정제된 키워드", "총검색량", "총문서수", "기회지수"])
        right_layout.addWidget(self.result_table)

        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([300, 700])
        tab_layout.addWidget(main_splitter)
        self.tabs.addTab(tab, "🔬 기회지수 분석")
        
        self.analyze_button.clicked.connect(self.start_competition_analysis)
        self.export_excel_button.clicked.connect(self.export_to_excel)

    def create_autocomplete_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        self.autocomplete_input = QLineEdit()
        self.autocomplete_input.setPlaceholderText("자동완성 키워드 입력...")
        self.autocomplete_input.textChanged.connect(lambda _: self.check_auto_cache_state())

        self.cb_naver = QCheckBox("네이버")
        self.cb_daum = QCheckBox("Daum")
        self.cb_google = QCheckBox("Google")
        self.cb_naver.setChecked(True)
        self.cb_daum.setChecked(True)
        self.cb_google.setChecked(True)

        self.cb_naver.stateChanged.connect(lambda _: self.check_auto_cache_state())
        self.cb_daum.stateChanged.connect(lambda _: self.check_auto_cache_state())
        self.cb_google.stateChanged.connect(lambda _: self.check_auto_cache_state())

        self.autocomplete_search_button = QPushButton("자동완성 검색")
        self.autocomplete_search_button.setObjectName("primaryBtn")
        self.autocomplete_copy_button = QPushButton("키워드 → 분석 탭으로 복사")
        
        left_layout.addWidget(QLabel("검색어:"))
        left_layout.addWidget(self.autocomplete_input)
        left_layout.addWidget(QLabel("검색 엔진:"))
        left_layout.addWidget(self.cb_naver)
        left_layout.addWidget(self.cb_daum)
        left_layout.addWidget(self.cb_google)
        left_layout.addSpacing(10)
        left_layout.addWidget(self.autocomplete_search_button)
        left_layout.addWidget(self.autocomplete_copy_button)
        left_layout.addStretch()

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.autocomplete_table = QTableWidget()
        self.autocomplete_table.setColumnCount(1)
        self.autocomplete_table.setHorizontalHeaderLabels(["자동완성 키워드"])
        self.autocomplete_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        right_layout.addWidget(self.autocomplete_table)

        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([200, 800])
        tab_layout.addWidget(main_splitter)
        self.tabs.addTab(tab, "🤖 연관/자동완성")
        
        self.autocomplete_search_button.clicked.connect(self.start_autocomplete_search)
        self.autocomplete_input.returnPressed.connect(self.start_autocomplete_search)
        self.autocomplete_copy_button.clicked.connect(self.copy_autocomplete_to_analyzer)

    def create_naver_main_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        self.fetch_main_content_button = QPushButton("메인 유입콘텐츠 가져오기")
        self.fetch_main_content_button.setObjectName("primaryBtn")
        hint_label = QLabel("💡 더블클릭으로 해당 링크 이동")
        hint_label.setStyleSheet("color: #868E96; font-size: 9pt;")
        
        left_layout.addWidget(self.fetch_main_content_button)
        left_layout.addWidget(hint_label)
        left_layout.addStretch()

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.naver_main_table = QTableWidget()
        self.naver_main_table.setColumnCount(2)
        self.naver_main_table.setHorizontalHeaderLabels(["순위", "제목"])
        self.naver_main_table.verticalHeader().setVisible(False)
        self.naver_main_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        right_layout.addWidget(self.naver_main_table)

        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([200, 800])
        tab_layout.addWidget(main_splitter)
        self.tabs.addTab(tab, "🏆 네이버 메인 유입")
        
        self.fetch_main_content_button.clicked.connect(self.start_fetch_naver_main)
        self.naver_main_table.cellDoubleClicked.connect(self.open_browser_link)

    def create_blog_views_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        date_nav_layout = QHBoxLayout()
        self.bv_prev_btn = QPushButton("<")
        self.bv_date_label = QLabel("")
        self.bv_date_label.setFont(QFont("Pretendard", 10, QFont.Weight.Bold))
        self.bv_date_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.bv_calendar_btn = QPushButton("📅")
        self.bv_next_btn = QPushButton(">")
        self.bv_prev_btn.setFixedSize(30, 30); self.bv_next_btn.setFixedSize(30, 30); self.bv_calendar_btn.setFixedSize(30, 30)
        date_nav_layout.addWidget(self.bv_prev_btn)
        date_nav_layout.addWidget(self.bv_date_label)
        date_nav_layout.addWidget(self.bv_next_btn)
        date_nav_layout.addWidget(self.bv_calendar_btn)
        
        self.bv_mode_group = QButtonGroup(self)
        self.bv_radio_daily = QPushButton("일간")
        self.bv_radio_weekly = QPushButton("주간")
        self.bv_radio_monthly = QPushButton("월간")
        
        mode_layout = QHBoxLayout()
        for btn, idx in zip([self.bv_radio_daily, self.bv_radio_weekly, self.bv_radio_monthly], [0, 1, 2]):
            btn.setCheckable(True)
            self.bv_mode_group.addButton(btn, idx)
            mode_layout.addWidget(btn)
            
        self.fetch_blog_views_button = QPushButton("조회수 순위 가져오기")
        self.fetch_blog_views_button.setObjectName("primaryBtn")
        self.export_blog_views_button = QPushButton("엑셀로 저장")
        self.export_blog_views_button.setDisabled(True)
        
        left_layout.addWidget(QLabel("조회 기간:"))
        left_layout.addLayout(date_nav_layout)
        left_layout.addLayout(mode_layout)
        left_layout.addSpacing(10)
        left_layout.addWidget(self.fetch_blog_views_button)
        left_layout.addWidget(self.export_blog_views_button)
        left_layout.addStretch()
        
        self.status_label_bv = QLabel("조회할 기간을 선택하고 버튼을 눌러주세요.")
        self.status_label_bv.setWordWrap(True)
        self.progress_bar_bv = QProgressBar()
        self.progress_bar_bv.setFormat("진행률: %p%")
        left_layout.addWidget(self.status_label_bv)
        left_layout.addWidget(self.progress_bar_bv)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.blog_views_table = QTableWidget()
        self.blog_views_table.setColumnCount(4)
        self.blog_views_table.setHorizontalHeaderLabels(["날짜", "순위", "조회수", "제목"])
        right_layout.addWidget(self.blog_views_table)

        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([220, 780])
        tab_layout.addWidget(main_splitter)
        self.tabs.addTab(tab, "📈 내 블로그 조회수")

        self.bv_mode_group.buttonClicked.connect(lambda _: self.bv_on_mode_changed())
        self.bv_prev_btn.clicked.connect(self.bv_navigate_prev)
        self.bv_next_btn.clicked.connect(self.bv_navigate_next)
        self.bv_calendar_btn.clicked.connect(self.bv_show_calendar_picker)
        self.fetch_blog_views_button.clicked.connect(self.start_fetch_blog_views)
        self.export_blog_views_button.clicked.connect(self.export_blog_views_to_excel)
        self.blog_views_table.cellDoubleClicked.connect(self.open_blog_view_link)
        self.bv_radio_daily.setChecked(True)
        self.bv_on_mode_changed()

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
        self.check_views_cache_state()

    def bv_navigate_prev(self):
        cid = self.bv_mode_group.checkedId()
        self.bv_current_date = self.bv_current_date.addDays(-1) if cid == 0 else (self.bv_current_date.addDays(-7) if cid == 1 else self.bv_current_date.addMonths(-1))
        self.bv_update_date_display()

    def bv_navigate_next(self):
        cid = self.bv_mode_group.checkedId()
        self.bv_current_date = self.bv_current_date.addDays(1) if cid == 0 else (self.bv_current_date.addDays(7) if cid == 1 else self.bv_current_date.addMonths(1))
        self.bv_update_date_display()

    def bv_show_calendar_picker(self):
        if self.bv_mode_group.checkedId() == 2:
            dialog = MonthPickerDialog(self.bv_current_date, self)
            dialog.month_selected.connect(self.bv_on_date_selected)
            dialog.exec()
            return
        if not self.bv_calendar_popup:
            self.bv_calendar_popup = WeeklyCalendarWidget()
            self.bv_calendar_popup.setWindowFlags(Qt.WindowType.Popup)
            self.bv_calendar_popup.clicked.connect(self.bv_on_date_selected)
        self.bv_calendar_popup.set_selected_date(self.bv_current_date)
        self.bv_calendar_popup.move(self.bv_calendar_btn.mapToGlobal(QPoint(0, self.bv_calendar_btn.height())))
        self.bv_calendar_popup.show()

    def bv_on_date_selected(self, date):
        self.bv_current_date = date
        self.bv_update_date_display()
        if self.bv_calendar_popup: self.bv_calendar_popup.hide()

    def reset_ui(self):
        self.cached_data = {"trends": None, "age_trends": None, "main_inflow": None, "blog_views": {}, "analysis": {}, "auto": {}}
        self.results_df = None
        self.blog_views_df = None
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
        self.ai_copy_button.setDisabled(True)
        self.rank_sort_order = Qt.SortOrder.DescendingOrder
        self.trend_table.horizontalHeader().setSortIndicatorShown(False)
        self.status_label_fetch.setText("먼저 [브라우저 열기]를 눌러 로그인 후 수집을 시작하세요.")
        self.progress_bar_fetch.setValue(0)
        self.analysis_input_widget.clear()
        self.result_table.setRowCount(0)
        
        # ✨ 상태 동기화 추가
        self.progress_bar_analysis.setValue(0)
        self.export_excel_button.setDisabled(True)
        self.export_include_normal_cb.setChecked(False) 
        
        self.autocomplete_input.clear()
        self.autocomplete_table.setRowCount(0)
        self.cb_naver.setChecked(True); self.cb_daum.setChecked(True); self.cb_google.setChecked(True)
        self.bv_on_mode_changed()
        self.blog_views_table.setRowCount(0)
        self.status_label_bv.setText("조회할 기간을 선택하고 버튼을 눌러주세요.")
        self.progress_bar_bv.setValue(0)
        self.export_blog_views_button.setDisabled(True)

        self.update_button_style(self.fetch_trends_button, False, "2-1. 주제별 수집")
        self.update_button_style(self.fetch_age_trends_button, False, "2-2. 연령별 수집")
        self.update_button_style(self.fetch_main_content_button, False, "메인 유입콘텐츠 가져오기")
        self.check_views_cache_state()
        self.check_analysis_cache_state()
        self.check_auto_cache_state()

        self.log_message("INFO", "화면 및 메모리 캐시가 모두 초기화되었습니다.")

    def start_open_browser(self):
        if self.is_working: return
        self.is_working = True
        self.set_all_buttons_disabled(True)
        self.req_open_browser.emit()

    @pyqtSlot()
    def on_browser_opened(self):
        self._finish_task_state()
        QMessageBox.information(self, "안내", "브라우저가 열렸습니다!\n로그인 후 창을 끄지 말고 프로그램의 수집 버튼을 눌러주세요.")

    def start_trend_fetching(self):
        if self.is_working: return
        if self.cached_data.get("trends"):
            QMessageBox.information(self, "캐시 적용됨", "💡 이미 데이터가 수집되어 화면에 표시되어 있습니다.\n(최신 데이터로 갱신하려면 '화면 초기화' 후 진행하세요)")
            return
        self.is_working = True
        self.current_task = "trends"
        self.set_all_buttons_disabled(True)
        self.status_label_fetch.setText("수집 중...")
        self.trend_table.setRowCount(0)
        self.progress_bar_fetch.setValue(0)
        self.req_fetch_trends.emit()

    def start_age_trend_fetching(self):
        if self.is_working: return
        if self.cached_data.get("age_trends"):
            QMessageBox.information(self, "캐시 적용됨", "💡 이미 데이터가 수집되어 화면에 표시되어 있습니다.\n(최신 데이터로 갱신하려면 '화면 초기화' 후 진행하세요)")
            return
        self.is_working = True
        self.current_task = "age"
        self.set_all_buttons_disabled(True)
        self.status_label_fetch.setText("수집 중...")
        self.trend_table.setRowCount(0)
        self.progress_bar_fetch.setValue(0)
        self.req_fetch_age_trends.emit()

    def start_fetch_naver_main(self):
        if self.is_working: return
        if self.cached_data.get("main_inflow"):
            QMessageBox.information(self, "캐시 적용됨", "💡 이미 데이터가 수집되어 화면에 표시되어 있습니다.\n(최신 데이터로 갱신하려면 '화면 초기화' 후 진행하세요)")
            return
        self.is_working = True
        self.current_task = "main"
        self.set_all_buttons_disabled(True)
        self.log_message("INFO", "네이버 메인 수집 시작...")
        self.naver_main_table.setRowCount(0)
        self.req_fetch_main.emit()

    def start_fetch_blog_views(self):
        if self.is_working: return
        cid = self.bv_mode_group.checkedId()
        time_dim = {0: "DATE", 1: "WEEK", 2: "MONTH"}[cid]
        d = self.bv_current_date
        if cid == 0: sd = ed = d.toPyDate()
        elif cid == 1:
            sw = d.addDays(-(d.dayOfWeek() - 1))
            sd, ed = sw.toPyDate(), sw.addDays(6).toPyDate()
        elif cid == 2:
            sd, ed = (QDate(d.year(), d.month(), 1).toPyDate(), QDate(d.year(), d.month(), d.daysInMonth()).toPyDate())

        cache_key = f"{sd}_{ed}_{time_dim}"
        if cache_key in self.cached_data["blog_views"]:
            if getattr(self, "current_views_cache_key", None) == cache_key:
                QMessageBox.information(self, "캐시 적용됨", "💡 선택하신 기간의 데이터가 이미 화면에 표시되어 있습니다.")
                return
            else:
                self.current_views_cache_key = cache_key
                self.log_message("SUCCESS", "💡 [메모리 캐시] 저장된 조회수 데이터를 즉시 띄웁니다.")
                self.current_task = "views"
                self.on_fetch_blog_views_finished(self.cached_data["blog_views"][cache_key])
                return

        self.current_views_cache_key = cache_key
        self.is_working = True
        self.current_task = "views"
        self.set_all_buttons_disabled(True)
        self.status_label_bv.setText(f"수집 중...")
        self.blog_views_table.setRowCount(0)
        self.progress_bar_bv.setValue(0)
        self.req_fetch_views.emit(sd, ed, time_dim)

    def start_competition_analysis(self):
        if self.is_working: return
        if not all(self.API_KEYS.values()):
            QMessageBox.critical(self, "API 키 오류", "하나 이상의 API 키가 없습니다. 'api.env' 파일을 확인해주세요.\n(하단 로그 창에서 누락된 키를 확인하세요)")
            return

        keywords = [kw.strip() for kw in self.analysis_input_widget.toPlainText().strip().split("\n") if kw.strip()]
        if not keywords:
            QMessageBox.warning(self, "경고", "분석할 키워드를 입력하거나 붙여넣어 주세요.")
            return

        cache_key = tuple(sorted(list(set(keywords))))
        if cache_key in self.cached_data["analysis"]:
            if getattr(self, "current_analysis_cache_key", None) == cache_key:
                QMessageBox.information(self, "캐시 적용됨", "💡 동일한 키워드의 분석 결과가 이미 화면에 표시되어 있습니다.")
                return
            else:
                self.current_analysis_cache_key = cache_key
                self.log_message("SUCCESS", "💡 [메모리 캐시] 저장된 분석 결과를 즉시 띄웁니다.")
                self.current_task = "analysis"
                self.on_analysis_finished(self.cached_data["analysis"][cache_key])
                return

        self.current_analysis_cache_key = cache_key
        self.is_working = True
        self.current_task = "analysis"
        self.set_all_buttons_disabled(True)
        self.result_table.setRowCount(0)
        self.progress_bar_analysis.setValue(0)
        self.req_fetch_analysis.emit(keywords, self.API_KEYS)

    def start_autocomplete_search(self):
        if self.is_working: return
        kw = self.autocomplete_input.text().strip()
        if not kw:
            QMessageBox.warning(self, "입력 오류", "검색어를 입력해주세요.")
            return

        engines = [name for cb, name in [("naver", "naver"), ("daum", "daum"), ("google", "google")] if getattr(self, f"cb_{cb}").isChecked()]
        if not engines:
            QMessageBox.warning(self, "선택 오류", "검색 엔진을 하나 이상 선택해주세요.")
            return

        cache_key = f"{kw}_{'-'.join(sorted(engines))}"
        if cache_key in self.cached_data["auto"]:
            if getattr(self, "current_auto_cache_key", None) == cache_key:
                QMessageBox.information(self, "캐시 적용됨", "💡 동일한 조건의 자동완성 결과가 이미 화면에 표시되어 있습니다.")
                return
            else:
                self.current_auto_cache_key = cache_key
                self.log_message("SUCCESS", "💡 [메모리 캐시] 저장된 자동완성 결과를 즉시 띄웁니다.")
                self.current_task = "auto"
                self.on_autocomplete_finished(self.cached_data["auto"][cache_key])
                return

        self.current_auto_cache_key = cache_key
        self.is_working = True
        self.current_task = "auto"
        self.set_all_buttons_disabled(True)
        self.autocomplete_table.setRowCount(0)
        self.req_fetch_autocomplete.emit(kw, engines)

    def on_worker_error(self, err):
        self._finish_task_state()
        self.log_message("ERROR", f"오류 발생: {err.splitlines()[0]}")
        QMessageBox.critical(self, "오류", err.splitlines()[0])

    def on_trend_fetching_finished(self, data):
        self.update_progress_bar(100)
        self._finish_task_state()
        if data:
            self.cached_data["trends"] = data
            self.update_button_style(self.fetch_trends_button, True, "2-1. 주제별 수집")
        self._finish_trend_fetching_ui(data, "카테고리")

    def on_age_trend_fetching_finished(self, data):
        self.update_progress_bar(100)
        self._finish_task_state()
        if data:
            self.cached_data["age_trends"] = data
            self.update_button_style(self.fetch_age_trends_button, True, "2-2. 연령별 수집")
        self._finish_trend_fetching_ui(data, "연령대")

    def _finish_trend_fetching_ui(self, data, first_col):
        if not data:
            self.status_label_fetch.setText("❌ 수집 실패.")
            return
        self.all_trend_data = list(data)
        self.status_label_fetch.setText(f"✅ {len(data)}개 완료!")
        self.trend_table.setHorizontalHeaderLabels([first_col, "원문(트렌드 내용)", "순위", "순위변동"])
        self.category_filter_combo.blockSignals(True)
        self.category_filter_combo.clear()
        self.category_filter_combo.addItem("전체 보기")
        self.category_filter_combo.addItem("✨ 신규 진입(NEW) 전체")
        self.category_filter_combo.addItem("🔥 최상위 신규 진입(1~5위 내 NEW)")
        self.category_filter_combo.addItem("🚀 급상승 키워드(+5 계단 이상)")
        self.category_filter_combo.addItems(sorted(list(set(str(it.get(first_col, "")) for it in data))))
        self.category_filter_combo.blockSignals(False)
        self.trend_search_input.blockSignals(True)
        self.trend_search_input.clear()
        self.trend_search_input.blockSignals(False)
        self.populate_trend_table(data)
        self.copy_to_analyzer_button.setDisabled(False)
        self.ai_copy_button.setDisabled(False)
        self.category_filter_combo.setDisabled(False)
        self.trend_search_input.setDisabled(False)
        self.export_trends_excel_button.setDisabled(False)

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
            r_it = QTableWidgetItem("NEW" if rc is None else ("-" if rc == 0 else f"{rc:g}"))
            r_it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if rc is None: r_it.setForeground(QColor("#28A745"))
            elif rc > 0: r_it.setForeground(QColor("#DC3545"))
            elif rc < 0: r_it.setForeground(QColor("#007BFF"))
            self.trend_table.setItem(row, 0, c_it)
            self.trend_table.setItem(row, 1, k_it)
            self.trend_table.setItem(row, 2, rank_it)
            self.trend_table.setItem(row, 3, r_it)
        self.trend_table.setUpdatesEnabled(True)
        self.filter_trend_table()

    def sort_trend_table(self, idx):
        if idx not in [2, 3] or not self.all_trend_data: return
        self.rank_sort_order = Qt.SortOrder.DescendingOrder if self.rank_sort_order == Qt.SortOrder.AscendingOrder else Qt.SortOrder.AscendingOrder
        if idx == 2:
            self.all_trend_data.sort(key=lambda x: x["순위"], reverse=(self.rank_sort_order == Qt.SortOrder.DescendingOrder))
        elif idx == 3:
            new_items = [i for i in self.all_trend_data if i["순위변동"] is None]
            other = sorted([i for i in self.all_trend_data if i["순위변동"] is not None], key=lambda x: x["순위변동"], reverse=(self.rank_sort_order == Qt.SortOrder.DescendingOrder))
            self.all_trend_data = new_items + other
        self.populate_trend_table(self.all_trend_data)
        self.trend_table.horizontalHeader().setSortIndicatorShown(True)
        self.trend_table.horizontalHeader().setSortIndicator(idx, self.rank_sort_order)

    def filter_trend_table(self):
        selected_filter = self.category_filter_combo.currentText()
        search_text = self.trend_search_input.text().strip().lower()
        if self.trend_table.rowCount() == 0: return
        for row in range(self.trend_table.rowCount()):
            cat_text = self.trend_table.item(row, 0).text()
            kwd_text = self.trend_table.item(row, 1).text().lower()
            rank_text = self.trend_table.item(row, 2).text()
            rc_text = self.trend_table.item(row, 3).text()
            hide_row = False
            if selected_filter and selected_filter != "전체 보기":
                if selected_filter == "✨ 신규 진입(NEW) 전체":
                    if rc_text != "NEW": hide_row = True
                elif selected_filter == "🔥 최상위 신규 진입(1~5위 내 NEW)":
                    if rc_text != "NEW" or int(rank_text) > 5: hide_row = True
                elif selected_filter == "🚀 급상승 키워드(+5 계단 이상)":
                    if rc_text in ["NEW", "-"] or int(rc_text) < 5: hide_row = True
                else:
                    if cat_text != selected_filter: hide_row = True
            if search_text and search_text not in kwd_text: hide_row = True
            self.trend_table.setRowHidden(row, hide_row)

    def start_ai_copy(self):
        if self.is_working: return
        if self.trend_table.rowCount() == 0: return

        kws = [self.trend_table.item(r, 1).text() for r in range(self.trend_table.rowCount()) if not self.trend_table.isRowHidden(r)]
        if not kws:
            self.log_message("WARNING", "복사할 데이터가 없습니다.")
            return

        self.is_working = True
        self.set_all_buttons_disabled(True)
        self.req_ai_extract.emit(kws, self.API_KEYS["gemini_key"], self.API_KEYS["gemini_model"])

    @pyqtSlot(list)
    def on_ai_extract_done(self, extracted_keywords):
        self._finish_task_state()
        if not extracted_keywords:
            self.log_message("WARNING", "AI가 키워드를 추출하지 못했습니다.")
            return

        existing = [x.strip() for x in self.analysis_input_widget.toPlainText().splitlines() if x.strip()]
        merged = list(dict.fromkeys(existing + extracted_keywords))
        self.analysis_input_widget.setPlainText("\n".join(merged))
        self.tabs.setCurrentIndex(1)
        self.log_message("SUCCESS", f"✨ AI가 총 {len(extracted_keywords)}개의 고가치 키워드를 추출하여 복사했습니다!")

    def on_analysis_finished(self, df):
        self.update_progress_bar(100)
        self._finish_task_state()
        if df is not None and not df.empty:
            ck = getattr(self, "current_analysis_cache_key", None)
            if ck and ck not in self.cached_data["analysis"]:
                self._add_to_cache(self.cached_data["analysis"], ck, df, limit=30)
            self.check_analysis_cache_state()
            self.results_df = df.sort_values(by="기회지수", ascending=False)
            self.result_table.setUpdatesEnabled(False)
            self.result_table.setRowCount(len(self.results_df))
            for r, row in enumerate(self.results_df.itertuples()):
                self.result_table.setItem(r, 0, QTableWidgetItem(str(row.분류)))
                self.result_table.setItem(r, 1, QTableWidgetItem(str(row.키워드)))
                self.result_table.setItem(r, 2, QTableWidgetItem(f"{row.총검색량:,}"))
                self.result_table.setItem(r, 3, QTableWidgetItem(f"{row.총문서수:,}"))
                self.result_table.setItem(r, 4, QTableWidgetItem(f"{row.기회지수:,}"))
            self.result_table.setUpdatesEnabled(True)
            self.export_excel_button.setDisabled(False)
        else:
            self.log_message("WARNING", "분석된 키워드가 0건입니다.")

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
        self.autocomplete_table.setUpdatesEnabled(True)
        if not kw: self.log_message("WARNING", "자동완성 키워드가 0건입니다.")

    def on_naver_main_finished(self, res):
        self._finish_task_state()
        if res:
            self.cached_data["main_inflow"] = res
            self.update_button_style(self.fetch_main_content_button, True, "메인 유입콘텐츠 가져오기")
        self.naver_main_table.setUpdatesEnabled(False)
        self.naver_main_table.setRowCount(len(res))
        for r, it in enumerate(res):
            ri, ti = QTableWidgetItem(it["rank"]), QTableWidgetItem(it["title"])
            ri.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ti.setData(Qt.ItemDataRole.UserRole, it["link"])
            self.naver_main_table.setItem(r, 0, ri)
            self.naver_main_table.setItem(r, 1, ti)
        self.naver_main_table.setUpdatesEnabled(True)
        if not res: self.log_message("WARNING", "메인 유입 데이터가 0건입니다.")

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
            return
        self.blog_views_df = pd.DataFrame(data)
        self.status_label_bv.setText(f"✅ {len(data)}개 완료!")
        self.blog_views_table.setUpdatesEnabled(False)
        self.blog_views_table.setRowCount(len(data))
        for r, row in enumerate(self.blog_views_df.itertuples()):
            self.blog_views_table.setItem(r, 0, QTableWidgetItem(str(row.날짜)))
            self.blog_views_table.setItem(r, 1, QTableWidgetItem(str(row.순위)))
            self.blog_views_table.setItem(r, 2, QTableWidgetItem(f"{row.조회수:,}"))
            ti = QTableWidgetItem(str(row.제목))
            ti.setData(Qt.ItemDataRole.UserRole, str(row.게시물_주소))
            self.blog_views_table.setItem(r, 3, ti)
        self.blog_views_table.setUpdatesEnabled(True)
        self.export_blog_views_button.setDisabled(False)

    def open_browser_link(self, r, c):
        item = self.naver_main_table.item(r, c)
        if c == 1 and item:
            link = item.data(Qt.ItemDataRole.UserRole)
            if link: webbrowser.open(link)

    def open_blog_view_link(self, r, c):
        item = self.blog_views_table.item(r, c)
        if c == 3 and item:
            link = item.data(Qt.ItemDataRole.UserRole)
            if link: webbrowser.open(link)

    def copy_trends_to_analyzer(self):
        if self.trend_table.rowCount() > 0:
            kws = [self.trend_table.item(r, 1).text() for r in range(self.trend_table.rowCount()) if not self.trend_table.isRowHidden(r)]
            if not kws:
                self.log_message("WARNING", "복사할 데이터가 없습니다 (필터링 0건).")
                return
            existing = [x.strip() for x in self.analysis_input_widget.toPlainText().splitlines() if x.strip()]
            merged = list(dict.fromkeys(existing + kws))
            self.analysis_input_widget.setPlainText("\n".join(merged))
            self.tabs.setCurrentIndex(1)
            self.log_message("INFO", f"중복 제거 후 총 {len(merged)}개 키워드 복사 완료.")

    def copy_autocomplete_to_analyzer(self):
        rows = self.autocomplete_table.rowCount()
        if rows > 0:
            kws = [self.autocomplete_table.item(r, 0).text() for r in range(rows)]
            existing = [x.strip() for x in self.analysis_input_widget.toPlainText().splitlines() if x.strip()]
            merged = list(dict.fromkeys(existing + kws))
            self.analysis_input_widget.setPlainText("\n".join(merged))
            self.tabs.setCurrentIndex(1)
            self.log_message("INFO", f"중복 제거 후 총 {len(merged)}개 키워드 복사 완료.")

    def export_trends_to_excel(self):
        if self.trend_table.rowCount() == 0: return
        os.makedirs("output", exist_ok=True)
        data = []
        for r in range(self.trend_table.rowCount()):
            if not self.trend_table.isRowHidden(r):
                data.append({
                    self.trend_table.horizontalHeaderItem(0).text(): self.trend_table.item(r, 0).text(),
                    "원문(트렌드 내용)": self.trend_table.item(r, 1).text(),
                    "순위": int(self.trend_table.item(r, 2).text()),
                    "순위변동": self.trend_table.item(r, 3).text(),
                })
        if not data:
            QMessageBox.warning(self, "경고", "저장할 데이터가 없습니다 (필터링 결과 0건).")
            return
        df = pd.DataFrame(data)
        df.to_excel(os.path.join("output", f"trend_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"), index=False)
        QMessageBox.information(self, "성공", f"현재 화면의 {len(data)}개 데이터 엑셀 저장 완료.")

    # ✨ xlsxwriter를 활용한 자동 서식 지정 및 파일 잠금 예외 처리 적용
    def export_to_excel(self):
        if getattr(self, "results_df", None) is None or self.results_df.empty: return
        os.makedirs("output", exist_ok=True)
        
        # 체크박스 상태에 따라 DataFrame 준비
        if self.export_include_normal_cb.isChecked():
            export_df = self.results_df
        else:
            export_df = self.results_df[self.results_df["분류"] != "일반"]

        if export_df.empty:
            QMessageBox.warning(self, "경고", "저장할 데이터가 없습니다 ('일반' 제외 후 0건).")
            return
            
        file_path = os.path.join("output", f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
        
        try:
            # xlsxwriter 엔진을 이용해 엑셀 기록
            writer = pd.ExcelWriter(file_path, engine='xlsxwriter')
            export_df.to_excel(writer, index=False, sheet_name='분석결과')
            
            workbook = writer.book
            worksheet = writer.sheets['분석결과']
            
            # 서식(Style) 포맷 지정
            header_format = workbook.add_format({
                'bold': True, 'text_wrap': True, 'valign': 'top',
                'fg_color': '#D7E4BC', 'border': 1
            })
            num_format = workbook.add_format({'num_format': '#,##0'})
            float_format = workbook.add_format({'num_format': '#,##0.00'})
            
            # 1행(헤더)에 서식 적용
            for col_num, value in enumerate(export_df.columns.values):
                worksheet.write(0, col_num, value, header_format)
                
            # 열 너비 및 데이터 포맷 적용
            worksheet.set_column('A:A', 12)                 # 분류
            worksheet.set_column('B:B', 30)                 # 정제된 키워드
            worksheet.set_column('C:D', 15, num_format)     # 총검색량, 총문서수 (콤마 적용)
            worksheet.set_column('E:E', 15, float_format)   # 기회지수 (소수점 2자리 적용)
            
            writer.close()
            QMessageBox.information(self, "성공", f"총 {len(export_df)}개의 데이터가 서식이 적용된 엑셀로 저장되었습니다.")
            self.log_message("SUCCESS", f"엑셀 저장 완료 (포함된 행: {len(export_df)}개)")
            
        except PermissionError:
            self.log_message("ERROR", "엑셀 파일 저장 실패 (파일 열림 에러)")
            QMessageBox.critical(self, "저장 실패", "해당 이름의 엑셀 파일이 이미 다른 프로그램에서 열려있습니다. 닫고 다시 시도해주세요.")
        except Exception as e:
            self.log_message("ERROR", f"엑셀 저장 중 알 수 없는 오류: {e}")
            QMessageBox.critical(self, "오류", f"엑셀 저장 중 오류가 발생했습니다:\n{e}")

    def export_blog_views_to_excel(self):
        if getattr(self, "blog_views_df", None) is None or self.blog_views_df.empty: return
        os.makedirs("output", exist_ok=True)
        self.blog_views_df.to_excel(os.path.join("output", f"views_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"), index=False)
        QMessageBox.information(self, "성공", "저장 완료.")

    def on_update_available(self, v):
        self.log_message("INFO", f"현재 버전: v{v}")

    def on_update_error(self, err):
        self.log_message("WARNING", f"업데이트 확인 오류: {err}")

    def closeEvent(self, e):
        if self._closing:
            e.ignore()
            return
        if getattr(self, "is_working", False):
            reply = QMessageBox.question(self, "종료 경고", "수집 작업이 진행 중입니다. 강제 종료하시겠습니까?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
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


if __name__ == "__main__":
    freeze_support()
    app = QApplication(sys.argv)
    window = KeywordApp()
    window.show()
    sys.exit(app.exec())
