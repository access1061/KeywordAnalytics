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

# [방어 확인] ET 임포트 정상 유지
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
    QButtonGroup,
    QDialog,
    QCalendarWidget,
    QGroupBox,
)
from PyQt6.QtGui import QIcon, QColor, QFont
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal, QDate, QPoint, pyqtSlot


def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def load_stylesheet():
    base_qss = """
        QCheckBox { spacing: 8px; font-size: 9pt; }
        QCheckBox::indicator { width: 18px; height: 18px; border: 2px solid #4A4A4A; border-radius: 4px; background-color: #2E2E2E; }
        QCheckBox::indicator:hover { border: 2px solid #82C0FF; }
        QCheckBox::indicator:checked { background-color: #007BFF; border: 2px solid #007BFF; }
        QGroupBox { font-size: 9pt; font-weight: bold; border: 1px solid #D0D0D0; border-radius: 5px; margin-top: 12px; }
        QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; left: 10px; }
        QTextEdit { background-color: #2E2E2E; color: #F0F0F0; border: 1px solid #4A4A4A; border-radius: 4px; padding: 5px; }
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
        hash_val = hmac.new(
            bytes(secret_key, "utf-8"), bytes(message, "utf-8"), hashlib.sha256
        )
        return base64.b64encode(hash_val.digest()).decode("utf-8")


def get_naver_ad_keywords(keyword, api_key, secret_key, customer_id, session=None):
    if not all([api_key, secret_key, customer_id]):
        raise ValueError("광고 API 키가 설정되지 않았습니다.")
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
    req_session = session or requests
    try:
        r = req_session.get(base_url + uri, params=params, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json().get("keywordList", [])
    except requests.RequestException as e:
        raise RuntimeError(f"광고 API 호출 실패: {e}")


def get_blog_post_count(keyword, client_id, client_secret, session=None):
    if not all([client_id, client_secret]):
        raise ValueError("검색 API 키가 설정되지 않았습니다.")
    url = f"https://openapi.naver.com/v1/search/blog?query={quote(keyword)}"
    headers = {"X-Naver-Client-Id": client_id, "X-Naver-Client-Secret": client_secret}
    req_session = session or requests
    try:
        response = req_session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get("total", 0)
    except requests.RequestException as e:
        raise RuntimeError(f"블로그 검색 API 호출 실패: {e}")


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
        self.current_year -= 1
        self.year_label.setText(str(self.current_year))

    def next_year(self):
        self.current_year += 1
        self.year_label.setText(str(self.current_year))

    def select_month(self, month):
        self.month_selected.emit(QDate(self.current_year, month, 1))
        self.accept()


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
# [방어] BackgroundWorker 완벽 무결성 튜닝
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

    def __init__(self):
        super().__init__()
        self.driver = None
        self.CATEGORIES = [
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
        self.DEMO_CODES = [
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
        self.DEMO_MAP = {
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

    # [방어 2] 순위 변동값(rankChange) 안전한 Int 파싱기
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
            app_data_path = os.path.join(
                os.path.expanduser("~"),
                "AppData",
                "Local",
                "KeywordAppPro",
                "ChromeProfile",
            )
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
                            rc = self._parse_rank_change(
                                item.get("rankChange")
                            )  # 안전한 타입 변환
                            all_trends_data.append(
                                {
                                    "카테고리": cat,
                                    "순위": r_idx,
                                    "키워드": item.get("query", "N/A"),
                                    "순위변동": rc,
                                }
                            )
                except Exception as e:
                    self.log.emit("WARNING", f"[{cat}] 데이터 파싱/통신 실패: {e}")
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
                            rc = self._parse_rank_change(
                                item.get("rankChange")
                            )  # 안전한 타입 변환
                            all_age_trends.append(
                                {
                                    "연령대": group_name,
                                    "순위": r_idx,
                                    "키워드": item.get("query", "N/A"),
                                    "순위변동": rc,
                                }
                            )
                except Exception as e:
                    self.log.emit(
                        "WARNING", f"[{group_name}] 데이터 파싱/통신 실패: {e}"
                    )
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
                    r_json = json.loads(res_text)
                    if isinstance(r_json, dict) and r_json.get("__fetch_error__"):
                        raise ValueError(f"HTTP 에러: {r_json.get('status')}")
                    # [방어 5] 조회수 응답 구조 깐깐한 검증
                    if not isinstance(r_json, dict) or "result" not in r_json:
                        raise ValueError("조회수 API 응답 구조가 변경되었습니다.")

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

    @pyqtSlot(list, dict)
    def fetch_analysis(self, keywords, api_keys):
        unique_kw = list(dict.fromkeys(keywords))
        analysis_results = []
        with requests.Session() as session:
            for i, original_kw in enumerate(unique_kw):
                self.progress.emit(int((i + 1) / len(unique_kw) * 100))
                kw_api = original_kw.replace(" ", "")
                if not kw_api:
                    continue
                try:
                    ad_data = get_naver_ad_keywords(
                        kw_api,
                        api_keys["ads_key"],
                        api_keys["ads_secret"],
                        api_keys["customer_id"],
                        session,
                    )
                    post_count = get_blog_post_count(
                        kw_api,
                        api_keys["client_id"],
                        api_keys["client_secret"],
                        session,
                    )
                    pc, mob = 0, 0
                    if ad_data and (
                        m := next(
                            (it for it in ad_data if it["relKeyword"] == kw_api), None
                        )
                    ):
                        pc_str, mob_str = str(m.get("monthlyPcQcCnt", 0)), str(
                            m.get("monthlyMobileQcCnt", 0)
                        )
                        pc = 5 if "<" in pc_str else int(pc_str)
                        mob = 5 if "<" in mob_str else int(mob_str)
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
                except Exception as e:
                    self.log.emit("ERROR", f"'{original_kw}' 분석 오류: {e}")
                time.sleep(0.15)
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

    # [방어 4] 에러 무시 안 하고 로그 남기기
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
class KeywordApp(QMainWindow):
    req_open_browser = pyqtSignal()
    req_fetch_trends = pyqtSignal()
    req_fetch_age_trends = pyqtSignal()
    req_fetch_main = pyqtSignal()
    req_fetch_views = pyqtSignal(object, object, str)
    req_fetch_analysis = pyqtSignal(list, dict)
    req_fetch_autocomplete = pyqtSignal(str, list)
    req_close_driver = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.current_version = get_current_version()
        self.setWindowTitle(f"키워드 분석기 Pro v{self.current_version}")

        self.is_working = False
        self._closing = False  # [방어 3] 중복 종료 호출 방지 플래그
        self.current_task = ""

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
        load_dotenv(resource_path("api.env"))

        self.API_KEYS = {
            "ads_key": os.getenv("NAVER_ADS_API_KEY"),
            "ads_secret": os.getenv("NAVER_ADS_API_SECRET"),
            "customer_id": os.getenv("NAVER_ADS_CUSTOMER_ID"),
            "client_id": os.getenv("NAVER_SEARCH_CLIENT_ID"),
            "client_secret": os.getenv("NAVER_SEARCH_CLIENT_SECRET"),
        }

        icon_path = resource_path("keyword_pro.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

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

        # [방어 3] 프로그램 종료 핸드셰이크 시그널을 미리 1번만 연결
        self.bg_worker.driver_closed.connect(self.final_quit)

        self.bg_worker.trends_done.connect(self.on_trend_fetching_finished)
        self.bg_worker.age_trends_done.connect(self.on_age_trend_fetching_finished)
        self.bg_worker.main_inflow_done.connect(self.on_naver_main_finished)
        self.bg_worker.blog_views_done.connect(self.on_fetch_blog_views_finished)
        self.bg_worker.analysis_done.connect(self.on_analysis_finished)
        self.bg_worker.autocomplete_done.connect(self.on_autocomplete_finished)

        self.bg_thread.start()

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
        self.auth_button = QPushButton("1. 네이버 연결 (브라우저 열기)")
        self.auth_button.setStyleSheet(
            "background-color: #007BFF; font-weight: bold; padding: 8px;"
        )
        self.auth_button.clicked.connect(self.start_open_browser)
        settings_layout.addStretch()
        settings_layout.addWidget(self.reset_button)
        settings_layout.addWidget(self.auth_button)
        parent_layout.addWidget(settings_frame)

    def create_trend_fetch_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        control_layout = QHBoxLayout()
        self.fetch_trends_button = QPushButton("2-1. 켜진 창에서 주제별 수집")
        self.fetch_age_trends_button = QPushButton("2-2. 켜진 창에서 연령별 수집")
        self.fetch_trends_button.setStyleSheet(
            "background-color: #28A745; font-weight: bold;"
        )
        self.fetch_age_trends_button.setStyleSheet(
            "background-color: #28A745; font-weight: bold;"
        )
        self.copy_to_analyzer_button = QPushButton("키워드 → 분석 탭으로 복사")
        self.category_filter_combo = QComboBox()
        self.category_filter_combo.setFixedWidth(230)
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
        status_container = QWidget()
        status_container.setMinimumWidth(350)
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label_fetch = QLabel(
            "먼저 [브라우저 열기]를 눌러 로그인 후 수집을 시작하세요."
        )
        self.progress_bar_fetch = QProgressBar()
        self.progress_bar_fetch.setFormat("수집 진행률: %p%")
        status_layout.addWidget(self.status_label_fetch)
        status_layout.addWidget(self.progress_bar_fetch)
        control_layout.addWidget(status_container)
        self.trend_table = QTableWidget()
        headers = ["카테고리", "키워드", "순위", "순위변동"]
        self.trend_table.setColumnCount(len(headers))
        self.trend_table.setHorizontalHeaderLabels(headers)
        self.trend_table.setSortingEnabled(False)
        self.trend_table.horizontalHeader().sectionClicked.connect(
            self.sort_trend_table
        )
        layout.addLayout(control_layout)
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
        self.export_excel_button = QPushButton("엑셀로 저장")
        self.export_excel_button.setDisabled(True)
        self.progress_bar_analysis = QProgressBar()
        self.progress_bar_analysis.setFixedHeight(20)
        control_layout.addWidget(self.analyze_button)
        control_layout.addWidget(self.export_excel_button)
        control_layout.addStretch()
        control_layout.addWidget(self.progress_bar_analysis)
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(5)
        self.result_table.setHorizontalHeaderLabels(
            ["분류", "키워드", "총검색량", "총문서수", "기회지수"]
        )
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
        self.autocomplete_input.setPlaceholderText("자동완성 키워드 입력...")
        input_layout.addWidget(QLabel("검색어:"), 0)
        input_layout.addWidget(self.autocomplete_input, 1)
        checkbox_layout = QHBoxLayout()
        checkbox_layout.setContentsMargins(10, 5, 0, 5)
        checkbox_layout.addWidget(QLabel("검색 엔진:"), 0)
        self.cb_naver = QCheckBox("네이버")
        self.cb_daum = QCheckBox("Daum")
        self.cb_google = QCheckBox("Google")
        self.cb_naver.setChecked(True)
        self.cb_daum.setChecked(True)
        self.cb_google.setChecked(True)
        checkbox_layout.addWidget(self.cb_naver)
        checkbox_layout.addWidget(self.cb_daum)
        checkbox_layout.addWidget(self.cb_google)
        checkbox_layout.addStretch()
        button_layout = QHBoxLayout()
        self.autocomplete_search_button = QPushButton("자동완성 검색")
        self.autocomplete_copy_button = QPushButton("키워드 → 분석 탭으로 복사")
        button_layout.addWidget(self.autocomplete_search_button)
        button_layout.addWidget(self.autocomplete_copy_button)
        button_layout.addStretch()
        top_control_layout.addLayout(input_layout)
        top_control_layout.addLayout(checkbox_layout)
        top_control_layout.addLayout(button_layout)
        self.autocomplete_table = QTableWidget()
        self.autocomplete_table.setColumnCount(1)
        self.autocomplete_table.setHorizontalHeaderLabels(["자동완성 키워드"])
        self.autocomplete_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
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
        self.fetch_main_content_button = QPushButton(
            "켜진 창에서 메인 유입콘텐츠 가져오기"
        )
        self.fetch_main_content_button.setStyleSheet(
            "background-color: #28A745; font-weight: bold;"
        )
        hint_label = QLabel("💡 더블클릭으로 해당 링크 이동")
        hint_label.setStyleSheet("color: #6C757D; font-size: 9pt; padding-left: 10px;")
        control_layout.addWidget(self.fetch_main_content_button)
        control_layout.addWidget(hint_label)
        control_layout.addStretch()
        self.naver_main_table = QTableWidget()
        self.naver_main_table.setColumnCount(2)
        self.naver_main_table.setHorizontalHeaderLabels(["순위", "제목"])
        self.naver_main_table.verticalHeader().setVisible(False)
        self.naver_main_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.naver_main_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.naver_main_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addLayout(control_layout)
        layout.addWidget(self.naver_main_table)
        self.tabs.addTab(tab, "네이버 메인 유입 콘텐츠")
        self.fetch_main_content_button.clicked.connect(self.start_fetch_naver_main)
        self.naver_main_table.cellDoubleClicked.connect(self.open_browser_link)

    def create_blog_views_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        top_control_layout = QHBoxLayout()
        top_control_layout.setContentsMargins(0, 0, 0, 10)
        self.bv_prev_btn = QPushButton("<")
        self.bv_date_label = QLabel("")
        self.bv_date_label.setFont(QFont("Arial", 10))
        self.bv_calendar_btn = QPushButton("📅")
        self.bv_next_btn = QPushButton(">")
        self.bv_prev_btn.setFixedSize(30, 30)
        self.bv_next_btn.setFixedSize(30, 30)
        self.bv_calendar_btn.setFixedSize(30, 30)
        self.bv_mode_group = QButtonGroup(self)
        self.bv_radio_daily = QPushButton("일간")
        self.bv_radio_weekly = QPushButton("주간")
        self.bv_radio_monthly = QPushButton("월간")
        for btn, idx in zip(
            [self.bv_radio_daily, self.bv_radio_weekly, self.bv_radio_monthly],
            [0, 1, 2],
        ):
            btn.setCheckable(True)
            self.bv_mode_group.addButton(btn, idx)
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
        self.fetch_blog_views_button = QPushButton("켜진 창에서 조회수 순위 가져오기")
        self.fetch_blog_views_button.setStyleSheet(
            "background-color: #28A745; font-weight: bold;"
        )
        self.export_blog_views_button = QPushButton("엑셀로 저장")
        self.export_blog_views_button.setDisabled(True)
        bottom_control_layout.addWidget(self.fetch_blog_views_button)
        bottom_control_layout.addWidget(self.export_blog_views_button)
        bottom_control_layout.addStretch()
        status_container = QWidget()
        status_container.setMinimumWidth(350)
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label_bv = QLabel("조회할 기간을 선택하고 버튼을 눌러주세요.")
        self.progress_bar_bv = QProgressBar()
        self.progress_bar_bv.setFormat("진행률: %p%")
        status_layout.addWidget(self.status_label_bv)
        status_layout.addWidget(self.progress_bar_bv)
        bottom_control_layout.addWidget(status_container)
        self.blog_views_table = QTableWidget()
        self.blog_views_table.setColumnCount(4)
        self.blog_views_table.setHorizontalHeaderLabels(
            ["날짜", "순위", "조회수", "제목"]
        )
        layout.addLayout(top_control_layout)
        layout.addLayout(bottom_control_layout)
        layout.addWidget(self.blog_views_table)
        self.tabs.addTab(tab, "블로그 조회수 순위")

        self.bv_mode_group.buttonClicked.connect(lambda _: self.bv_on_mode_changed())
        self.bv_prev_btn.clicked.connect(self.bv_navigate_prev)
        self.bv_next_btn.clicked.connect(self.bv_navigate_next)
        self.bv_calendar_btn.clicked.connect(self.bv_show_calendar_picker)
        self.fetch_blog_views_button.clicked.connect(self.start_fetch_blog_views)
        self.export_blog_views_button.clicked.connect(self.export_blog_views_to_excel)
        self.blog_views_table.cellDoubleClicked.connect(self.open_blog_view_link)
        self.bv_radio_daily.setChecked(True)
        self.bv_on_mode_changed()

    def bv_on_mode_changed(self, button=None):
        cid = self.bv_mode_group.checkedId()
        today = QDate.currentDate()
        if cid == 0:
            self.bv_current_date = today
        elif cid == 1:
            self.bv_current_date = today.addDays(-7)
        elif cid == 2:
            self.bv_current_date = today.addMonths(-1)
        self.bv_update_date_display()

    def bv_update_date_display(self):
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

    def bv_navigate_prev(self):
        cid = self.bv_mode_group.checkedId()
        self.bv_current_date = (
            self.bv_current_date.addDays(-1)
            if cid == 0
            else (
                self.bv_current_date.addDays(-7)
                if cid == 1
                else self.bv_current_date.addMonths(-1)
            )
        )
        self.bv_update_date_display()

    def bv_navigate_next(self):
        cid = self.bv_mode_group.checkedId()
        self.bv_current_date = (
            self.bv_current_date.addDays(1)
            if cid == 0
            else (
                self.bv_current_date.addDays(7)
                if cid == 1
                else self.bv_current_date.addMonths(1)
            )
        )
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
        self.bv_calendar_popup.move(
            self.bv_calendar_btn.mapToGlobal(QPoint(0, self.bv_calendar_btn.height()))
        )
        self.bv_calendar_popup.show()

    def bv_on_date_selected(self, date):
        self.bv_current_date = date
        self.bv_update_date_display()
        if self.bv_calendar_popup:
            self.bv_calendar_popup.hide()

    def reset_ui(self):
        # [방어 7] 숨어있는 DataFrame 데이터 완전 초기화
        self.results_df = None
        self.blog_views_df = None

        self.trend_table.setRowCount(0)
        self.all_trend_data = []
        self.category_filter_combo.clear()
        self.category_filter_combo.setDisabled(True)
        self.export_trends_excel_button.setDisabled(True)
        self.copy_to_analyzer_button.setDisabled(True)
        self.rank_sort_order = Qt.SortOrder.DescendingOrder
        self.trend_table.horizontalHeader().setSortIndicatorShown(False)
        self.status_label_fetch.setText(
            "먼저 [브라우저 열기]를 눌러 로그인 후 수집을 시작하세요."
        )
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
        self.log_message("INFO", "모든 작업 공간이 초기화되었습니다.")

    # --- Actions ---
    def start_open_browser(self):
        if self.is_working:
            return
        self.is_working = True
        self.set_all_buttons_disabled(True)
        self.req_open_browser.emit()

    @pyqtSlot()
    def on_browser_opened(self):
        self.is_working = False
        self.set_all_buttons_disabled(False)
        QMessageBox.information(
            self,
            "안내",
            "브라우저가 열렸습니다!\n로그인 후 창을 끄지 말고 프로그램의 수집 버튼을 눌러주세요.",
        )

    def start_trend_fetching(self):
        if self.is_working:
            return
        self.is_working = True
        self.current_task = "trends"
        self.set_all_buttons_disabled(True)
        self.status_label_fetch.setText("수집 중...")
        self.trend_table.setRowCount(0)
        self.progress_bar_fetch.setValue(0)
        self.req_fetch_trends.emit()

    def start_age_trend_fetching(self):
        if self.is_working:
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
        self.is_working = True
        self.current_task = "main"
        self.set_all_buttons_disabled(True)
        self.log_message("INFO", "네이버 메인 수집 시작...")
        self.naver_main_table.setRowCount(0)
        self.req_fetch_main.emit()

    def start_fetch_blog_views(self):
        if self.is_working:
            return
        self.is_working = True
        self.current_task = "views"
        self.set_all_buttons_disabled(True)
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
        self.status_label_bv.setText(f"수집 중...")
        self.blog_views_table.setRowCount(0)
        self.progress_bar_bv.setValue(0)
        self.req_fetch_views.emit(sd, ed, time_dim)

    def start_competition_analysis(self):
        if self.is_working:
            return
        if not all(self.API_KEYS.values()):
            QMessageBox.critical(
                self,
                "API 키 오류",
                "하나 이상의 API 키가 없습니다. 'api.env' 파일을 확인해주세요.",
            )
            return
        keywords = [
            kw.strip()
            for kw in self.analysis_input_widget.toPlainText().strip().split("\n")
            if kw.strip()
        ]
        if not keywords:
            QMessageBox.warning(
                self, "경고", "분석할 키워드를 입력하거나 붙여넣어 주세요."
            )
            return
        self.is_working = True
        self.current_task = "analysis"
        self.set_all_buttons_disabled(True)
        self.result_table.setRowCount(0)
        self.progress_bar_analysis.setValue(0)
        self.req_fetch_analysis.emit(keywords, self.API_KEYS)

    def start_autocomplete_search(self):
        if self.is_working:
            return
        kw = self.autocomplete_input.text().strip()
        if not kw:
            QMessageBox.warning(self, "입력 오류", "검색어를 입력해주세요.")
            return
        engines = [
            name
            for cb, name in [
                (self.cb_naver, "naver"),
                (self.cb_daum, "daum"),
                (self.cb_google, "google"),
            ]
            if cb.isChecked()
        ]
        if not engines:
            QMessageBox.warning(
                self, "선택 오류", "검색 엔진을 하나 이상 선택해주세요."
            )
            return
        self.is_working = True
        self.current_task = "auto"
        self.set_all_buttons_disabled(True)
        self.autocomplete_table.setRowCount(0)
        self.req_fetch_autocomplete.emit(kw, engines)

    # --- Callbacks ---
    def on_worker_error(self, err):
        self.is_working = False
        self.set_all_buttons_disabled(False)
        self.log_message("ERROR", f"오류 발생: {err.splitlines()[0]}")
        QMessageBox.critical(self, "오류", err.splitlines()[0])

    def on_trend_fetching_finished(self, data):
        self.is_working = False
        self.set_all_buttons_disabled(False)
        self._finish_trend_fetching_ui(data, "카테고리")

    def on_age_trend_fetching_finished(self, data):
        self.is_working = False
        self.set_all_buttons_disabled(False)
        self._finish_trend_fetching_ui(data, "연령대")

    def _finish_trend_fetching_ui(self, data, first_col):
        self.progress_bar_fetch.setValue(100)
        if not data:
            self.status_label_fetch.setText("❌ 수집 실패.")
            return
        self.all_trend_data = data
        self.currently_displayed_data = data
        self.status_label_fetch.setText(f"✅ {len(data)}개 완료!")
        self.trend_table.setHorizontalHeaderLabels(
            [first_col, "키워드", "순위", "순위변동"]
        )
        self.category_filter_combo.blockSignals(True)
        self.category_filter_combo.clear()
        self.category_filter_combo.addItem("전체 보기")
        self.category_filter_combo.addItem("✨ 신규 진입(NEW) 전체")
        self.category_filter_combo.addItem("🔥 최상위 신규 진입(1~5위 내 NEW)")
        self.category_filter_combo.addItem("🚀 급상승 키워드(+5 계단 이상)")
        self.category_filter_combo.addItems(
            sorted(list(set(it[first_col] for it in data)))
        )
        self.category_filter_combo.blockSignals(False)
        self.populate_trend_table(data)
        self.copy_to_analyzer_button.setDisabled(False)
        self.category_filter_combo.setDisabled(False)
        self.export_trends_excel_button.setDisabled(False)

    def populate_trend_table(self, data):
        self.trend_table.setUpdatesEnabled(False)
        self.trend_table.setRowCount(len(data))
        if not data:
            self.trend_table.setUpdatesEnabled(True)
            return
        fk = list(data[0].keys())[0]
        for row, it in enumerate(data):
            c_it = QTableWidgetItem(str(it[fk]))
            k_it = QTableWidgetItem(str(it["키워드"]))
            rank_it = QTableWidgetItem(str(it["순위"]))
            rank_it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            rc = it["순위변동"]
            # [방어] 정수화된 rc를 포맷 에러 없이 렌더링
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

    def sort_trend_table(self, idx):
        if idx not in [2, 3] or not self.currently_displayed_data:
            return
        self.rank_sort_order = (
            Qt.SortOrder.DescendingOrder
            if self.rank_sort_order == Qt.SortOrder.AscendingOrder
            else Qt.SortOrder.AscendingOrder
        )
        if idx == 2:
            sorted_data = sorted(
                self.currently_displayed_data,
                key=lambda x: x["순위"],
                reverse=(self.rank_sort_order == Qt.SortOrder.DescendingOrder),
            )
        elif idx == 3:
            new_items = [
                i for i in self.currently_displayed_data if i["순위변동"] is None
            ]
            other = sorted(
                [i for i in self.currently_displayed_data if i["순위변동"] is not None],
                key=lambda x: x["순위변동"],
                reverse=(self.rank_sort_order == Qt.SortOrder.DescendingOrder),
            )
            sorted_data = new_items + other
        self.currently_displayed_data = sorted_data
        self.populate_trend_table(sorted_data)
        self.trend_table.horizontalHeader().setSortIndicatorShown(True)
        self.trend_table.horizontalHeader().setSortIndicator(idx, self.rank_sort_order)

    def filter_trend_table(self):
        selected_filter = self.category_filter_combo.currentText()
        if not self.all_trend_data:
            return
        fk = list(self.all_trend_data[0].keys())[0]
        if selected_filter == "전체 보기":
            self.currently_displayed_data = self.all_trend_data
        elif selected_filter == "✨ 신규 진입(NEW) 전체":
            self.currently_displayed_data = [
                i for i in self.all_trend_data if i.get("순위변동") is None
            ]
        elif selected_filter == "🔥 최상위 신규 진입(1~5위 내 NEW)":
            self.currently_displayed_data = [
                i
                for i in self.all_trend_data
                if i.get("순위변동") is None and i.get("순위", 99) <= 5
            ]
        elif selected_filter == "🚀 급상승 키워드(+5 계단 이상)":
            self.currently_displayed_data = [
                i
                for i in self.all_trend_data
                if i.get("순위변동") is not None and i.get("순위변동") >= 5
            ]
        else:
            self.currently_displayed_data = [
                i for i in self.all_trend_data if i.get(fk) == selected_filter
            ]
        self.populate_trend_table(self.currently_displayed_data)

    def on_analysis_finished(self, df):
        self.is_working = False
        self.set_all_buttons_disabled(False)
        self.progress_bar_analysis.setValue(100)
        if df is not None and not df.empty:
            self.results_df = df.sort_values(by="기회지수", ascending=False)
            self.result_table.setUpdatesEnabled(False)
            self.result_table.setRowCount(len(self.results_df))
            for r, row in enumerate(self.results_df.itertuples()):
                self.result_table.setItem(r, 0, QTableWidgetItem(str(row.분류)))
                self.result_table.setItem(r, 1, QTableWidgetItem(str(row.키워드)))
                self.result_table.setItem(r, 2, QTableWidgetItem(f"{row.총검색량:,}"))
                self.result_table.setItem(r, 3, QTableWidgetItem(f"{row.총문서수:,}"))
                self.result_table.setItem(r, 4, QTableWidgetItem(f"{row.기회지수:,}"))
            self.result_table.resizeColumnsToContents()
            self.result_table.setUpdatesEnabled(True)
            self.export_excel_button.setDisabled(False)
        else:
            self.log_message("WARNING", "분석된 키워드가 0건입니다.")

    def on_autocomplete_finished(self, kw):
        self.is_working = False
        self.set_all_buttons_disabled(False)
        self.autocomplete_table.setUpdatesEnabled(False)
        self.autocomplete_table.setRowCount(len(kw))
        for r, k in enumerate(kw):
            self.autocomplete_table.setItem(r, 0, QTableWidgetItem(k))
        self.autocomplete_table.resizeColumnsToContents()
        self.autocomplete_table.setUpdatesEnabled(True)
        if not kw:
            self.log_message("WARNING", "자동완성 키워드가 0건입니다.")

    def on_naver_main_finished(self, res):
        self.is_working = False
        self.set_all_buttons_disabled(False)
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
        self.is_working = False
        self.set_all_buttons_disabled(False)
        self.progress_bar_bv.setValue(100)
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
        self.blog_views_table.resizeColumnsToContents()
        self.blog_views_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.blog_views_table.setUpdatesEnabled(True)
        self.export_blog_views_button.setDisabled(False)

    def open_browser_link(self, r, c):
        item = self.naver_main_table.item(r, c)
        if c == 1 and item:
            link = item.data(Qt.ItemDataRole.UserRole)
            if link:
                webbrowser.open(link)

    def open_blog_view_link(self, r, c):
        item = self.blog_views_table.item(r, c)
        if c == 3 and item:
            link = item.data(Qt.ItemDataRole.UserRole)
            if link:
                webbrowser.open(link)

    def copy_trends_to_analyzer(self):
        if self.trend_table.rowCount() > 0:
            self.analysis_input_widget.setPlainText(
                "\n".join(
                    self.trend_table.item(r, 1).text()
                    for r in range(self.trend_table.rowCount())
                )
            )
            self.tabs.setCurrentIndex(1)
            self.log_message("INFO", "복사 완료.")

    def copy_autocomplete_to_analyzer(self):
        if (rows := self.autocomplete_table.rowCount()) > 0:
            kws = "\n".join(
                self.autocomplete_table.item(r, 0).text() for r in range(rows)
            )
            cur = self.analysis_input_widget.toPlainText().strip()
            self.analysis_input_widget.setPlainText(f"{cur}\n{kws}".strip())
            self.tabs.setCurrentIndex(1)

    def export_trends_to_excel(self):
        if self.trend_table.rowCount() == 0:
            return
        os.makedirs("output", exist_ok=True)
        df = pd.DataFrame(
            [
                {
                    self.trend_table.horizontalHeaderItem(0)
                    .text(): self.trend_table.item(r, 0)
                    .text(),
                    "키워드": self.trend_table.item(r, 1).text(),
                    "순위": int(self.trend_table.item(r, 2).text()),
                    "순위변동": self.trend_table.item(r, 3).text(),
                }
                for r in range(self.trend_table.rowCount())
            ]
        )
        df.to_excel(
            os.path.join(
                "output", f"trend_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            ),
            index=False,
        )
        QMessageBox.information(self, "성공", "저장 완료.")

    def export_to_excel(self):
        if getattr(self, "results_df", None) is None or self.results_df.empty:
            return
        os.makedirs("output", exist_ok=True)
        self.results_df[self.results_df["분류"] != "일반"].to_excel(
            os.path.join(
                "output", f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            ),
            index=False,
        )
        QMessageBox.information(self, "성공", "저장 완료.")

    def export_blog_views_to_excel(self):
        if getattr(self, "blog_views_df", None) is None or self.blog_views_df.empty:
            return
        os.makedirs("output", exist_ok=True)
        self.blog_views_df.to_excel(
            os.path.join(
                "output", f"views_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            ),
            index=False,
        )
        QMessageBox.information(self, "성공", "저장 완료.")

    def on_update_available(self, v):
        self.log_message("INFO", f"현재 버전: v{v}")

    def on_update_error(self, err):
        self.log_message("WARNING", f"업데이트 확인 오류: {err}")

    # [방어 3] 중복 종료 호출 완벽 방지 및 타임아웃 기반 안전 종료
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
        self.hide()  # 사용자에겐 꺼진 것처럼 보이게 함
        e.ignore()
        self.req_close_driver.emit()

    @pyqtSlot()
    def final_quit(self):
        self.bg_thread.quit()
        # [방어 6] 좀비 스레드 무한 대기 방어 (3초 타임아웃)
        if not self.bg_thread.wait(3000):
            print("Background thread did not terminate in time. Forcing quit.")
        QApplication.quit()


if __name__ == "__main__":
    freeze_support()
    app = QApplication(sys.argv)
    window = KeywordApp()
    window.show()
    sys.exit(app.exec())
