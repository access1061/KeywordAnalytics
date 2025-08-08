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
)
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal

# --- 스타일시트 (이전 버전과 동일) ---
STYLESHEET = """
    QWidget { background-color: #F8F9FA; color: #212529; font-family: 'Malgun Gothic'; font-size: 10pt; }
    QMainWindow { background-color: #FFFFFF; }
    QTabWidget::pane { border: 1px solid #DEE2E6; border-radius: 4px; }
    QTabBar::tab { background-color: #E9ECEF; color: #495057; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; border: 1px solid #DEE2E6; border-bottom: none; }
    QTabBar::tab:selected { background-color: #007BFF; color: white; font-weight: bold; }
    QPushButton { background-color: #007BFF; color: white; border-radius: 4px; padding: 10px; border: none; font-weight: bold; }
    QPushButton:hover { background-color: #0056b3; }
    QPushButton#SuccessButton { background-color: #28A745; }
    QPushButton#SuccessButton:hover { background-color: #1E7E34; }
    QPushButton:disabled { background-color: #6C757D; color: #E0E0E0; }
    QTextEdit, QTableWidget { background-color: #FFFFFF; border: 1px solid #CED4DA; border-radius: 4px; padding: 5px; }
    QHeaderView::section { background-color: #E9ECEF; color: #495057; padding: 8px; border: 1px solid #DEE2E6; font-weight: bold; }
    QProgressBar { border: none; border-radius: 6px; background-color: #E9ECEF; }
    QProgressBar::chunk { background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4DA6FF, stop:1 #007ACC); border-radius: 6px; }
    QTextEdit#LogWindow { background-color: #252525; color: #F8F9FA; font-family: 'Consolas', 'Courier New', monospace; }
"""


# --- 백그라운드 작업을 위한 Worker 클래스 (이전과 동일) ---
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
            self.error.emit(str(e))


# --- 메인 애플리케이션 클래스 ---
class KeywordApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("키워드 분석기 Pro v5.1")
        self.setGeometry(100, 100, 1400, 800)
        self.setStyleSheet(STYLESHEET)

        self.thread = None
        self.worker = None
        self.results_df = None

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, 3)

        log_layout = QVBoxLayout()
        log_label = QLabel("실시간 로그")
        log_label.setStyleSheet("font-weight: bold; font-size: 12pt; padding: 5px;")
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setObjectName("LogWindow")
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.log_widget)
        log_container = QWidget()
        log_container.setLayout(log_layout)
        main_layout.addWidget(log_container, 1)

        self.create_trend_fetch_tab()
        self.create_analysis_tab()

        load_dotenv("api.env")
        self.log_message("INFO", "프로그램이 시작되었습니다. API 키를 로드했습니다.")

    def create_trend_fetch_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        control_layout = QHBoxLayout()
        self.fetch_trends_button = QPushButton("어제 날짜 트렌드 가져오기")
        self.copy_to_analyzer_button = QPushButton("키워드 → 분석 탭으로 복사")
        self.status_label_fetch = QLabel("버튼을 눌러 트렌드 키워드 수집을 시작하세요.")
        control_layout.addWidget(self.fetch_trends_button)
        control_layout.addWidget(self.copy_to_analyzer_button)
        control_layout.addStretch()
        control_layout.addWidget(self.status_label_fetch)

        # ▼▼▼▼▼ [수정] QTextEdit를 QTableWidget으로 변경 ▼▼▼▼▼
        self.trend_table = QTableWidget()
        headers = ["카테고리", "키워드", "순위변동"]
        self.trend_table.setColumnCount(len(headers))
        self.trend_table.setHorizontalHeaderLabels(headers)
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        layout.addLayout(control_layout)
        layout.addWidget(self.trend_table)
        self.tabs.addTab(tab, "트렌드 키워드 수집")

        self.fetch_trends_button.clicked.connect(self.start_trend_fetching)
        self.copy_to_analyzer_button.clicked.connect(self.copy_trends_to_analyzer)

    def create_analysis_tab(self):
        # (이전과 동일)
        tab = QWidget()
        layout = QVBoxLayout(tab)
        input_label = QLabel("분석할 키워드를 아래에 붙여넣으세요 (한 줄에 하나씩)")
        self.analysis_input_widget = QTextEdit()
        self.analysis_input_widget.setPlaceholderText("예시)\n맛집\n국내여행\n...")
        control_layout = QHBoxLayout()
        self.analyze_button = QPushButton("경쟁률 분석 시작")
        self.export_excel_button = QPushButton("엑셀로 저장")
        self.export_excel_button.setObjectName("SuccessButton")
        self.export_excel_button.setDisabled(True)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setTextVisible(False)
        control_layout.addWidget(self.analyze_button)
        control_layout.addWidget(self.export_excel_button)
        control_layout.addStretch()
        control_layout.addWidget(self.progress_bar)
        self.result_table = QTableWidget()
        headers = ["분류", "키워드", "총검색량", "총문서수", "경쟁률"]
        self.result_table.setColumnCount(len(headers))
        self.result_table.setHorizontalHeaderLabels(headers)
        layout.addWidget(input_label)
        layout.addWidget(self.analysis_input_widget, 1)
        layout.addLayout(control_layout)
        layout.addWidget(self.result_table, 3)
        self.tabs.addTab(tab, "경쟁률 분석")

        self.analyze_button.clicked.connect(self.start_competition_analysis)
        self.export_excel_button.clicked.connect(self.export_to_excel)

    def log_message(self, level, message):
        # (이전과 동일)
        pass

    def start_trend_fetching(self):
        self.fetch_trends_button.setDisabled(True)
        self.status_label_fetch.setText("트렌드 수집 중...")
        self.trend_table.setRowCount(0)  # 테이블 초기화
        self.run_worker(self.fetch_trends_worker, self.on_trend_fetching_finished)

    # (start_competition_analysis, run_worker 등 이전과 동일)
    def start_competition_analysis(self):
        pass

    def run_worker(self, worker_fn, finish_slot, **kwargs):
        pass

    # --- 워커 함수들 (백그라운드 로직) ---
    def fetch_trends_worker(self, worker_instance):
        worker_instance.log.emit("INFO", "📈 트렌드 키워드 수집을 시작합니다...")
        cookies = load_cookies_from_auth_file()
        if not cookies:
            raise ValueError("'auth.json' 파일을 찾을 수 없습니다.")
        worker_instance.log.emit("SUCCESS", "✅ 인증 정보 로드 성공.")

        target_date_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        # ▼▼▼▼▼ [수정] 모든 카테고리를 포함하도록 리스트 확장 ▼▼▼▼▼
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
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        all_trends_data = []  # structured data
        total_categories = len(CATEGORIES)

        for i, category in enumerate(CATEGORIES):
            worker_instance.log.emit("INFO", f"   - '{category}' 카테고리 수집 중...")
            worker_instance.progress.emit(int((i + 1) / total_categories * 100))
            encoded_category = quote(category)
            api_url = f"https://creator-advisor.naver.com/api/v6/trend/category?categories={encoded_category}&contentType=text&date={target_date_str}&hasRankChange=true&interval=day&limit=20&service=naver_blog"
            try:
                response = requests.get(
                    api_url,
                    cookies=cookies,
                    headers={"Referer": "https://creator-advisor.naver.com/"},
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("data") and data["data"][0].get("queryList"):
                        for item in data["data"][0]["queryList"]:
                            # ▼▼▼▼▼ [수정] 구조화된 데이터로 저장 ▼▼▼▼▼
                            all_trends_data.append(
                                {
                                    "카테고리": category,
                                    "키워드": item["query"],
                                    "순위변동": item.get("rankChange"),
                                }
                            )
                            # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
                else:
                    worker_instance.log.emit(
                        "WARNING",
                        f"   - '{category}' 카테고리 요청 실패 (상태 코드: {response.status_code})",
                    )
                time.sleep(0.3)
            except Exception as e:
                worker_instance.log.emit(
                    "ERROR", f"   - '{category}' 처리 중 오류: {e}"
                )

        return all_trends_data  # 키워드 리스트 대신 구조화된 데이터 반환

    # (analyze_competition_worker 이전과 동일)
    def analyze_competition_worker(self, worker_instance, keywords):
        pass

    # --- 슬롯 함수들 (UI 업데이트) ---
    def on_trend_fetching_finished(self, trend_data):
        self.fetch_trends_button.setDisabled(False)
        self.progress_bar.setValue(100)
        self.status_label_fetch.setText(
            f"✅ {len(trend_data)}개 트렌드 키워드 수집 완료!"
        )
        self.log_message("SUCCESS", "트렌드 키워드 수집이 완료되었습니다.")

        # ▼▼▼▼▼ [수정] 테이블에 데이터 채우고 색상 적용 ▼▼▼▼▼
        self.trend_table.setRowCount(len(trend_data))
        for row_idx, item in enumerate(trend_data):
            # 아이템 생성
            category_item = QTableWidgetItem(str(item["카테고리"]))
            keyword_item = QTableWidgetItem(str(item["키워드"]))

            rank_change = item["순위변동"]
            rank_text = ""
            if rank_change is None:
                rank_text = "NEW"
            elif rank_change == 0:
                rank_text = "-"
            else:
                rank_text = f"{rank_change:g}"  # g 포맷은 .0을 제거해줌

            rank_item = QTableWidgetItem(rank_text)
            rank_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # 조건부 색상 적용
            if rank_change is None:  # NEW
                rank_item.setForeground(QColor("#28A745"))  # 녹색
            elif rank_change > 0:  # 상승
                rank_item.setForeground(QColor("#DC3545"))  # 빨간색
            elif rank_change < 0:  # 하락
                rank_item.setForeground(QColor("#007BFF"))  # 파란색

            self.trend_table.setItem(row_idx, 0, category_item)
            self.trend_table.setItem(row_idx, 1, keyword_item)
            self.trend_table.setItem(row_idx, 2, rank_item)

        self.trend_table.resizeColumnsToContents()  # 글자 크기에 맞춰 컬럼 폭 자동 조절
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

    # (on_analysis_finished, on_worker_error 등 이전과 동일)
    def on_analysis_finished(self, df):
        pass

    def on_worker_error(self, error_message):
        pass

    def copy_trends_to_analyzer(self):
        # ▼▼▼▼▼ [수정] 테이블에서 키워드만 복사하도록 변경 ▼▼▼▼▼
        rows = self.trend_table.rowCount()
        if rows > 0:
            keywords = [self.trend_table.item(row, 1).text() for row in range(rows)]
            self.analysis_input_widget.setPlainText("\n".join(keywords))
            self.tabs.setCurrentIndex(1)
            self.log_message(
                "INFO", f"{len(keywords)}개 키워드를 분석 탭으로 복사했습니다."
            )
        else:
            QMessageBox.information(self, "알림", "먼저 트렌드 키워드를 가져와주세요.")
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

    # (update_result_table, export_to_excel 등 이전과 동일)
    def update_result_table(self, df):
        pass

    def export_to_excel(self):
        pass


if __name__ == "__main__":
    # 전체 코드를 여기에 포함시킵니다.
    # ... (생략된 모든 함수들의 전체 코드를 포함한 최종본)
    app = QApplication(sys.argv)
    window = KeywordApp()
    window.show()
    sys.exit(app.exec())
