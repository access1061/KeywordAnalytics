pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" pyqt_app.py



pyinstaller keyword_analyzer.spec --clean


pip install -r requirements.txt

python -m venv venv

venv\Scripts\activate


2.0 ver (api 저장기능 포함) 빌드 명령어
pyinstaller KeywordAnalyzerPro.spec

dll 이슈로 아래 파일로 빌드

pyinstaller --windowed --name KeywordAnalyzerPro --icon=keyword_pro.ico --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import=xlsxwriter pyqt_app.py

pyinstaller --onefile --windowed --name KeywordAnalyzerPro --icon=keyword_pro.ico --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import=xlsxwriter pyqt_app.py
