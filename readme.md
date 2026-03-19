<<<<<<< HEAD
# Keyword Pro Build Commands
=======
# Keyword Analytics Build Commands
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b

pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" pyqt_app.py

pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" pyqt_app_new.py

pip install -r requirements.txt

<<<<<<< HEAD
pyinstaller keyword_analyzer.spec

pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" --hidden-import "openpyxl" pyqt_app_new.py
=======
python -m venv venv

venv\Scripts\activate

2.0 ver (api 저장기능 포함) 빌드 명령어
pyinstaller KeywordAnalyzerPro.spec

dll 이슈로 아래 파일로 빌드

pyinstaller --windowed --name KeywordAnalyzerPro --icon=keyword_pro.ico --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import=xlsxwriter pyqt_app.py

pyinstaller --onefile --windowed --name Keyword_studio_Pro --icon=studio.ico --add-data "studio.ico;." --add-data "style.qss;." --hidden-import=xlsxwriter Keyword_Studio_Gemini.py
>>>>>>> 2d0a37ae0d13296509d8cb65c08d1a7a02bb985b
