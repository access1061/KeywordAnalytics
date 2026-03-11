# Keyword Pro Build Commands

pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" pyqt_app.py

pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" pyqt_app_new.py

pip install -r requirements.txt

pyinstaller keyword_analyzer.spec

pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" --hidden-import "openpyxl" pyqt_app_new.py
