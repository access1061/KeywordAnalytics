pyinstaller --noconsole --onefile --icon="keyword_pro.ico" --name="Keyword_Pro" --add-data "keyword_pro.ico;." --add-data "style.qss;." --hidden-import "xlsxwriter" pyqt_app.py



pyinstaller keyword_analyzer.spec --clean