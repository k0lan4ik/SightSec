import sys
import os
import shutil
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QStackedWidget, QFrame, QGridLayout, QScrollArea,
                             QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QIcon, QFont, QCursor

# --- Импорты логики ---
from core.engine import ScannerEngine
from core.plugin_manager import PluginManager
from core.base_plugin import ScanContext, ScanResult
from reports.reporter import ReportGenerator

# --- STYLESHEET (CSS) ---
STYLESHEET = """
QMainWindow {
    background-color: #f8f9fa;
}

/* --- САЙДБАР --- */
QFrame#Sidebar {
    background-color: rgba(38, 69, 139, 1);
    min-width: 80px;
    max-width: 80px;
    border: none;
}
QPushButton#NavButton {
    background-color: transparent;
    border: none;
    border-radius: 10px;
    padding: 10px;
    color: #bdc3c7;
    font-size: 24px;
}
QPushButton#NavButton:hover {
    background-color: #34495e;
    color: white;
}
QPushButton#NavButton:checked {
    background-color: #3498db;
    color: white;
}

/* --- ОСНОВНЫЕ ЭЛЕМЕНТЫ --- */
QLineEdit {
    border: 1px solid #dfe6e9;
    border-radius: 8px;
    padding: 12px;
    font-size: 14px;
    background-color: white;
    selection-background-color: #3498db;
}
QLineEdit:focus {
    border: 1px solid #3498db;
}

/* Кнопка действия (белая с синей обводкой) */
QPushButton#ActionBtn {
    background-color: white;
    border: 1px solid #3498db;
    color: #3498db;
    border-radius: 8px;
    padding: 5px 10px; 
    font-weight: bold;
    font-size: 13px;
}
QPushButton#ActionBtn:hover {
    background-color: #f0f8ff;
}

/* Основная кнопка (Сканировать/Сохранить) */
QPushButton#PrimaryBtn {
    background-color: #2e4ead; 
    color: white;
    border: none;
    border-radius: 8px;
    padding: 12px 25px;
    font-size: 14px;
    font-weight: bold;
}
QPushButton#PrimaryBtn:hover {
    background-color: #1a2f6e;
}
QPushButton#PrimaryBtn:disabled {
    background-color: #95a5a6;
}

/* --- КАРТОЧКА ПЛАГИНА и АДМИН-ЭЛЕМЕНТЫ --- */
QFrame#PluginCard {
    background-color: white;
    border: 1px solid #000000;
    border-radius: 16px;
}
QFrame#PluginCard[active="true"] {
    border: 2px solid #000000;
}

QLabel#CardTitle {
    font-weight: bold;
    font-size: 16px;
    color: #2c3e50;
}
QLabel#CardDesc {
    color: #7f8c8d; 
    font-size: 11px;
    line-height: 1.2;
}

QPushButton#CardBtn {
    border-radius: 8px;
    padding: 8px;
    font-weight: 600;
}

QFrame#AddPluginCard {
    background-color: #000000;
    border-radius: 16px;
    border: none;
}
QFrame#AddPluginCard:hover {
    background-color: #1a2f6e;
}
QLabel#AddPluginText {
    color: white;
    font-weight: bold;
    font-size: 14px;
}

/* --- РЕЗУЛЬТАТЫ --- */
QLabel#PageTitle {
    font-size: 26px;
    font-weight: bold;
    color: #2c3e50;
    margin-bottom: 10px;
}
QFrame#ResultItem {
    background-color: white;
    border-radius: 8px;
    border-left: 5px solid #bdc3c7; 
    margin-bottom: 10px;
}
/* Секция деталей внутри карточки */
QFrame#DetailsFrame {
    background: #f0f2f5; 
    border-radius: 5px; 
    padding: 10px; 
    margin-top: 5px;
}
/* Для доказательств (payload, code) */
QLabel#EvidenceLabel {
    font-family: monospace; 
    background: #e0e4e7; 
    padding: 8px; 
    border-radius: 5px;
    font-size: 12px;
}

/* НОВЫЙ СТИЛЬ: Кнопка сворачивания/разворачивания деталей */
QPushButton#DetailToggleBtn {
    background-color: white;
    border: 1px solid #bdc3c7; 
    color: #34495e; 
    border-radius: 4px; 
    padding: 0px; 
    min-width: 30px; 
    max-width: 30px;
    min-height: 30px; 
    max-height: 30px;
    font-size: 18px; 
    font-weight: bold;
}
QPushButton#DetailToggleBtn:hover {
    background-color: #e0e4e7; 
    border-color: #95a5a6;
}

/* --- СТИЛИЗАЦИЯ СКРОЛЛБАРОВ --- */
QScrollBar:vertical {
    border: none;
    background: #f0f2f5; 
    width: 8px; 
    margin: 0px 0px 0px 0px;
}
QScrollBar::handle:vertical {
    background: #bdc3c7; 
    min-height: 20px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #95a5a6; 
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    border: none;
    background: none;
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}
QScrollBar:horizontal {
    border: none;
    background: #f0f2f5;
    height: 8px;
    margin: 0px 0px 0px 0px;
}
QScrollBar::handle:horizontal {
    background: #bdc3c7;
    min-width: 20px;
    border-radius: 4px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    border: none;
    background: none;
    width: 0px;
}
"""

# --- WORKER THREAD ---
class ScanWorker(QThread):
    finished_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)

    def __init__(self, engine, target_url, config):
        super().__init__()
        self.engine = engine
        self.target_url = target_url
        self.config = config

    def run(self):
        original_log = ScanContext.log
        def gui_logger(ctx_self, message):
            self.log_signal.emit(message)
            print(f"[Core] {message}")
        
        ScanContext.log = gui_logger
        try:
            results = self.engine.start_scan(self.target_url, self.config)
            self.finished_signal.emit(results)
        except Exception as e:
            self.log_signal.emit(f"CRITICAL ERROR: {str(e)}")
            self.finished_signal.emit([])
        finally:
            ScanContext.log = original_log

# --- UI COMPONENTS ---

class Sidebar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 0, 10, 0)
        layout.setSpacing(20)

        layout.addStretch()

        self.btn_scan = self._create_btn("🔍", "Сканирование")
        self.btn_plugins = self._create_btn("⚙️", "Плагины")
        self.btn_results = self._create_btn("📈", "Результаты")
        
        layout.addWidget(self.btn_scan)
        layout.addWidget(self.btn_plugins)
        layout.addWidget(self.btn_results)

        layout.addStretch()

    def _create_btn(self, icon_text, tooltip):
        btn = QPushButton(icon_text)
        btn.setObjectName("NavButton")
        btn.setToolTip(tooltip)
        btn.setCheckable(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        return btn

class PluginCard(QFrame):
    toggled = pyqtSignal(str, bool)

    def __init__(self, name, description, is_enabled):
        super().__init__()
        self.setObjectName("PluginCard")
        self.name = name
        self.is_enabled = is_enabled
        self.setProperty("active", str(is_enabled).lower())
        self.setFixedSize(220, 240)

        # *** КЛЮЧЕВЫЕ ИЗМЕНЕНИЯ ДЛЯ ГАРАНТИИ РАБОТЫ CSS ***
        self.setFrameShape(QFrame.Shape.StyledPanel) 
        self.setAutoFillBackground(True) # <- ЭТО ОБЯЗАТЕЛЬНО
        
        # Дополнительный "активатор" QSS-движка (иногда помогает)
        self.setStyleSheet("QFrame#PluginCard { padding: 0px; }") 
        # *************************************************

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 25, 20, 25)
        
        
        lbl_name = QLabel(name)
        lbl_name.setObjectName("CardTitle")
        lbl_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_name)

        short_desc = (description[:70] + '...') if len(description) > 70 else description
        lbl_desc = QLabel(short_desc)
        lbl_desc.setObjectName("CardDesc")
        lbl_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_desc.setWordWrap(True)
        layout.addWidget(lbl_desc)

        layout.addStretch()

        self.btn_toggle = QPushButton()
        self.btn_toggle.setObjectName("CardBtn")
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle.setFixedHeight(35)
        self.btn_toggle.clicked.connect(self._on_click)
        
        self._update_style()
        layout.addWidget(self.btn_toggle)

    def _update_style(self):
        if self.is_enabled:
            self.btn_toggle.setText("Выбрано")
            self.btn_toggle.setStyleSheet("""
                background-color: #2e4ead; color: white; border: none;
            """)
            self.setProperty("active", "true")
        else:
            self.btn_toggle.setText("Выбрать")
            self.btn_toggle.setStyleSheet("""
                background-color: white; color: #2e4ead; border: 1px solid #2e4ead;
            """)
            self.setProperty("active", "false")
        
        self.style().unpolish(self)
        self.style().polish(self)

    def _on_click(self):
        self.is_enabled = not self.is_enabled
        self._update_style()
        self.toggled.emit(self.name, self.is_enabled)

class AddPluginCard(QFrame):
    clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setObjectName("AddPluginCard")
        self.setFixedSize(220, 240)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # *** КЛЮЧЕВЫЕ ИЗМЕНЕНИЯ ДЛЯ ГАРАНТИИ РАБОТЫ CSS ***
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setAutoFillBackground(True) # <- ЭТО ОБЯЗАТЕЛЬНО
        
        # Дополнительный "активатор" QSS-движка (иногда помогает)
        self.setStyleSheet("QFrame#AddPluginCard { padding: 0px; }")
        # *************************************************

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)


        lbl_text = QLabel("Добавить плагин")
        lbl_text.setObjectName("AddPluginText")
        
        lbl_plus = QLabel("+")
        lbl_plus.setStyleSheet("color: white; font-size: 40px; font-weight: bold;")
        
        layout.addWidget(lbl_text, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_plus, 0, Qt.AlignmentFlag.AlignCenter)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

class ResultCard(QFrame):
    def __init__(self, result: ScanResult):
        super().__init__()
        self.setObjectName("ResultItem")
        self.result = result
        
        # Определяем цвет полоски по уровню опасности
        severity_colors = {
            "LOW": "#27ae60", "MEDIUM": "#f39c12", 
            "HIGH": "#e74c3c", "CRITICAL": "#c0392b"
        }
        color = severity_colors.get(result.severity, "#bdc3c7")
        self.setStyleSheet(f"QFrame#ResultItem {{ border-left: 5px solid {color}; }}")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)

        # --- Top Section (Always Visible) ---
        top_layout = QHBoxLayout()
        
        name_lbl = QLabel(f"**{result.vulnerability_id}** ({result.plugin_name})")
        name_lbl.setStyleSheet("font-weight: bold; font-size: 14px; color: #2c3e50;")
        
        # Severity Badge
        sev_lbl = QLabel(result.severity)
        sev_lbl.setStyleSheet(f"color: {color}; font-weight: bold; border: 1px solid {color}; border-radius: 4px; padding: 2px 6px;")
        
        # **ОБНОВЛЕННЫЙ ЭЛЕМЕНТ: Кнопка сворачивания/разворачивания**
        self.toggle_btn = QPushButton("▼") 
        self.toggle_btn.setObjectName("DetailToggleBtn")
        self.toggle_btn.setFixedSize(30, 30)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.clicked.connect(self._toggle_details)

        top_layout.addWidget(name_lbl)
        top_layout.addStretch()
        top_layout.addWidget(sev_lbl)
        top_layout.addWidget(self.toggle_btn)
        layout.addLayout(top_layout)

        # URL
        url_lbl = QLabel(f"<a href='{result.url}' style='color:#3498db;'>{result.url}</a>")
        url_lbl.setOpenExternalLinks(True)
        layout.addWidget(url_lbl)
        
        # --- Details Section (Hidden by Default) ---
        self.details_frame = QFrame()
        self.details_frame.setObjectName("DetailsFrame")
        self.details_layout = QVBoxLayout(self.details_frame)
        self.details_layout.setContentsMargins(5, 5, 5, 5)

        # 1. Evidence
        if result.evidence:
            ev_title = QLabel("<br><b>Доказательство (Payload/Proof):</b>")
            self.details_layout.addWidget(ev_title)
            
            ev_lbl = QLabel(result.evidence)
            ev_lbl.setObjectName("EvidenceLabel")
            ev_lbl.setWordWrap(True)
            self.details_layout.addWidget(ev_lbl)
        
        # 2. Response Snippet
        if result.response_snippet:
            resp_title = QLabel("<br><b>Фрагмент ответа сервера:</b>")
            self.details_layout.addWidget(resp_title)
            
            resp_lbl = QLabel(result.response_snippet)
            resp_lbl.setObjectName("EvidenceLabel")
            resp_lbl.setWordWrap(True)
            resp_lbl.setMaximumHeight(150)
            self.details_layout.addWidget(resp_lbl)

        layout.addWidget(self.details_frame)
        self.details_frame.hide()

    def _toggle_details(self):
        """Переключает видимость секции деталей и меняет текст кнопки (иконку)."""
        if self.details_frame.isVisible():
            self.details_frame.hide()
            self.toggle_btn.setText("▼") # Стрелка вниз, когда свернуто
        else:
            self.details_frame.show()
            self.toggle_btn.setText("▲") # Стрелка вверх, когда развернуто

# --- MAIN WINDOW ---

class MainUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SightSec Vulnerability Scanner")
        self.resize(1000, 700)
        
        self.pm = PluginManager()
        self.pm.discover_plugins()
        self.engine = ScannerEngine(self.pm)
        self.current_results = []
        
        self.SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        central = QWidget()
        self.setCentralWidget(central)
        main_h_layout = QHBoxLayout(central)
        main_h_layout.setContentsMargins(0, 0, 0, 0)
        main_h_layout.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.btn_scan.setChecked(True)
        self.sidebar.btn_scan.clicked.connect(lambda: self.switch_page(0))
        self.sidebar.btn_plugins.clicked.connect(lambda: self.switch_page(1))
        self.sidebar.btn_results.clicked.connect(lambda: self.switch_page(2))
        main_h_layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        main_h_layout.addWidget(self.stack)

        self.page_scan = self._init_scan_page()
        self.page_plugins = self._init_plugins_page()
        self.page_results = self._init_results_page()

        self.stack.addWidget(self.page_scan)
        self.stack.addWidget(self.page_plugins)
        self.stack.addWidget(self.page_results)

        self.setStyleSheet(STYLESHEET)

    def switch_page(self, idx):
        self.stack.setCurrentIndex(idx)
        self.sidebar.btn_scan.setChecked(idx == 0)
        self.sidebar.btn_plugins.setChecked(idx == 1)
        self.sidebar.btn_results.setChecked(idx == 2)
        
        if idx == 1:
            self._refresh_plugins_grid()

    # --- Pages Init ---

    def _init_scan_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(25)

        logo = QLabel("SightSec")
        logo.setStyleSheet("font-size: 50px; font-weight: bold; color: #34495e;")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target-site.com")
        self.url_input.setFixedWidth(450)

        self.folder_btn = QPushButton(" Добавить папку с проектом")
        self.folder_btn.setObjectName("ActionBtn")
        self.folder_btn.setFixedWidth(450)
        self.folder_btn.clicked.connect(self._select_folder)
        self.selected_folder = None

        self.scan_btn = QPushButton("Сканировать")
        self.scan_btn.setObjectName("PrimaryBtn")
        self.scan_btn.setFixedWidth(200)
        self.scan_btn.clicked.connect(self._start_scan)

        self.status_lbl = QLabel("Готов к работе")
        self.status_lbl.setStyleSheet("color: #95a5a6;")

        layout.addStretch()
        layout.addWidget(logo)
        layout.addWidget(self.url_input)
        layout.addWidget(self.folder_btn)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.status_lbl)
        layout.addStretch()
        return page

    def _init_plugins_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 20)

        lbl = QLabel("Настройка тестирования")
        lbl.setObjectName("PageTitle")
        layout.addWidget(lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        
        self.plugins_container = QWidget()
        self.plugins_grid = QGridLayout(self.plugins_container)
        self.plugins_grid.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.plugins_grid.setSpacing(20)
        
        scroll.setWidget(self.plugins_container)
        layout.addWidget(scroll)
        return page

    def _init_results_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 20)

        head_layout = QHBoxLayout()
        lbl = QLabel("Результаты")
        lbl.setObjectName("PageTitle")
        
        self.save_json_btn = QPushButton("Сохранить JSON")
        self.save_json_btn.setObjectName("ActionBtn")
        self.save_json_btn.clicked.connect(self._save_report_json)
        self.save_json_btn.setVisible(False)
        
        # **НОВАЯ КНОПКА PDF**
        self.save_pdf_btn = QPushButton("Сохранить PDF")
        self.save_pdf_btn.setObjectName("ActionBtn")
        self.save_pdf_btn.clicked.connect(self._save_report_pdf)
        self.save_pdf_btn.setVisible(False)

        head_layout.addWidget(lbl)
        head_layout.addStretch()
        head_layout.addWidget(self.save_json_btn)
        head_layout.addWidget(self.save_pdf_btn) 
        layout.addLayout(head_layout)

        self.res_area = QScrollArea()
        self.res_area.setWidgetResizable(True)
        self.res_area.setStyleSheet("background: #f0f2f5; border-radius: 10px; border: none;")
        
        self.res_cont = QWidget()
        self.res_layout = QVBoxLayout(self.res_cont)
        self.res_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        self.res_area.setWidget(self.res_cont)
        layout.addWidget(self.res_area)
        return page

    # --- Logic Methods ---

    def _refresh_plugins_grid(self):
        for i in reversed(range(self.plugins_grid.count())): 
            self.plugins_grid.itemAt(i).widget().setParent(None)

        all_classes = self.pm.get_plugin_classes(active_only=False)
        row, col = 0, 0
        columns_count = 3

        for cls in all_classes:
            meta = cls.meta()
            is_active = meta['name'] in self.pm.enabled_plugins
            desc = meta.get('description', f"Тип: {meta.get('type')}")
            
            card = PluginCard(meta['name'], desc, is_active)
            card.toggled.connect(self.pm.toggle_plugin)
            
            self.plugins_grid.addWidget(card, row, col)
            col += 1
            if col >= columns_count:
                col = 0
                row += 1

        add_card = AddPluginCard()
        add_card.clicked.connect(self._add_new_plugin_file)
        self.plugins_grid.addWidget(add_card, row, col)

    def _add_new_plugin_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Выберите плагин (.py)", "", "Python Files (*.py)")
        if fname:
            try:
                dest_dir = "plugins"
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)
                
                shutil.copy(fname, dest_dir)
                
                self.pm.discover_plugins()
                self._refresh_plugins_grid()
                QMessageBox.information(self, "Успех", "Плагин успешно добавлен!")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось добавить плагин:\n{e}")

    def _select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку проекта")
        if folder:
            self.selected_folder = folder
            self.folder_btn.setText(f"📁 {os.path.basename(folder)}")

    def _start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Введите URL!")
            return

        config = {"local_source_path": self.selected_folder}
        
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Сканирование...")
        self.status_lbl.setText("Запуск движка...")
        
        for i in reversed(range(self.res_layout.count())): 
            self.res_layout.itemAt(i).widget().setParent(None)
        self.save_json_btn.setVisible(False)
        self.save_pdf_btn.setVisible(False) 

        self.worker = ScanWorker(self.engine, url, config)
        self.worker.log_signal.connect(self.status_lbl.setText)
        self.worker.finished_signal.connect(self._on_scan_finished)
        self.worker.start()

    def _on_scan_finished(self, results):
        
        # Сортировка результатов по опасности
        sorted_results = sorted(
            results, 
            key=lambda x: self.SEVERITY_ORDER.get(x.severity.upper(), 99)
        )
        
        self.current_results = sorted_results
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Сканировать")
        self.status_lbl.setText(f"Готово. Найдено: {len(sorted_results)}")
        
        self.switch_page(2)
        self.save_json_btn.setVisible(True)
        self.save_pdf_btn.setVisible(True) # Показываем кнопку PDF

        if not sorted_results:
            lbl = QLabel("Уязвимостей не найдено.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.res_layout.addWidget(lbl)
            return

        for res in sorted_results:
            self.res_layout.addWidget(ResultCard(res))

    def _save_report_json(self):
        if not self.current_results:
            return
            
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "report.json", "JSON Files (*.json)")
        if path:
            try:
                ReportGenerator.save_json(self.current_results, path)
                QMessageBox.information(self, "Успех", f"Отчет сохранен:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения:\n{e}")

    def _save_report_pdf(self):
        """Сохраняет отчет в формате PDF, используя ReportGenerator."""
        if not self.current_results:
            return
            
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "report.pdf", "PDF Files (*.pdf)")
        if path:
            try:
                ReportGenerator.save_pdf(self.current_results, path)
                QMessageBox.information(self, "Успех", f"Отчет сохранен:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения:\n{e}\n\nУбедитесь, что установлена библиотека fpdf2 (например, pip install fpdf2), и что метод save_pdf в reporter.py корректен.")

if __name__ == "__main__":
    if not os.path.exists("plugins"): os.makedirs("plugins")
    
    app = QApplication(sys.argv)
    window = MainUI()
    window.show()
    sys.exit(app.exec())