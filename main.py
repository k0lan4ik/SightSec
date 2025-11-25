import sys
from PyQt6.QtWidgets import QApplication
from ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    
    # Загрузка стилей (Dark Theme)
    app.setStyleSheet("""
        QMainWindow { background-color: #2b2b2b; }
        QLabel { color: #ffffff; }
        QPushButton { background-color: #0d6efd; color: white; border-radius: 5px; padding: 5px; }
        QPushButton:hover { background-color: #0b5ed7; }
    """)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()