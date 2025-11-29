import json
import os
from datetime import datetime
from typing import List
from dataclasses import asdict
from fpdf import FPDF
from colorama import init, Fore, Style
from core.base_plugin import ScanResult

# Инициализация цвета для консоли
init(autoreset=True)

class ConsoleReporter:
    """Вывод результатов в консоль с цветовой подсветкой."""
    
    SEVERITY_COLORS = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.BLUE,
        "INFO": Fore.GREEN
    }

    @staticmethod
    def print_summary(results: List[ScanResult]):
        print("\n" + "="*60)
        print(f"{Style.BRIGHT}РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ{Style.RESET_ALL}")
        print("="*60)
        
        if not results:
            print(f"{Fore.GREEN}Уязвимостей не обнаружено.{Style.RESET_ALL}")
            return

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_results = sorted(results, key=lambda x: order.get(x.severity, 10))

        for res in sorted_results:
            color = ConsoleReporter.SEVERITY_COLORS.get(res.severity, Fore.WHITE)
            print(f"[{color}{res.severity:<8}{Style.RESET_ALL}] {res.plugin_name}")
            print(f"  Url: {res.url}")
            print(f"  Info: {res.evidence}")
            print("-" * 60)

        stats = {k: 0 for k in order.keys()}
        for res in results:
            if res.severity in stats:
                stats[res.severity] += 1
        
        print(f"\n{Style.BRIGHT}ИТОГОВАЯ СТАТИСТИКА:{Style.RESET_ALL}")
        for sev, count in stats.items():
            if count > 0:
                color = ConsoleReporter.SEVERITY_COLORS.get(sev, Fore.WHITE)
                print(f"{sev:<10}: {color}{count}{Style.RESET_ALL}")


class PdfReporter(FPDF):
    """Генератор PDF отчетов, наследует FPDF."""
    
    def __init__(self, orientation='P', unit='mm', format='A4'):
        # Сначала инициализируем родительский класс
        super().__init__(orientation, unit, format)
        
        # Затем регистрируем шрифты
        custom_font_alias = 'oswald'
        font_path = os.path.join("reports", "font", "Oswald-VariableFont_wght.ttf") 
        
        self.font_name = 'helvetica'  # Стандартный шрифт по умолчанию
        
        if os.path.exists(font_path):
            try:
                # Регистрируем шрифт после инициализации
                self.add_font(custom_font_alias, '', font_path, uni=True)
                self.add_font(custom_font_alias, 'B', font_path, uni=True)
                self.font_name = custom_font_alias
                print(f"[+] Custom font '{custom_font_alias}' registered successfully.")
            except Exception as e:
                print(f"[!] Error registering font: {e}. Using default.")
        else:
            print(f"[!] Warning: Font file not found at '{font_path}'. Using default Helvetica.")
        
        self.set_auto_page_break(auto=True, margin=15)
        # Устанавливаем margins для предотвращения ошибки пространства
        self.set_left_margin(10)
        self.set_right_margin(10)

    def header(self):
        self.set_font(self.font_name, 'B', 15)
        self.cell(0, 10, 'SightSec Vulnerability Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font(self.font_name, '', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_vulnerability(self, res: ScanResult):
        # Устанавливаем margins для этого контента
        self.set_left_margin(10)
        self.set_right_margin(10)
        
        # 1. Заголовок (Severity)
        if res.severity == 'CRITICAL':
            self.set_text_color(255, 0, 0)
        elif res.severity == 'HIGH':
            self.set_text_color(200, 50, 0)
        elif res.severity == 'MEDIUM':
            self.set_text_color(255, 165, 0)
        else:
            self.set_text_color(0, 0, 0)

        self.set_font(self.font_name, 'B', 12)
        self.cell(0, 10, f"[{res.severity}] {res.plugin_name}", 0, 1)
        self.set_text_color(0, 0, 0)
        
        # 2. Контент (URL и Evidence)
        self.set_font(self.font_name, '', 8)
        
        # Обработка URL - разбиваем длинные строки
        url_text = f"URL: {res.url}"
        if self.get_string_width(url_text) > 180:  # Проверяем ширину
            self.multi_cell(0, 4, url_text)
        else:
            self.cell(0, 4, url_text, 0, 1)
        
        # Обработка Evidence - разбиваем длинные строки
        evidence_text = f"Evidence: {res.evidence}"
        self.multi_cell(0, 4, evidence_text)
        
        self.ln(2)
        
        # 3. Сниппет - ВАЖНОЕ ИСПРАВЛЕНИЕ: используем тот же шрифт, что поддерживает кириллицу
        snippet = res.response_snippet[:300] + "..." if len(res.response_snippet) > 300 else res.response_snippet
        # Заменяем Courier на наш основной шрифт, который поддерживает кириллицу
        self.set_font(self.font_name, '', 7)  # БЫЛО: 'Courier', СТАЛО: self.font_name
        self.set_fill_color(240, 240, 240)
        
        # Для сниппета используем multi_cell с явной шириной
        available_width = 190  # Ширина A4 минус margins
        
        # Очищаем текст от потенциально проблемных символов
        clean_snippet = self.clean_text(snippet)
        clean_snippet = clean_snippet.replace('\x00', '')  # Удаляем нулевые байты
        
        self.multi_cell(available_width, 4, f"Server Response:\n{clean_snippet}", 1, 'L', True)
        self.ln(5)

    def clean_text(self, text):
        """Очистка текста от символов, которые могут вызвать проблемы в PDF"""
        if not text:
            return ""
        # Удаляем управляющие символы, но оставляем кириллицу и обычные символы
        return ''.join(char for char in str(text) if ord(char) >= 32 or char in '\n\r\t')


class ReportGenerator:
    @staticmethod
    def save_json(results: List[ScanResult], filename: str):
        data = {
            "scan_date": datetime.now().isoformat(),
            "tool": "SightSec",
            "results": [asdict(r) for r in results]
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"[+] JSON report saved: {filename}")

    @staticmethod
    def save_pdf(results: List[ScanResult], filename: str):
        pdf_reporter = PdfReporter()
        active_font_name = pdf_reporter.font_name

        pdf_reporter.set_font(active_font_name, '', 12)
        pdf_reporter.add_page()
        
        # Метаданные
        pdf_reporter.set_font(active_font_name, '', 10)
        pdf_reporter.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
        pdf_reporter.cell(0, 10, f"Total Vulnerabilities: {len(results)}", 0, 1)
        pdf_reporter.ln(10)

        # Сортировка и добавление уязвимостей
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_results = sorted(results, key=lambda x: order.get(x.severity, 10))

        for res in sorted_results:
            pdf_reporter.add_vulnerability(res)
            
        pdf_reporter.output(filename)
        print(f"[+] PDF report saved: {filename}")