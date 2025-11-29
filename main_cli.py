import argparse
import sys
from core.plugin_manager import PluginManager
from core.engine import ScannerEngine
from reports.reporter import ReportGenerator, ConsoleReporter

def main():
    parser = argparse.ArgumentParser(description="SightSec Vulnerability Scanner")
    
    # Параметры согласно ТЗ 4.1.2.1
    scan_group = parser.add_argument_group('Scanning')
    scan_group.add_argument("--url", help="Target URL to scan")
    scan_group.add_argument("--json", default="report.json", help="Output JSON file path")
    scan_group.add_argument("--pdf", help="Output PDF file path (optional)")
    scan_group.add_argument("--source-path", help="Path to local source code for whitebox analysis")  # <-- Новый аргумент
    
    plugin_group = parser.add_argument_group('Plugins Management')
    plugin_group.add_argument("--list-plugins", action="store_true", help="List plugins")
    plugin_group.add_argument("--enable", help="Enable plugin")
    plugin_group.add_argument("--disable", help="Disable plugin")
    
    args = parser.parse_args()

    print(r"""
   _____ _       _     _   _____           
  / ____(_)     | |   | | / ____|          
 | (___  _  __ _| |__ | || (___   ___  ___ 
  \___ \| |/ _` | '_ \| | \___ \ / _ \/ __|
  ____) | | (_| | | | | | ____) |  __/ (__ 
 |_____/|_|\__, |_| |_|_||_____/ \___|\___|
            __/ |                          
           |___/   v1.0.0
    """)

    # 1. Загрузка плагинов
    pm = PluginManager(plugin_folder="plugins")
    pm.discover_plugins()

    # Логика управления плагинами (та же, что и раньше)
    if args.enable:
        pm.toggle_plugin(args.enable, True)
        sys.exit(0)
    if args.disable:
        pm.toggle_plugin(args.disable, False)
        sys.exit(0)
    if args.list_plugins:
        # (Код вывода списка плагинов такой же, как в предыдущем ответе)
        print("... Listing plugins ...") 
        sys.exit(0)

    if args.url:
        print(f"[*] Starting SightSec on {args.url}...\n")

        # Подготовка конфигурации с путем к исходникам
        config = {}
        if args.source_path:
            config["local_source_path"] = args.source_path
            print(f"[*] WhiteBox analysis enabled. Source path: {args.source_path}")

        engine = ScannerEngine(plugin_manager=pm)
        # Получаем список результатов (ScanResult)
        results = engine.start_scan(target_url=args.url, config=config)
        
        # 3. Вывод результатов в консоль (цветной)
        ConsoleReporter.print_summary(results)

        # 4. Генерация отчетов
        # [cite_start]JSON (обязательный по ТЗ [cite: 10])
        ReportGenerator.save_json(results, args.json)
        
        # PDF (по желанию пользователя)
        if args.pdf:
            ReportGenerator.save_pdf(results, args.pdf)
            
    else:
        parser.print_help()

if __name__ == "__main__":
    main()