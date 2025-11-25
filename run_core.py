from core.plugin_manager import PluginManager
from core.engine import ScannerEngine
from core.base_plugin import ScanContext
import os

def main():
    # 1. Инициализация менеджера и загрузка плагинов
    manager = PluginManager(plugin_folder="plugins")
    manager.discover_plugins()
    
    # 2. Инициализация движка
    engine = ScannerEngine(manager)
    
    
    # 3. Настройка сканирования
    target = "http://127.0.0.1:8080" # Цель для сканирования
    whitebox_path = os.path.join(os.getcwd(), "../target_site")
    config = {
        "local_source_path": whitebox_path, # Передаем путь для White Box
        "timeout": 10
    }
    
    # 4. Запуск сканирования
    print("\n================ STARTING SCAN ================")
    final_results = engine.start_scan(target, config)
    print("================ SCAN FINISHED ================\n")

    # 5. Вывод результатов
    for r in final_results:
        print(f"[{r.severity.upper():<10}] Plugin: {r.plugin_name:<20} | ID: {r.vulnerability_id:<15} | URL: {r.url}")

if __name__ == "__main__":
    # Для запуска необходимо создать папку 'plugins' с примерами:
    # plugins/example_crawler.py и plugins/example_audit.py (наследники BasePlugin)
    main()