import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List
from core.base_plugin import ScanContext, ScanResult
from core.plugin_manager import PluginManager

class ScannerEngine:
    """
    Управляет жизненным циклом сканирования, фазами и многопоточностью.
    """
    def __init__(self, plugin_manager: PluginManager):
        self.pm = plugin_manager
        self.max_workers = 5 # Ограничение на количество параллельных потоков

    def start_scan(self, target_url: str, config: dict) -> List[ScanResult]:
        
        # --- 1. Инициализация и Контекст ---
        
        # Создаем новую сессию для каждого сканирования
        session = requests.Session()
        session.headers.update({"User-Agent": "SecScanner-Python-Core/1.0"})
        
        context = ScanContext(
            target_url=target_url,
            session=session,
            config=config
        )
        context.log(f"Начало сканирования {target_url}...")

        all_results: List[ScanResult] = []
        # ВАЖНОЕ ИЗМЕНЕНИЕ: Запрашиваем только активные плагины
        plugin_classes = self.pm.get_plugin_classes(active_only=True)

        if not plugin_classes:
            context.log("ВНИМАНИЕ: Нет активных плагинов для запуска! Проверьте настройки.")
            return []

        # --- 2. Разделение по фазам ---
        discovery_plugins = [cls(context) for cls in plugin_classes if cls.meta().get('type') == 'discovery']
        audit_plugins = [cls(context) for cls in plugin_classes if cls.meta().get('type') == 'audit']
        whitebox_plugins = [cls(context) for cls in plugin_classes if cls.meta().get('type') == 'whitebox']
       
        # --- 3. Фаза Discovery (Последовательно) ---
        context.log("Phase 1: Discovery (Crawler, FormFinder)")
        for plugin in discovery_plugins:
            plugin.setup()
            plugin.run()
            plugin.teardown()
            
        context.log(f"Discovery завершено. Найдено URL: {len(context.discovered_urls)}, Форм: {len(context.discovered_forms)}")


        # --- 4. Фаза Audit (Параллельно) ---
        context.log("Phase 2: Audit (SQLi, XSS, Fuzzing)")
        
        audit_futures = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Сначала отправляем ВСЕ задачи
            for plugin in audit_plugins:
                audit_futures.append(executor.submit(self._run_audit_plugin, plugin))
            
            # Затем собираем результаты по мере готовности
            from concurrent.futures import as_completed
            for future in as_completed(audit_futures):
                try:
                    res = future.result()
                    all_results.extend(res)
                except Exception as exc:
                     context.log(f"Thread Error: {exc}")
        
        # --- 5. Фаза White Box (Последовательно, т.к. может быть ресурсоемко) ---
        if config.get("local_source_path"):
            context.log("Phase 3: White Box (Code Analysis)")
            for plugin in whitebox_plugins:
                plugin.setup()
                results = plugin.run()
                all_results.extend(results)
                plugin.teardown()
        else:
            context.log("Phase 3: White Box skipped (no source path provided)")
        
        
        context.log("Сканирование завершено.")
        return all_results

    def _run_audit_plugin(self, plugin) -> List[ScanResult]:
        """Внутренний метод для запуска аудиторского плагина"""
        try:
            plugin.setup()
            results = plugin.run()
            plugin.teardown()
            return results
        except Exception as e:
            plugin.context.log(f"FATAL error in {plugin.meta['name']}: {e}")
            return []