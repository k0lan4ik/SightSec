# plugins/config_auditor.py
import os
from core.base_plugin import BasePlugin, ScanResult
from typing import List, Dict, Any

class ConfigAuditorPlugin(BasePlugin):
    @classmethod
    def meta(self):
        return {"name": "Local Config Auditor", "type": "whitebox", "version": "1.0"}

    def run(self) -> List[ScanResult]:
        results = []
        
        # Берем путь из конфигурации, переданной ядру
        source_path = self.context.config.get("local_source_path")
        
        if not source_path or not os.path.isdir(source_path):
            self.context.log("White Box: local_source_path не указан или недействителен. Пропускаю.")
            return []

        # --- Проверка наличия опасных файлов ---
        
        critical_files = ["config.ini", ".env", "db_creds.txt"]
        
        for root, _, files in os.walk(source_path):
            for file in files:
                if file in critical_files:
                    full_path = os.path.join(root, file)
                    # Дополнительная проверка: читаем файл и ищем "password"
                    try:
                        with open(full_path, 'r', errors='ignore') as f:
                            content = f.read(1024) # Читаем только начало
                            if "password" in content.lower() or "secret" in content.lower():
                                results.append(ScanResult(
                                    plugin_name=self.meta()['name'],
                                    vulnerability_id="WB-SECRETS-001",
                                    severity="CRITICAL",
                                    url=f"file://{full_path}", # Используем file:// для локальных путей
                                    evidence="Файл конфигурации содержит потенциальные учетные данные.",
                                    response_snippet=content[:100] + "..."
                                ))
                    except Exception as e:
                        self.context.log(f"Ошибка чтения файла {full_path}: {e}")
                        
        return results