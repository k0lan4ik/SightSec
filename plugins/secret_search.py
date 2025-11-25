# plugins/secret_search.py
import os
import re
from core.base_plugin import BasePlugin, ScanResult
from typing import List, Dict, Any

class SourceCodeAuditor(BasePlugin):
    @classmethod
    def meta(self):
        return {"name": "Hardcoded Secrets Scanner", "type": "whitebox", "version": "1.0"}

    def run(self) -> List[ScanResult]:
        # В конфиге мы ожидаем путь к локальной папке с кодом
        source_path = self.context.config.get("local_source_path")
        if not source_path or not os.path.exists(source_path):
            return []

        results = []
        # Регулярки для поиска ключей (AWS, Private Keys, etc)
        patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key": r"api_key\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]"
        }

        for root, _, files in os.walk(source_path):
            for file in files:
                if file.endswith(('.py', '.js', '.env', '.config')):
                    full_path = os.path.join(root, file)
                    with open(full_path, 'r', errors='ignore') as f:
                        content = f.read()
                        for name, regex in patterns.items():
                            match = re.search(regex, content)
                            if match:
                                results.append(ScanResult(
                                    plugin_name=self.meta()['name'],
                                    vulnerability_id="SEC-CODE",
                                    severity="CRITICAL",
                                    url=f"file://{full_path}",
                                    evidence=match.group(0),
                                    response_snippet="Найден хардкод секрета в исходном коде"
                                ))
        return results