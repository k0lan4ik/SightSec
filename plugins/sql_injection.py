# plugins/sqli_heuristic.py
from core.base_plugin import BasePlugin, ScanResult
from typing import List, Dict, Any
import difflib

class SQLiHeuristicPlugin(BasePlugin):
    @classmethod
    def meta(self):
        return {"name": "SQLi Heuristic Scanner", "type": "audit", "version": "2.1"}

    def run(self) -> List[ScanResult]:
        results = []
        # Берем URL, найденные краулером
        urls_to_test = list(self.context.discovered_urls)
        if not urls_to_test:
            urls_to_test = [self.context.target_url] # Если краулер ничего не нашел, тестим главную

        for url in urls_to_test:
            if "=" in url: # Тестируем только URL с параметрами
                vuln = self.check_url(url)
                if vuln:
                    results.append(vuln)
        return results

    def check_url(self, url):
        # 1. Запрос "Нормальный"
        original_resp = self.context.session.get(url)
        
        # 2. Запрос "Ломающий" (добавляем кавычку)
        # Простая замена, для примера. В реальности нужен парсинг URL параметров.
        injected_url = url + "'"
        injected_resp = self.context.session.get(injected_url)

        # 3. Анализ: Сравниваем похожесть (Ratio)
        # Если ответы сильно отличаются (ratio < 0.90), возможно, мы сломали SQL синтаксис
        matcher = difflib.SequenceMatcher(None, original_resp.text, injected_resp.text)
        similarity = matcher.ratio()

        if similarity < 0.95 and original_resp.status_code == 200:
            # Дополнительная проверка: ищем ошибки СУБД
            errors = ["SQL syntax", "mysql_fetch", "ORA-01756"]
            is_confirmed = any(err in injected_resp.text for err in errors)
            
            severity = "HIGH" if is_confirmed else "MEDIUM"
            
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="SQLI-HEUR",
                severity=severity,
                url=url,
                evidence="Различие в ответе при добавлении кавычки",
                response_snippet=f"Similarity: {similarity:.2f}"
            )
        return None