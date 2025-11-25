# plugins/sql_injection.py
from core.base_plugin import BasePlugin, ScanResult, TargetForm # ДОБАВЛЕНО: TargetForm
from typing import List, Dict, Any
import difflib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class SQLiHeuristicPlugin(BasePlugin):
    @classmethod
    def meta(cls): # ИСПРАВЛЕНО: meta() теперь @classmethod
        return {"name": "SQLi Heuristic Scanner", "type": "audit", "version": "2.2"}

    # Список пейлоадов, чтобы не определять его в run()
    SQLI_PAYLOADS = ["'", "' OR 1=1 --", '" OR 1=1 --']
    
    def run(self) -> List[ScanResult]:
        results = []
        
        # 1. Сбор целей для тестирования
        urls_to_test = list(self.context.discovered_urls)
        if not urls_to_test:
            urls_to_test = [self.context.target_url]

        # 2. Тестирование URL-параметров (Heuristic Mode)
        for url in urls_to_test:
            if "=" in url:
                vuln = self._check_url_params(url)
                if vuln:
                    results.append(vuln)
        
        # 3. Тестирование Форм (Payload Mode)
        for form in self.context.discovered_forms:
            # ИСПРАВЛЕНО: Передаем определенный список пейлоадов
            results.extend(self._check_form(form, self.SQLI_PAYLOADS))
            
        return results

    def _inject_url(self, url: str, payload: str) -> str:
        """Вставляет пейлоад в каждый параметр URL по очереди."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for key in query_params:
            # Создаем новый набор параметров для инъекции
            temp_params = query_params.copy()
            # Вставляем пейлоад в первое значение параметра
            temp_params[key] = [temp_params[key][0] + payload]
            
            # Собираем URL обратно
            injected_query = urlencode(temp_params, doseq=True)
            return urlunparse(parsed_url._replace(query=injected_query))
        return url # Если параметров не было, возвращаем оригинал

    def _check_url_params(self, url: str) -> ScanResult | None:
        """Тестирует URL-параметры методом эвристики и сравнения."""
        
        # 1. Запрос "Нормальный"
        try:
            original_resp = self.context.session.get(url, timeout=5)
        except Exception:
            return None

        # Пейлоад для "ломающего" запроса
        test_payload = "'" # Одинарная кавычка
        
        # 2. Запрос "Ломающий"
        injected_url = self._inject_url(url, test_payload)
        
        # Если URL остался тем же (нет параметров), пропускаем
        if injected_url == url:
            return None
            
        try:
            injected_resp = self.context.session.get(injected_url, timeout=5)
        except Exception:
            return None

        # 3. Анализ
        matcher = difflib.SequenceMatcher(None, original_resp.text, injected_resp.text)
        similarity = matcher.ratio()

        # Расширенный список ошибок (добавлены SQLite и кастомные)
        errors = [
            "SQL syntax", "mysql_fetch", "ORA-", "SQL_SYNTAX_ERROR", "sqlite3.OperationalError", "near '"
        ]
        
        is_confirmed = any(err in injected_resp.text for err in errors)
        
        # Если ответы сильно отличаются ИЛИ найдена явная ошибка
        if similarity < 0.95 or is_confirmed:
            
            severity = "CRITICAL" if is_confirmed else "MEDIUM"
            
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="SQLI-HEUR",
                severity=severity,
                url=injected_url,
                evidence=f"Similarity: {similarity:.2f}. Confirmed: {is_confirmed}",
                response_snippet=f"Original Status: {original_resp.status_code}, Injected Status: {injected_resp.status_code}"
            )
        return None

    def _check_form(self, form: TargetForm, payloads: List[str]) -> List[ScanResult]:
        """Тестирует все текстовые поля одной формы на SQLi."""
        form_results = []
        full_url = form.get_full_url(self.context.target_url)
        
        # Расширенный список ошибок для форм (дублируем, чтобы быть уверенными)
        detection_strings = [
            "SQL_SYNTAX_ERROR", 
            "syntax error",
            "near '",
            "mysql_fetch", "SQL syntax" 
        ]

        for input_field in form.inputs:
            if input_field.type not in ['text', 'search', 'password', 'textarea']:
                continue
            
            for payload in payloads:
                # 1. Готовим полезную нагрузку (data)
                data = {i.name: payload if i.name == input_field.name else i.value 
                        for i in form.inputs}
                
                # 2. Отправляем запрос, используя корректный метод (POST/GET)
                try:
                    if form.method == 'POST':
                        response = self.context.session.post(full_url, data=data, timeout=5)
                    else:
                        response = self.context.session.get(full_url, params=data, timeout=5)
                    
                    # 3. АНАЛИЗ ОТВЕТА
                    if any(s in response.text for s in detection_strings):
                        form_results.append(
                            ScanResult(
                                plugin_name=self.meta()['name'],
                                vulnerability_id="SQLI-FORM-001",
                                severity="CRITICAL",
                                url=full_url,
                                evidence=f"Payload '{payload[:10]}...' injected into field: {input_field.name}",
                                response_snippet=response.text[:200]
                            )
                        )
                        # Как только нашли одну уязвимость в форме, останавливаемся
                        return form_results 
                
                except Exception as e:
                    self.context.log(f"SQLi Form error at {full_url}: {e}")
                    
        return form_results