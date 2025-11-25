# plugins/xss_fuzzer.py
from core.base_plugin import BasePlugin, ScanResult
from typing import List

class XSSFuzzerPlugin(BasePlugin):
    @classmethod
    def meta(self):
        return {"name": "Basic XSS Fuzzer", "type": "audit", "version": "1.0"}

    def run(self) -> List[ScanResult]:
        results = []
        xss_payload = "<script>alert(1)</script>" # Простой, но легко детектируемый пейлоад
        
        if not self.context.discovered_forms:
            self.context.log("Audit: Формы не найдены, XSS Fuzzer пропускается.")
            return []

        for target_form in self.context.discovered_forms:
            full_url = target_form.get_full_url(self.context.target_url)
            
            # --- Логика фаззинга ---
            for field in target_form.inputs:
                if field.type in ['text', 'textarea', 'search']:
                    # Создаем данные для отправки, вставляя пейлоад в одно поле
                    post_data = {i.name: xss_payload if i.name == field.name else i.value 
                                 for i in target_form.inputs}
                    
                    try:
                        if target_form.method == 'POST':
                            response = self.context.session.post(full_url, data=post_data)
                        else:
                            response = self.context.session.get(full_url, params=post_data)
                        
                        # --- Детектирование ---
                        # Если наш пейлоад вернулся в ответе без кодирования, это XSS
                        if xss_payload in response.text:
                            results.append(ScanResult(
                                plugin_name=self.meta()['name'],
                                vulnerability_id="XSS-REFLECT-001",
                                severity="HIGH",
                                url=full_url,
                                evidence=f"Payload {xss_payload} отражен в поле {field.name}",
                                response_snippet=f"Form Action: {target_form.action_url}"
                            ))
                            break # Нашли XSS, идем к следующей форме
                    
                    except Exception as e:
                        self.context.log(f"XSS Fuzzer error on {full_url}: {e}")
                
        return results