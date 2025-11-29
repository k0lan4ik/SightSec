from core.base_plugin import BasePlugin, ScanResult

class SQLInjector(BasePlugin):
    @classmethod
    def meta(cls) -> dict:
        return {
            "name": "SQL Injection Scanner",
            "version": "1.0",
            "type": "audit"
        }

    def run(self):
        results = []
        # Простые пейлоады для Error-based SQLi
        payloads = ["'", "\"", "' OR '1'='1"]
        errors = ["syntax error", "mysql_fetch", "ORA-", "PostgreSQL"]

        # 1. Проверка найденных форм
        for form in self.context.discovered_forms:
            target_url = form.get_full_url(self.context.target_url)
            
            for inp in form.inputs:
                if inp.type in ['submit', 'button', 'image']:
                    continue
                
                for payload in payloads:
                    # Подготовка данных
                    data = {i.name: i.value for i in form.inputs}
                    data[inp.name] = payload # Внедряем пейлоад
                    
                    try:
                        if form.method == 'POST':
                            res = self.context.session.post(target_url, data=data)
                        else:
                            res = self.context.session.get(target_url, params=data)
                        
                        # Анализ ответа
                        for err in errors:
                            if err in res.text:
                                results.append(ScanResult(
                                    plugin_name=self.meta()['name'],
                                    vulnerability_id="SQLI-001",
                                    severity="CRITICAL", # Согласно ТЗ классификация критичности
                                    url=target_url,
                                    evidence=f"Input: {inp.name}, Payload: {payload}",
                                    response_snippet=err
                                ))
                                break # Нашли - идем к следующему инпуту
                    except Exception as e:
                        self.context.log(f"SQLi check fail: {e}")
        
        return results