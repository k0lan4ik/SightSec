import requests
from typing import Dict, Any, List
from core.base_plugin import ScanContext, ScanResult

class ScenarioExecutor:
    """Движок для выполнения пользовательских, последовательных тест-кейсов."""
    
    def execute_scenario(self, scenario: Dict[str, Any], context: ScanContext) -> List[ScanResult]:
        
        context.log(f"Запуск кастомного сценария: {scenario.get('name', 'Unnamed Scenario')}")
        results = []
        
        # Используем сессию из контекста, чтобы сохранить авторизацию
        session = context.session 
        
        for step in scenario.get('steps', []):
            step_id = step.get('id', 'N/A')
            action = step.get('action')
            
            if action == "HTTP_REQUEST":
                # --- Шаг: Выполнение HTTP-запроса ---
                method = step.get('method', 'GET').upper()
                path = step.get('path', '/')
                url = context.target_url + path
                
                try:
                    if method == 'POST':
                        response = session.post(url, data=step.get('data', {}))
                    else: # GET, PUT, DELETE и т.д.
                        response = session.request(method, url, params=step.get('params', {}))
                    
                    context.log(f"Step {step_id}: {method} {path} -> Status {response.status_code}")

                    # Сохранение ответа для следующего шага (например, извлечение токена)
                    context.config[f'response_{step_id}'] = response 
                    
                except requests.RequestException as e:
                    context.log(f"Step {step_id} FAILED (Request): {e}")

            elif action == "ASSERT":
                # --- Шаг: Проверка результата (Assertion) ---
                check_type = step.get('check_type')
                expected = step.get('expected_value')
                
                # Допустим, мы проверяем ответ предыдущего шага (response_1)
                prev_response: requests.Response = context.config.get(f"response_{step.get('check_step_id')}")
                
                if prev_response:
                    is_ok = False
                    if check_type == 'status_code' and prev_response.status_code == expected:
                        is_ok = True
                    elif check_type == 'text_contains' and expected in prev_response.text:
                        is_ok = True
                    
                    if not is_ok:
                        results.append(ScanResult(
                            plugin_name="Scenario Builder",
                            vulnerability_id=f"SCENARIO-FAIL-{step_id}",
                            severity="CRITICAL" if step.get('severity') == 'critical' else 'MEDIUM',
                            url=prev_response.url,
                            evidence=f"Assertion failed: Expected {expected}",
                            response_snippet=f"Actual status: {prev_response.status_code}"
                        ))
                        context.log(f"Step {step_id}: ASSERT FAILED.")
                        
            # Можно добавить другие действия: 'WAIT', 'EXTRACT_TOKEN', 'UPLOAD_FILE'

        return results