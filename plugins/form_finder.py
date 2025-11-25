# plugins/form_finder.py
from core.base_plugin import BasePlugin, ScanResult, TargetForm, FormInput
from typing import List, Dict, Any
from bs4 import BeautifulSoup

class FormFinderPlugin(BasePlugin):
    @classmethod
    def meta(self):
        return {"name": "HTML Form Finder", "type": "discovery", "version": "1.0"}

    def run(self) -> List[ScanResult]:
        target = self.context.target_url
        self.context.log(f"Discovery: Ищу формы на {target}")
        
        try:
            # Используем общую сессию для получения контента
            response = self.context.session.get(target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms_found_count = 0
            for form in soup.find_all('form'):
                action = form.get('action') or self.context.target_url
                method = form.get('method', 'get').upper()
                
                form_data = TargetForm(
                    action_url=action,
                    method=method,
                    inputs=[]
                )
                
                for field in form.find_all(['input', 'textarea', 'select']):
                    input_name = field.get('name')
                    input_type = field.get('type', 'text')
                    input_value = field.get('value', '')
                    
                    if input_name:
                        form_data.inputs.append(
                            FormInput(input_name, input_type, input_value)
                        )
                
                self.context.discovered_forms.append(form_data)
                forms_found_count += 1
            
            self.context.log(f"Discovery завершено. Найдено {forms_found_count} форм.")
            return [] 
            
        except Exception as e:
            self.context.log(f"Ошибка FormFinder: {e}")
            return []