import requests
from typing import List
from core.base_plugin import BasePlugin, ScanContext, ScanResult

class SensitiveFilesPlugin(BasePlugin):
    """Плагин для проверки раскрытия чувствительной информации через файлы"""
    
    @classmethod
    def meta(cls):
        return {
            'name': 'sensitive_files',
            'version': '1.0.0',
            'type': 'audit',
            'description': 'Проверяет раскрытие чувствительной информации через robots.txt, .env и другие файлы'
        }

    def run(self) -> List[ScanResult]:
        results = []
        
        # Список чувствительных файлов для проверки
        sensitive_files = [
            'robots.txt',
            '.env',
            '.git/config',
            'backup.zip',
            'config.json',
            'database.sql',
            'wp-config.php',
            'config.php',
            'settings.py',
            'docker-compose.yml',
            'README.md'
        ]
        
        for file_path in sensitive_files:
            url = f"{self.context.target_url.rstrip('/')}/{file_path}"
            
            try:
                response = self.context.session.get(url, timeout=10)
                
                # Если файл существует и доступен
                if response.status_code == 200:
                    severity = self._classify_severity(file_path, response.text)
                    
                    # Создаем сниппет ответа (первые 200 символов)
                    snippet = response.text[:200] + "..." if len(response.text) > 200 else response.text
                    
                    results.append(ScanResult(
                        plugin_name=self.meta()['name'],
                        vulnerability_id=f"SENSITIVE_FILE_{file_path.replace('.', '_').upper()}",
                        severity=severity,
                        url=url,
                        evidence=f"Обнаружен чувствительный файл: {file_path}",
                        response_snippet=snippet
                    ))
                    
                    self.context.log(f"Обнаружен чувствительный файл: {file_path}")
                    
            except requests.RequestException as e:
                self.context.log(f"Ошибка при проверке {url}: {e}")
                continue
        
        return results

    def _classify_severity(self, file_path: str, content: str) -> str:
        """Определяет уровень серьезности на основе типа файла и его содержимого"""
        
        # Файлы с паролями и ключами
        if file_path == '.env':
            sensitive_keywords = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'DATABASE_URL']
            if any(keyword in content.upper() for keyword in sensitive_keywords):
                return "HIGH"
            return "MEDIUM"
        
        # Конфигурационные файлы
        elif file_path in ['config.php', 'wp-config.php', 'settings.py', 'config.json']:
            return "MEDIUM"
        
        # Файлы бэкапов и баз данных
        elif file_path in ['backup.zip', 'database.sql']:
            return "HIGH"
        
        # Git конфиг
        elif file_path == '.git/config':
            return "MEDIUM"
        
        # Robots.txt - обычно низкий риск, но может раскрывать структуру
        elif file_path == 'robots.txt':
            return "LOW"
        
        # Остальные файлы
        else:
            return "LOW"