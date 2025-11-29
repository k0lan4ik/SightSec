import os
import re
from typing import List
from core.base_plugin import BasePlugin, ScanContext, ScanResult

class HardcodedSecretsPlugin(BasePlugin):
    """Whitebox плагин для поиска жестко закодированных секретов в исходном коде"""
    
    @classmethod
    def meta(cls):
        return {
            'name': 'hardcoded_secrets',
            'version': '1.0.0',
            'type': 'whitebox',
            'description': 'Ищет жестко закодированные пароли, API ключи и другие секреты в исходном коде'
        }

    def run(self) -> List[ScanResult]:
        results = []
        source_path = self.context.config.get("local_source_path")
        
        if not source_path or not os.path.exists(source_path):
            self.context.log("Путь к исходному коду не указан или не существует")
            return results

        # Паттерны для поиска секретов
        patterns = {
            'API_KEY': r'api[_-]?key\s*=\s*["\']([^"\']{10,100})["\']',
            'PASSWORD': r'password\s*=\s*["\']([^"\']{4,50})["\']',
            'SECRET_KEY': r'secret[_-]?key\s*=\s*["\']([^"\']{10,100})["\']',
            'DATABASE_URL': r'(mysql|postgresql|mongodb)://[^"\'\s]+',
            'PRIVATE_KEY': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'AWS_ACCESS_KEY': r'AKIA[0-9A-Z]{16}',
            'JWT_TOKEN': r'eyJhbGciOiJ[^"\']{50,500}'
        }

        for root, dirs, files in os.walk(source_path):
            # Исключаем некоторые директории
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            
            for file in files:
                if self._is_code_file(file):
                    file_path = os.path.join(root, file)
                    results.extend(self._scan_file(file_path, patterns))

        return results

    def _is_code_file(self, filename: str) -> bool:
        """Определяет, является ли файл исходным кодом"""
        code_extensions = ['.py', '.js', '.java', '.php', '.rb', '.go', '.cpp', '.c', '.h', 
                          '.cs', '.html', '.xml', '.json', '.yml', '.yaml', '.env', '.config']
        return any(filename.endswith(ext) for ext in code_extensions)

    def _scan_file(self, file_path: str, patterns: dict) -> List[ScanResult]:
        """Сканирует один файл на наличие секретов"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for secret_type, pattern in patterns.items():
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Пропускаем короткие значения и комментарии
                            if self._is_false_positive(line):
                                continue
                                
                            secret_value = match.group(1) if match.groups() else match.group(0)
                            # Маскируем часть секрета для вывода
                            masked_secret = self._mask_secret(secret_value)
                            
                            results.append(ScanResult(
                                plugin_name=self.meta()['name'],
                                vulnerability_id=f"HARDCODED_{secret_type}",
                                severity="HIGH",
                                url=file_path,
                                evidence=f"Обнаружен {secret_type}: {masked_secret}",
                                response_snippet=f"Строка {line_num}: {line.strip()}"
                            ))
                            
        except Exception as e:
            self.context.log(f"Ошибка чтения файла {file_path}: {e}")
            
        return results

    def _is_false_positive(self, line: str) -> bool:
        """Проверяет, является ли найденное значение ложным срабатыванием"""
        false_positives = [
            'example', 'test', 'demo', 'placeholder', 'changeme',
            'your_', 'fake_', 'dummy_', 'sample_'
        ]
        line_lower = line.lower()
        return any(fp in line_lower for fp in false_positives) or line.strip().startswith('#') or line.strip().startswith('//')

    def _mask_secret(self, secret: str) -> str:
        """Маскирует секрет для безопасного вывода"""
        if len(secret) <= 8:
            return "***"
        return secret[:4] + "***" + secret[-4:]
