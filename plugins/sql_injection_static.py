import os
import re
from typing import List
from core.base_plugin import BasePlugin, ScanContext, ScanResult

class SQLInjectionStaticPlugin(BasePlugin):
    """Whitebox плагин для поиска потенциальных SQL инъекций в исходном коде"""
    
    @classmethod
    def meta(cls):
        return {
            'name': 'sql_injection_static',
            'version': '1.0.0',
            'type': 'whitebox',
            'description': 'Ищет потенциальные SQL инъекции через конкатенацию строк в запросах'
        }

    def run(self) -> List[ScanResult]:
        results = []
        source_path = self.context.config.get("local_source_path")
        
        if not source_path or not os.path.exists(source_path):
            self.context.log("Путь к исходному коду не указан или не существует")
            return results

        # Паттерны для поиска SQL запросов с конкатенацией
        sql_patterns = {
            'PYTHON': [
                r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*\+\s*[^)]+\)',
                r'cursor\.execute\s*\(\s*f["\'][^"\']*\{[^}]+\}',
                r'execute\s*\(\s*["\'][^"\']*\%s[^"\']*["\']\s*\%',
                r'%\([^)]+\)s.*\%.*dict'
            ],
            'PHP': [
                r'mysql_query\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$.+\)',
                r'mysqli_query\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$.+\)',
                r'query\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$.+\)',
                r'prepare\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$.+\)'
            ],
            'JAVA': [
                r'Statement\.executeQuery\s*\(\s*["\'][^"\']*["\']\s*\+\s*[^)]+\)',
                r'executeQuery\s*\(\s*["\'][^"\']*["\']\s*\+\s*[^)]+\)',
                r'createStatement\s*\(\s*\).*executeQuery\s*\(\s*["\'][^"\']*["\']\s*\+\s*'
            ]
        }

        for root, dirs, files in os.walk(source_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1].lower()
                
                language = self._detect_language(file_ext)
                if language in sql_patterns:
                    results.extend(self._scan_file(file_path, language, sql_patterns[language]))

        return results

    def _detect_language(self, file_ext: str) -> str:
        """Определяет язык программирования по расширению файла"""
        extension_map = {
            '.py': 'PYTHON',
            '.php': 'PHP',
            '.java': 'JAVA',
            '.js': 'JAVASCRIPT'
        }
        return extension_map.get(file_ext, 'UNKNOWN')

    def _scan_file(self, file_path: str, language: str, patterns: list) -> List[ScanResult]:
        """Сканирует файл на наличие потенциальных SQL инъекций"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for pattern in patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            if self._is_commented(line, language):
                                continue
                                
                            sql_code = match.group(0)
                            
                            results.append(ScanResult(
                                plugin_name=self.meta()['name'],
                                vulnerability_id=f"POTENTIAL_SQLI_{language}",
                                severity="HIGH",
                                url=file_path,
                                evidence=f"Потенциальная SQL инъекция: {sql_code[:100]}...",
                                response_snippet=f"Строка {line_num}: {line.strip()}"
                            ))
                            
        except Exception as e:
            self.context.log(f"Ошибка чтения файла {file_path}: {e}")
            
        return results

    def _is_commented(self, line: str, language: str) -> bool:
        """Проверяет, является ли строка комментарием"""
        line_trimmed = line.strip()
        
        comment_patterns = {
            'PYTHON': line_trimmed.startswith('#'),
            'PHP': line_trimmed.startswith('//') or line_trimmed.startswith('#') or line_trimmed.startswith('/*'),
            'JAVA': line_trimmed.startswith('//') or line_trimmed.startswith('/*')
        }
        
        return comment_patterns.get(language, False)
