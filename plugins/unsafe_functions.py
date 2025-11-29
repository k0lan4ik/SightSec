import os
import re
from typing import List
from core.base_plugin import BasePlugin, ScanContext, ScanResult

class UnsafeFunctionsPlugin(BasePlugin):
    """Whitebox плагин для поиска опасных функций в исходном коде"""
    
    @classmethod
    def meta(cls):
        return {
            'name': 'unsafe_functions',
            'version': '1.0.0',
            'type': 'whitebox',
            'description': 'Ищет использование опасных функций (eval, exec, system и др.) в исходном коде'
        }

    def run(self) -> List[ScanResult]:
        results = []
        source_path = self.context.config.get("local_source_path")
        
        if not source_path or not os.path.exists(source_path):
            self.context.log("Путь к исходному коду не указан или не существует")
            return results

        # Опасные функции по языкам программирования
        dangerous_patterns = {
            'PYTHON': [
                r'eval\s*\([^)]+\)',
                r'exec\s*\([^)]+\)',
                r'os\.system\s*\([^)]+\)',
                r'subprocess\.call\s*\([^)]+\)',
                r'subprocess\.Popen\s*\([^)]+\)',
                r'pickle\.loads\s*\([^)]+\)',
                r'marshal\.loads\s*\([^)]+\)',
                r'__import__\s*\([^)]+\)',
                r'input\s*\([^)]*\)'  # В некоторых контекстах может быть опасно
            ],
            'JAVASCRIPT': [
                r'eval\s*\([^)]+\)',
                r'Function\s*\([^)]+\)',
                r'setTimeout\s*\([^)]+\)',
                r'setInterval\s*\([^)]+\)',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'document\.write\s*\([^)]+\)'
            ],
            'PHP': [
                r'eval\s*\([^)]+\)',
                r'system\s*\([^)]+\)',
                r'exec\s*\([^)]+\)',
                r'passthru\s*\([^)]+\)',
                r'shell_exec\s*\([^)]+\)',
                r'popen\s*\([^)]+\)',
                r'assert\s*\([^)]+\)',
                r'include\s*\([^)]+\$',
                r'require\s*\([^)]+\$'
            ],
            'JAVA': [
                r'Runtime\.exec\s*\([^)]+\)',
                r'ProcessBuilder\s*\([^)]+\)',
                r'ScriptEngineManager.*eval',
                r'unsafe\..*',
                r'Reflection\.'
            ]
        }

        for root, dirs, files in os.walk(source_path):
            # Исключаем некоторые директории
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1].lower()
                
                language = self._detect_language(file_ext, file_path)
                if language in dangerous_patterns:
                    results.extend(self._scan_file(file_path, language, dangerous_patterns[language]))

        return results

    def _detect_language(self, file_ext: str, file_path: str) -> str:
        """Определяет язык программирования по расширению файла"""
        extension_map = {
            '.py': 'PYTHON',
            '.js': 'JAVASCRIPT',
            '.php': 'PHP',
            '.java': 'JAVA',
            '.cpp': 'CPP',
            '.c': 'C',
            '.cs': 'CSHARP',
            '.rb': 'RUBY',
            '.go': 'GO'
        }
        return extension_map.get(file_ext, 'UNKNOWN')

    def _scan_file(self, file_path: str, language: str, patterns: list) -> List[ScanResult]:
        """Сканирует файл на наличие опасных функций"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for pattern in patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Пропускаем закомментированные строки
                            if self._is_commented(line, language):
                                continue
                                
                            function_call = match.group(0)
                            
                            results.append(ScanResult(
                                plugin_name=self.meta()['name'],
                                vulnerability_id=f"UNSAFE_FUNCTION_{language}",
                                severity="MEDIUM",
                                url=file_path,
                                evidence=f"Обнаружена опасная функция: {function_call}",
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
            'JAVASCRIPT': line_trimmed.startswith('//') or line_trimmed.startswith('/*'),
            'PHP': line_trimmed.startswith('//') or line_trimmed.startswith('#') or line_trimmed.startswith('/*'),
            'JAVA': line_trimmed.startswith('//') or line_trimmed.startswith('/*')
        }
        
        return comment_patterns.get(language, False)