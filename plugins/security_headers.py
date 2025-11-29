import requests
from typing import List, Dict
from core.base_plugin import BasePlugin, ScanContext, ScanResult

class SecurityHeadersPlugin(BasePlugin):
    """Плагин для проверки настроек безопасности HTTP-заголовков"""
    
    @classmethod
    def meta(cls):
        return {
            'name': 'security_headers',
            'version': '1.0.0',
            'type': 'audit',
            'description': 'Проверяет наличие и корректность настроек security headers'
        }

    def run(self) -> List[ScanResult]:
        results = []
        
        try:
            response = self.context.session.get(self.context.target_url, timeout=10)
            headers = response.headers
            
            # Проверяем различные security headers
            checks = [
                self._check_hsts(headers),
                self._check_x_content_type_options(headers),
                self._check_x_frame_options(headers),
                self._check_x_xss_protection(headers),
                self._check_content_security_policy(headers),
                self._check_referrer_policy(headers)
            ]
            
            for check_result in checks:
                if check_result:
                    results.append(check_result)
                    
        except requests.RequestException as e:
            self.context.log(f"Ошибка при проверке security headers: {e}")
            
        return results

    def _check_hsts(self, headers: Dict) -> ScanResult:
        """Проверка HTTP Strict Transport Security"""
        if 'strict-transport-security' not in headers:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="MISSING_HSTS_HEADER",
                severity="MEDIUM",
                url=self.context.target_url,
                evidence="Отсутствует HSTS header",
                response_snippet="HSTS не настроен, что может позволить атаки SSL stripping"
            )
        
        hsts_value = headers['strict-transport-security'].lower()
        if 'max-age=0' in hsts_value:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="HSTS_DISABLED",
                severity="MEDIUM",
                url=self.context.target_url,
                evidence="HSTS отключен (max-age=0)",
                response_snippet=f"HSTS header: {headers['strict-transport-security']}"
            )
        
        return None

    def _check_x_content_type_options(self, headers: Dict) -> ScanResult:
        """Проверка X-Content-Type-Options"""
        if 'x-content-type-options' not in headers:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="MISSING_X_CONTENT_TYPE_OPTIONS",
                severity="LOW",
                url=self.context.target_url,
                evidence="Отсутствует X-Content-Type-Options header",
                response_snippet="Отсутствует защита от MIME sniffing"
            )
        
        if headers['x-content-type-options'].lower() != 'nosniff':
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="INVALID_X_CONTENT_TYPE_OPTIONS",
                severity="LOW",
                url=self.context.target_url,
                evidence="Некорректное значение X-Content-Type-Options",
                response_snippet=f"X-Content-Type-Options: {headers['x-content-type-options']}"
            )
        
        return None

    def _check_x_frame_options(self, headers: Dict) -> ScanResult:
        """Проверка X-Frame-Options"""
        if 'x-frame-options' not in headers:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="MISSING_X_FRAME_OPTIONS",
                severity="MEDIUM",
                url=self.context.target_url,
                evidence="Отсутствует X-Frame-Options header",
                response_snippet="Возможна атака clickjacking"
            )
        
        valid_values = ['deny', 'sameorigin']
        if headers['x-frame-options'].lower() not in valid_values:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="INVALID_X_FRAME_OPTIONS",
                severity="MEDIUM",
                url=self.context.target_url,
                evidence="Некорректное значение X-Frame-Options",
                response_snippet=f"X-Frame-Options: {headers['x-frame-options']}"
            )
        
        return None

    def _check_x_xss_protection(self, headers: Dict) -> ScanResult:
        """Проверка X-XSS-Protection"""
        if 'x-xss-protection' not in headers:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="MISSING_X_XSS_PROTECTION",
                severity="LOW",
                url=self.context.target_url,
                evidence="Отсутствует X-XSS-Protection header",
                response_snippet="Отсутствует дополнительная защита от XSS"
            )
        
        return None

    def _check_content_security_policy(self, headers: Dict) -> ScanResult:
        """Проверка Content-Security-Policy"""
        if 'content-security-policy' not in headers:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="MISSING_CSP",
                severity="MEDIUM",
                url=self.context.target_url,
                evidence="Отсутствует Content-Security-Policy header",
                response_snippet="Отсутствует защита от XSS и инъекций контента"
            )
        
        return None

    def _check_referrer_policy(self, headers: Dict) -> ScanResult:
        """Проверка Referrer-Policy"""
        if 'referrer-policy' not in headers:
            return ScanResult(
                plugin_name=self.meta()['name'],
                vulnerability_id="MISSING_REFERRER_POLICY",
                severity="LOW",
                url=self.context.target_url,
                evidence="Отсутствует Referrer-Policy header",
                response_snippet="Возможна утечка данных через Referer header"
            )
        
        return None