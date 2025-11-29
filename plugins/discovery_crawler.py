import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.base_plugin import BasePlugin, ScanResult, TargetForm, FormInput

class SimpleCrawler(BasePlugin):
    @classmethod
    def meta(cls) -> dict:
        return {
            "name": "Basic Crawler",
            "version": "1.0",
            "type": "discovery" # Важно: запускается первым
        }

    def run(self):
        start_url = self.context.target_url
        domain = urlparse(start_url).netloc
        visited = set()
        queue = [start_url]
        
        self.context.log(f"Crawler started on {start_url}")

        while queue:
            url = queue.pop(0)
            if url in visited:
                continue
            
            try:
                # Используем сессию из контекста
                res = self.context.session.get(url, timeout=5)
                visited.add(url)
                self.context.discovered_urls.add(url)
                
                if res.headers.get('Content-Type', '').startswith('text/html'):
                    soup = BeautifulSoup(res.text, 'html.parser')
                    
                    # 1. Поиск новых ссылок
                    for a_tag in soup.find_all('a', href=True):
                        link = urljoin(url, a_tag['href'])
                        if urlparse(link).netloc == domain and link not in visited:
                            queue.append(link)

                    # 2. Поиск форм (для фаззинга)
                    for form in soup.find_all('form'):
                        action = form.get('action') or url
                        method = form.get('method', 'GET').upper()
                        inputs = []
                        for inp in form.find_all(['input', 'textarea']):
                            inputs.append(FormInput(
                                name=inp.get('name', ''),
                                type=inp.get('type', 'text'),
                                value=inp.get('value', '')
                            ))
                        
                        target_form = TargetForm(action, method, inputs)
                        self.context.discovered_forms.append(target_form)
                        
            except Exception as e:
                self.context.log(f"Error crawling {url}: {e}")
        
        return [] # Discovery плагины обычно не возвращают уязвимости, а наполняют контекст