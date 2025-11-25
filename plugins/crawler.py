# plugins/crawler.py
from core.base_plugin import BasePlugin, ScanResult
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class SimpleCrawler(BasePlugin):
    @classmethod
    def meta(self):
        return {"name": "Link Spider", "type": "discovery", "version": "1.0"}

    def run(self) -> List[ScanResult]:
        target = self.context.target_url
        self.context.log(f"Начинаю обход {target}")
        
        try:
            # Используем общую сессию
            response = self.context.session.get(target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            count = 0
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(target, href)
                    # Фильтруем внешние ссылки, оставляем только внутренние
                    if target in full_url and full_url not in self.context.discovered_urls:
                        self.context.discovered_urls.add(full_url)
                        count += 1
            
            self.context.log(f"Найдено новых ссылок: {count}")
            # Краулер обычно не возвращает уязвимости, он наполняет контекст
            return [] 
            
        except Exception as e:
            self.context.log(f"Ошибка краулера: {e}")
            return []