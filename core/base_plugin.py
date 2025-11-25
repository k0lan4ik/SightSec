from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any
import requests
from urllib.parse import urljoin

# --- 1.1. Структуры данных ---

@dataclass
class FormInput:
    """Один элемент формы (input, textarea, select)"""
    name: str
    type: str
    value: str

@dataclass
class TargetForm:
    """Данные HTML-формы, найденной краулером"""
    action_url: str     # Относительный или абсолютный URL отправки
    method: str         # GET или POST
    inputs: List[FormInput]
    
    def get_full_url(self, base_url: str) -> str:
        """Возвращает полный URL для отправки данных"""
        return urljoin(base_url, self.action_url)

@dataclass
class ScanResult:
    """Стандартизированный отчет об уязвимости"""
    plugin_name: str
    vulnerability_id: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    url: str
    evidence: str          # Доказательство (пейлоад, скриншот и т.д.)
    response_snippet: str  # Часть ответа сервера

@dataclass
class ScanContext:
    """Общая память и состояние для всех плагинов в рамках одного сканирования"""
    target_url: str
    session: requests.Session = field(default_factory=requests.Session) # Общая HTTP-сессия (куки, заголовки)
    discovered_urls: set = field(default_factory=set) # URL для проверки
    discovered_forms: List[TargetForm] = field(default_factory=list) # Формы для фаззинга
    config: Dict[str, Any] = field(default_factory=dict) # Конфиг (white-box path, таймауты)
    
    def log(self, message: str):
        """Простой логгер для консоли (в реальном приложении - QWidget/DB)"""
        print(f"[CONTEXT] {message}")


# --- 1.2. Базовый Класс Плагина (Контракт) ---

class BasePlugin(ABC):
    """Абстрактный класс, от которого должны наследоваться все проверки"""
    def __init__(self, context: ScanContext):
        self.context = context

    @classmethod
    @abstractmethod
    def meta(self) -> dict:
        """Метаданные: name, version, type ('discovery', 'audit', 'whitebox')"""
        pass

    def setup(self):
        """Опционально: подготовка ресурсов перед запуском"""
        pass

    @abstractmethod
    def run(self) -> List[ScanResult]:
        """Обязательный метод, содержащий основную логику проверки"""
        pass

    def teardown(self):
        """Опционально: очистка ресурсов после запуска"""
        pass