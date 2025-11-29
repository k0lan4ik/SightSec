import os
import json
import importlib.util
import inspect
from typing import List, Type
from core.base_plugin import BasePlugin

class PluginManager:
    """
    Загружает плагины и управляет списком активных плагинов через JSON-конфиг.
    """
    def __init__(self, plugin_folder="plugins", config_file="plugins_config.json"):
        self.plugin_folder = plugin_folder
        self.config_file = config_file
        self.loaded_plugin_classes: List[Type[BasePlugin]] = []
        self.enabled_plugins: List[str] = [] # Хранит имена (meta['name']) активных плагинов

    def discover_plugins(self):
        """Сканирует папку и загружает классы, затем загружает конфиг выбора."""
        # 1. Загрузка кода плагинов
        if not os.path.exists(self.plugin_folder):
            print(f"[-] Folder not found: {self.plugin_folder}")
            return
            
        for filename in os.listdir(self.plugin_folder):
            if filename.endswith(".py") and not filename.startswith("__"):
                self._load_plugin(filename)
        
        # 2. Загрузка выбора пользователя из JSON
        self._load_config()

    def _load_plugin(self, filename):
        module_name = filename[:-3]
        file_path = os.path.join(self.plugin_folder, filename)
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                    # Проверяем, что класс еще не загружен
                    if obj not in self.loaded_plugin_classes:
                        self.loaded_plugin_classes.append(obj)
        except Exception as e:
            print(f"[!] Error loading {filename}: {e}")

    # --- Работа с конфигом (JSON) ---

    def _load_config(self):
        """Загружает список включенных плагинов из файла."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.enabled_plugins = data.get("enabled_plugins", [])
            except Exception as e:
                print(f"[!] Error reading config: {e}")
        else:
            # Если конфига нет, включаем все плагины по умолчанию
            self.enabled_plugins = [cls.meta()['name'] for cls in self.loaded_plugin_classes]
            self._save_config()

    def _save_config(self):
        """Сохраняет текущий список включенных плагинов в файл."""
        data = {"enabled_plugins": self.enabled_plugins}
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def toggle_plugin(self, plugin_name: str, enable: bool):
        """Включает или отключает плагин и обновляет JSON."""
        # Проверяем, существует ли такой плагин вообще
        available_names = [cls.meta()['name'] for cls in self.loaded_plugin_classes]
        if plugin_name not in available_names:
            print(f"[!] Plugin '{plugin_name}' not found installed.")
            return

        if enable and plugin_name not in self.enabled_plugins:
            self.enabled_plugins.append(plugin_name)
            print(f"[+] Plugin '{plugin_name}' enabled.")
        elif not enable and plugin_name in self.enabled_plugins:
            self.enabled_plugins.remove(plugin_name)
            print(f"[-] Plugin '{plugin_name}' disabled.")
        
        self._save_config()

    def get_plugin_classes(self, active_only=True) -> List[Type[BasePlugin]]:
        """Возвращает список классов. Если active_only=True, то только включенные."""
        if not active_only:
            return self.loaded_plugin_classes
        
        return [
            cls for cls in self.loaded_plugin_classes 
            if cls.meta()['name'] in self.enabled_plugins
        ]