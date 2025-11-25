import os
import importlib.util
import inspect
from typing import List, Type
from core.base_plugin import BasePlugin, ScanContext

class PluginManager:
    """
    Загружает классы плагинов из файлов в папке plugins.
    """
    def __init__(self, plugin_folder="plugins"):
        self.plugin_folder = plugin_folder
        # Хранит классы, а не их инстансы! (List[Type[BasePlugin]])
        self.loaded_plugin_classes: List[Type[BasePlugin]] = []

    def discover_plugins(self):
        """Сканирует папку и динамически импортирует Python-файлы"""
        if not os.path.exists(self.plugin_folder):
            print(f"[-] Folder not found: {self.plugin_folder}")
            return
            
        for filename in os.listdir(self.plugin_folder):
            if filename.endswith(".py") and not filename.startswith("__"):
                self._load_plugin(filename)
    
    def _load_plugin(self, filename):
        module_name = filename[:-3]
        file_path = os.path.join(self.plugin_folder, filename)
        
        try:
            # Создаем спецификацию и импортируем модуль
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Ищем классы, наследующие BasePlugin (кроме самого BasePlugin)
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                    self.loaded_plugin_classes.append(obj)
                    print(f"[+] Loaded plugin class: {name}")
        except Exception as e:
            print(f"[!] Error loading {filename}: {e}")

    def get_plugin_classes(self) -> List[Type[BasePlugin]]:
        return self.loaded_plugin_classes