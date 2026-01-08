"""
Configuration Manager
Loads and manages application settings
"""

import yaml
from pathlib import Path
from typing import Any, Dict
import logging

logger = logging.getLogger(__name__)


class Settings:
    """Application settings manager"""
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.load()
        
    def load(self):
        """Load configuration from YAML file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config = yaml.safe_load(f) or {}
                logger.info(f"Configuration loaded from {self.config_path}")
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
                self.config = self._get_defaults()
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self.config = self._get_defaults()
            
    def save(self):
        """Save configuration to YAML file"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
                
        return value if value is not None else default
        
    def set(self, key: str, value: Any):
        """Set configuration value by key (supports dot notation)"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        
    @property
    def default_interface(self) -> str:
        """Get default network interface"""
        return self.get('capture.default_interface', 'auto')
        
    @property
    def buffer_size(self) -> int:
        """Get capture buffer size"""
        return self.get('capture.buffer_size', 65536)
        
    @property
    def promiscuous_mode(self) -> bool:
        """Get promiscuous mode setting"""
        return self.get('capture.promiscuous_mode', True)
        
    @property
    def update_interval(self) -> int:
        """Get UI update interval in milliseconds"""
        return self.get('performance.update_interval_ms', 100)
        
    @property
    def max_packets_memory(self) -> int:
        """Get maximum packets to keep in memory"""
        return self.get('performance.max_packets_memory', 100000)
        
    @property
    def theme(self) -> str:
        """Get UI theme"""
        return self.get('ui.theme', 'dark')
        
    @property
    def theme_colors(self) -> Dict[str, str]:
        """Get theme colors"""
        theme = self.theme
        return self.get(f'theme.{theme}', {})
        
    @property
    def filter_presets(self) -> list:
        """Get filter presets"""
        return self.get('filter_presets', [])
        
    @property
    def anomaly_detection_enabled(self) -> bool:
        """Check if anomaly detection is enabled"""
        return self.get('anomaly_detection.enabled', True)
        
    @property
    def api_enabled(self) -> bool:
        """Check if API is enabled"""
        return self.get('api.enabled', False)
        
    @property
    def api_port(self) -> int:
        """Get API port"""
        return self.get('api.port', 8080)
        
    @property
    def plugins_enabled(self) -> bool:
        """Check if plugins are enabled"""
        return self.get('plugins.enabled', True)
        
    @property
    def auto_save_enabled(self) -> bool:
        """Check if auto-save is enabled"""
        return self.get('session.auto_save', True)
        
    @property
    def auto_save_interval(self) -> int:
        """Get auto-save interval in seconds"""
        return self.get('session.auto_save_interval', 300)
        
    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'capture': {
                'default_interface': 'auto',
                'buffer_size': 65536,
                'promiscuous_mode': True,
            },
            'performance': {
                'max_packets_memory': 100000,
                'update_interval_ms': 100,
            },
            'ui': {
                'theme': 'dark',
                'window_width': 1600,
                'window_height': 900,
            },
            'theme': {
                'dark': {
                    'background': '#1e1e1e',
                    'foreground': '#d4d4d4',
                    'accent': '#007acc',
                }
            }
        }


# Global settings instance
_settings_instance = None


def get_settings(config_path: str = "config/settings.yaml") -> Settings:
    """Get global settings instance"""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings(config_path)
    return _settings_instance
