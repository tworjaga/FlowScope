"""
Dark Theme
Professional dark theme for FlowScope
"""

from typing import Dict


class DarkTheme:
    """Dark theme stylesheet generator"""
    
    def __init__(self, settings=None):
        self.settings = settings
        self.colors = self._get_colors()
        
    def _get_colors(self) -> Dict[str, str]:
        """Get theme colors"""
        if self.settings:
            return self.settings.theme_colors
        
        # Default dark theme colors
        return {
            'background': '#1e1e1e',
            'foreground': '#d4d4d4',
            'accent': '#007acc',
            'success': '#4ec9b0',
            'warning': '#ce9178',
            'error': '#f48771',
            'border': '#3e3e3e',
            'selection': '#264f78',
            'hover': '#2a2d2e',
            
            # Protocol colors
            'tcp': '#569cd6',
            'udp': '#4ec9b0',
            'icmp': '#c586c0',
            'dns': '#dcdcaa',
            'http': '#ce9178',
            'https': '#4fc1ff',
            'arp': '#b5cea8',
            'dhcp': '#9cdcfe',
        }
        
    def get_stylesheet(self) -> str:
        """Generate complete stylesheet"""
        c = self.colors
        
        return f"""
        /* Main Window */
        QMainWindow {{
            background-color: {c['background']};
            color: {c['foreground']};
        }}
        
        /* Menu Bar */
        QMenuBar {{
            background-color: {c['background']};
            color: {c['foreground']};
            border-bottom: 1px solid {c['border']};
            padding: 2px;
        }}
        
        QMenuBar::item {{
            background-color: transparent;
            padding: 4px 12px;
        }}
        
        QMenuBar::item:selected {{
            background-color: {c['hover']};
        }}
        
        QMenuBar::item:pressed {{
            background-color: {c['accent']};
        }}
        
        /* Menu */
        QMenu {{
            background-color: {c['background']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
        }}
        
        QMenu::item {{
            padding: 5px 25px 5px 20px;
        }}
        
        QMenu::item:selected {{
            background-color: {c['selection']};
        }}
        
        QMenu::separator {{
            height: 1px;
            background-color: {c['border']};
            margin: 5px 0px;
        }}
        
        /* Toolbar */
        QToolBar {{
            background-color: {c['background']};
            border-bottom: 1px solid {c['border']};
            spacing: 5px;
            padding: 5px;
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {c['background']};
            color: {c['foreground']};
            border-top: 1px solid {c['border']};
        }}
        
        QStatusBar::item {{
            border: none;
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {c['hover']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
            border-radius: 3px;
            padding: 5px 15px;
            min-width: 60px;
        }}
        
        QPushButton:hover {{
            background-color: {c['accent']};
            border-color: {c['accent']};
        }}
        
        QPushButton:pressed {{
            background-color: {c['selection']};
        }}
        
        QPushButton:disabled {{
            background-color: {c['background']};
            color: #666666;
            border-color: {c['border']};
        }}
        
        /* Tables */
        QTableWidget {{
            background-color: {c['background']};
            color: {c['foreground']};
            gridline-color: {c['border']};
            border: 1px solid {c['border']};
            selection-background-color: {c['selection']};
        }}
        
        QTableWidget::item {{
            padding: 5px;
        }}
        
        QTableWidget::item:selected {{
            background-color: {c['selection']};
        }}
        
        QHeaderView::section {{
            background-color: {c['hover']};
            color: {c['foreground']};
            padding: 5px;
            border: 1px solid {c['border']};
            font-weight: bold;
        }}
        
        /* Tab Widget */
        QTabWidget::pane {{
            border: 1px solid {c['border']};
            background-color: {c['background']};
        }}
        
        QTabBar::tab {{
            background-color: {c['hover']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
            border-bottom: none;
            padding: 8px 20px;
            margin-right: 2px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {c['background']};
            border-bottom: 2px solid {c['accent']};
        }}
        
        QTabBar::tab:hover {{
            background-color: {c['selection']};
        }}
        
        /* Scroll Bars */
        QScrollBar:vertical {{
            background-color: {c['background']};
            width: 12px;
            border: none;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {c['hover']};
            min-height: 20px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {c['accent']};
        }}
        
        QScrollBar:horizontal {{
            background-color: {c['background']};
            height: 12px;
            border: none;
        }}
        
        QScrollBar::handle:horizontal {{
            background-color: {c['hover']};
            min-width: 20px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:horizontal:hover {{
            background-color: {c['accent']};
        }}
        
        QScrollBar::add-line, QScrollBar::sub-line {{
            border: none;
            background: none;
        }}
        
        /* Line Edit */
        QLineEdit {{
            background-color: {c['hover']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
            border-radius: 3px;
            padding: 5px;
        }}
        
        QLineEdit:focus {{
            border-color: {c['accent']};
        }}
        
        /* Combo Box */
        QComboBox {{
            background-color: {c['hover']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
            border-radius: 3px;
            padding: 5px;
        }}
        
        QComboBox:hover {{
            border-color: {c['accent']};
        }}
        
        QComboBox::drop-down {{
            border: none;
        }}
        
        QComboBox QAbstractItemView {{
            background-color: {c['background']};
            color: {c['foreground']};
            selection-background-color: {c['selection']};
            border: 1px solid {c['border']};
        }}
        
        /* Spin Box */
        QSpinBox, QDoubleSpinBox {{
            background-color: {c['hover']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
            border-radius: 3px;
            padding: 5px;
        }}
        
        /* Check Box */
        QCheckBox {{
            color: {c['foreground']};
            spacing: 5px;
        }}
        
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border: 1px solid {c['border']};
            border-radius: 3px;
            background-color: {c['hover']};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {c['accent']};
            border-color: {c['accent']};
        }}
        
        /* Radio Button */
        QRadioButton {{
            color: {c['foreground']};
            spacing: 5px;
        }}
        
        QRadioButton::indicator {{
            width: 18px;
            height: 18px;
            border: 1px solid {c['border']};
            border-radius: 9px;
            background-color: {c['hover']};
        }}
        
        QRadioButton::indicator:checked {{
            background-color: {c['accent']};
            border-color: {c['accent']};
        }}
        
        /* Group Box */
        QGroupBox {{
            color: {c['foreground']};
            border: 1px solid {c['border']};
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 5px;
            color: {c['accent']};
        }}
        
        /* Progress Bar */
        QProgressBar {{
            background-color: {c['hover']};
            border: 1px solid {c['border']};
            border-radius: 3px;
            text-align: center;
            color: {c['foreground']};
        }}
        
        QProgressBar::chunk {{
            background-color: {c['accent']};
            border-radius: 2px;
        }}
        
        /* Splitter */
        QSplitter::handle {{
            background-color: {c['border']};
        }}
        
        QSplitter::handle:hover {{
            background-color: {c['accent']};
        }}
        
        /* Dock Widget */
        QDockWidget {{
            color: {c['foreground']};
            titlebar-close-icon: url(close.png);
            titlebar-normal-icon: url(float.png);
        }}
        
        QDockWidget::title {{
            background-color: {c['hover']};
            padding: 5px;
            border: 1px solid {c['border']};
        }}
        
        /* Labels */
        QLabel {{
            color: {c['foreground']};
        }}
        
        /* Tool Tip */
        QToolTip {{
            background-color: {c['hover']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
            padding: 5px;
        }}
        
        /* List Widget */
        QListWidget {{
            background-color: {c['background']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
        }}
        
        QListWidget::item:selected {{
            background-color: {c['selection']};
        }}
        
        QListWidget::item:hover {{
            background-color: {c['hover']};
        }}
        
        /* Tree Widget */
        QTreeWidget {{
            background-color: {c['background']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
        }}
        
        QTreeWidget::item:selected {{
            background-color: {c['selection']};
        }}
        
        QTreeWidget::item:hover {{
            background-color: {c['hover']};
        }}
        
        /* Text Edit */
        QTextEdit, QPlainTextEdit {{
            background-color: {c['background']};
            color: {c['foreground']};
            border: 1px solid {c['border']};
            selection-background-color: {c['selection']};
        }}
        
        /* Slider */
        QSlider::groove:horizontal {{
            background-color: {c['hover']};
            height: 6px;
            border-radius: 3px;
        }}
        
        QSlider::handle:horizontal {{
            background-color: {c['accent']};
            width: 16px;
            margin: -5px 0;
            border-radius: 8px;
        }}
        
        /* Dialog */
        QDialog {{
            background-color: {c['background']};
            color: {c['foreground']};
        }}
        
        /* Message Box */
        QMessageBox {{
            background-color: {c['background']};
            color: {c['foreground']};
        }}
        """
        
    def get_protocol_color(self, protocol: str) -> str:
        """Get color for specific protocol"""
        protocol_lower = protocol.lower()
        return self.colors.get(protocol_lower, self.colors['foreground'])
