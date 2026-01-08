"""
Filters Panel
UI for creating and managing packet filters
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QComboBox, QListWidget,
                             QGroupBox, QCheckBox)
from PyQt6.QtCore import pyqtSignal
from typing import Dict, Any


class FiltersPanel(QWidget):
    """Filter management panel"""
    
    filter_applied = pyqtSignal(dict)
    
    def __init__(self, filter_engine):
        super().__init__()
        self.filter_engine = filter_engine
        self.setup_ui()
        
    def setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        
        # Quick filters
        quick_group = QGroupBox("Quick Filters")
        quick_layout = QVBoxLayout()
        
        quick_buttons = [
            ("HTTP/HTTPS", "http"),
            ("DNS", "dns"),
            ("Local Network", "local"),
            ("External Traffic", "external"),
            ("Suspicious Ports", "suspicious"),
            ("Encrypted Traffic", "encrypted")
        ]
        
        for label, filter_type in quick_buttons:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, ft=filter_type: self.apply_quick_filter(ft))
            quick_layout.addWidget(btn)
            
        quick_group.setLayout(quick_layout)
        layout.addWidget(quick_group)
        
        # IP Filter
        ip_group = QGroupBox("IP Filter")
        ip_layout = QVBoxLayout()
        
        ip_input_layout = QHBoxLayout()
        ip_input_layout.addWidget(QLabel("IP Range:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.0/24")
        ip_input_layout.addWidget(self.ip_input)
        
        self.ip_direction = QComboBox()
        self.ip_direction.addItems(["Both", "Source", "Destination"])
        ip_input_layout.addWidget(self.ip_direction)
        
        ip_btn = QPushButton("Apply")
        ip_btn.clicked.connect(self.apply_ip_filter)
        ip_input_layout.addWidget(ip_btn)
        
        ip_layout.addLayout(ip_input_layout)
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)
        
        # Port Filter
        port_group = QGroupBox("Port Filter")
        port_layout = QVBoxLayout()
        
        port_input_layout = QHBoxLayout()
        port_input_layout.addWidget(QLabel("Ports:"))
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("e.g., 80,443,8080")
        port_input_layout.addWidget(self.port_input)
        
        port_btn = QPushButton("Apply")
        port_btn.clicked.connect(self.apply_port_filter)
        port_input_layout.addWidget(port_btn)
        
        port_layout.addLayout(port_input_layout)
        port_group.setLayout(port_layout)
        layout.addWidget(port_group)
        
        # Protocol Filter
        protocol_group = QGroupBox("Protocol Filter")
        protocol_layout = QVBoxLayout()
        
        self.protocol_checks = {}
        protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'ARP']
        
        for protocol in protocols:
            check = QCheckBox(protocol)
            self.protocol_checks[protocol] = check
            protocol_layout.addWidget(check)
            
        protocol_btn = QPushButton("Apply")
        protocol_btn.clicked.connect(self.apply_protocol_filter)
        protocol_layout.addWidget(protocol_btn)
        
        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)
        
        # Active Filters
        active_group = QGroupBox("Active Filters")
        active_layout = QVBoxLayout()
        
        self.active_filters_list = QListWidget()
        active_layout.addWidget(self.active_filters_list)
        
        clear_btn = QPushButton("Clear All Filters")
        clear_btn.clicked.connect(self.clear_all_filters)
        active_layout.addWidget(clear_btn)
        
        active_group.setLayout(active_layout)
        layout.addWidget(active_group)
        
        layout.addStretch()
        
    def apply_quick_filter(self, filter_type: str):
        """Apply quick filter"""
        from backend.core.filter_engine import QuickFilters
        
        self.filter_engine.clear_filters()
        
        if filter_type == 'http':
            self.filter_engine.add_filter(QuickFilters.http_https(), "HTTP/HTTPS")
        elif filter_type == 'dns':
            self.filter_engine.add_filter(QuickFilters.dns(), "DNS")
        elif filter_type == 'local':
            self.filter_engine.add_filter(QuickFilters.local_network(), "Local Network")
        elif filter_type == 'external':
            self.filter_engine.add_filter(QuickFilters.external_traffic(), "External Traffic")
        elif filter_type == 'suspicious':
            self.filter_engine.add_filter(QuickFilters.suspicious_ports(), "Suspicious Ports")
        elif filter_type == 'encrypted':
            self.filter_engine.add_filter(QuickFilters.encrypted_traffic(), "Encrypted Traffic")
            
        self.update_active_filters()
        self.filter_applied.emit({'type': 'quick', 'filter': filter_type})
        
    def apply_ip_filter(self):
        """Apply IP filter"""
        ip_range = self.ip_input.text().strip()
        if not ip_range:
            return
            
        direction = self.ip_direction.currentText().lower()
        if direction == "both":
            direction = "both"
        elif direction == "source":
            direction = "src"
        else:
            direction = "dst"
            
        filter_func = self.filter_engine.create_ip_filter(ip_range, direction)
        self.filter_engine.add_filter(filter_func, f"IP: {ip_range} ({direction})")
        
        self.update_active_filters()
        self.filter_applied.emit({'type': 'ip', 'range': ip_range, 'direction': direction})
        
    def apply_port_filter(self):
        """Apply port filter"""
        ports_str = self.port_input.text().strip()
        if not ports_str:
            return
            
        try:
            ports = [int(p.strip()) for p in ports_str.split(',')]
            filter_func = self.filter_engine.create_port_filter(ports)
            self.filter_engine.add_filter(filter_func, f"Ports: {ports_str}")
            
            self.update_active_filters()
            self.filter_applied.emit({'type': 'port', 'ports': ports})
        except ValueError:
            pass
            
    def apply_protocol_filter(self):
        """Apply protocol filter"""
        selected_protocols = [proto for proto, check in self.protocol_checks.items() 
                            if check.isChecked()]
        
        if not selected_protocols:
            return
            
        filter_func = self.filter_engine.create_protocol_filter(selected_protocols)
        self.filter_engine.add_filter(filter_func, f"Protocols: {', '.join(selected_protocols)}")
        
        self.update_active_filters()
        self.filter_applied.emit({'type': 'protocol', 'protocols': selected_protocols})
        
    def clear_all_filters(self):
        """Clear all filters"""
        self.filter_engine.clear_filters()
        self.update_active_filters()
        self.filter_applied.emit({'type': 'clear'})
        
    def update_active_filters(self):
        """Update active filters list"""
        self.active_filters_list.clear()
        for filter_dict in self.filter_engine.active_filters:
            self.active_filters_list.addItem(filter_dict['name'])
