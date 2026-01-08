"""
Statistics Panel
Displays real-time network statistics
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QGroupBox, QGridLayout)
from PyQt6.QtCore import Qt
from typing import Dict, Any


class StatisticsPanel(QWidget):
    """Statistics display panel"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        
        # Overview section
        overview_group = QGroupBox("Overview")
        overview_layout = QGridLayout()
        
        self.total_packets_label = QLabel("0")
        self.total_bytes_label = QLabel("0 B")
        self.pps_label = QLabel("0 pps")
        self.bps_label = QLabel("0 bps")
        self.duration_label = QLabel("0:00:00")
        
        overview_layout.addWidget(QLabel("Total Packets:"), 0, 0)
        overview_layout.addWidget(self.total_packets_label, 0, 1)
        overview_layout.addWidget(QLabel("Total Bytes:"), 0, 2)
        overview_layout.addWidget(self.total_bytes_label, 0, 3)
        
        overview_layout.addWidget(QLabel("Packets/sec:"), 1, 0)
        overview_layout.addWidget(self.pps_label, 1, 1)
        overview_layout.addWidget(QLabel("Bytes/sec:"), 1, 2)
        overview_layout.addWidget(self.bps_label, 1, 3)
        
        overview_layout.addWidget(QLabel("Duration:"), 2, 0)
        overview_layout.addWidget(self.duration_label, 2, 1)
        
        overview_group.setLayout(overview_layout)
        layout.addWidget(overview_group)
        
        # Protocol distribution
        protocol_group = QGroupBox("Protocol Distribution")
        protocol_layout = QVBoxLayout()
        
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(3)
        self.protocol_table.setHorizontalHeaderLabels(['Protocol', 'Packets', 'Bytes'])
        self.protocol_table.setMaximumHeight(200)
        
        protocol_layout.addWidget(self.protocol_table)
        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)
        
        # Top IPs
        top_ips_group = QGroupBox("Top IP Addresses")
        top_ips_layout = QVBoxLayout()
        
        self.top_ips_table = QTableWidget()
        self.top_ips_table.setColumnCount(3)
        self.top_ips_table.setHorizontalHeaderLabels(['IP Address', 'Packets', 'Bytes'])
        self.top_ips_table.setMaximumHeight(200)
        
        top_ips_layout.addWidget(self.top_ips_table)
        top_ips_group.setLayout(top_ips_layout)
        layout.addWidget(top_ips_group)
        
        # Top Ports
        top_ports_group = QGroupBox("Top Ports")
        top_ports_layout = QVBoxLayout()
        
        self.top_ports_table = QTableWidget()
        self.top_ports_table.setColumnCount(3)
        self.top_ports_table.setHorizontalHeaderLabels(['Port', 'Packets', 'Bytes'])
        self.top_ports_table.setMaximumHeight(200)
        
        top_ports_layout.addWidget(self.top_ports_table)
        top_ports_group.setLayout(top_ports_layout)
        layout.addWidget(top_ports_group)
        
        layout.addStretch()
        
    def update_statistics(self, stats: Dict[str, Any]):
        """Update statistics display"""
        # Update overview
        self.total_packets_label.setText(str(stats.get('total_packets', 0)))
        self.total_bytes_label.setText(self.format_bytes(stats.get('total_bytes', 0)))
        self.pps_label.setText(f"{stats.get('pps', 0):.0f} pps")
        self.bps_label.setText(f"{self.format_bytes(stats.get('bps', 0))}/s")
        
        duration = stats.get('duration', 0)
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.duration_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        # Update protocol distribution
        protocols = stats.get('packets_per_protocol', {})
        self.update_table(self.protocol_table, protocols, stats.get('bytes_per_protocol', {}))
        
        # Update top IPs
        top_ips = stats.get('top_ips', [])
        self.update_top_table(self.top_ips_table, top_ips)
        
        # Update top ports
        top_ports = stats.get('top_ports', [])
        self.update_top_table(self.top_ports_table, top_ports)
        
    def update_table(self, table: QTableWidget, packets_dict: Dict, bytes_dict: Dict):
        """Update protocol table"""
        table.setRowCount(0)
        
        for protocol, packet_count in sorted(packets_dict.items(), 
                                            key=lambda x: x[1], reverse=True):
            row = table.rowCount()
            table.insertRow(row)
            
            table.setItem(row, 0, QTableWidgetItem(protocol))
            table.setItem(row, 1, QTableWidgetItem(str(packet_count)))
            table.setItem(row, 2, QTableWidgetItem(self.format_bytes(bytes_dict.get(protocol, 0))))
            
    def update_top_table(self, table: QTableWidget, data: list):
        """Update top IPs/ports table"""
        table.setRowCount(0)
        
        for item, count in data[:10]:
            row = table.rowCount()
            table.insertRow(row)
            
            table.setItem(row, 0, QTableWidgetItem(str(item)))
            table.setItem(row, 1, QTableWidgetItem(str(count)))
            table.setItem(row, 2, QTableWidgetItem(self.format_bytes(count)))
            
    def format_bytes(self, bytes_count: float) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"
