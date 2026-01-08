"""
Packet Table Widget
Displays captured packets in a table view
"""

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QMenu
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush
from datetime import datetime
from typing import Dict, Any


class PacketTableWidget(QTableWidget):
    """Table widget for displaying packets"""
    
    packet_selected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.setup_ui()
        
    def setup_ui(self):
        """Setup table UI"""
        # Define columns
        self.columns = [
            'No.', 'Time', 'Source', 'Destination', 
            'Protocol', 'Length', 'Info'
        ]
        
        self.setColumnCount(len(self.columns))
        self.setHorizontalHeaderLabels(self.columns)
        
        # Configure table
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        
        # Resize columns
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        
        # Context menu
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        
        # Selection changed
        self.itemSelectionChanged.connect(self.on_selection_changed)
        
    def add_packet(self, packet_info: Dict[str, Any]):
        """Add packet to table"""
        self.packets.append(packet_info)
        
        row = self.rowCount()
        self.insertRow(row)
        
        # Packet number
        self.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        
        # Timestamp
        timestamp = packet_info.get('timestamp', datetime.now())
        time_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
        self.setItem(row, 1, QTableWidgetItem(time_str))
        
        # Source
        src = packet_info.get('src_ip', '')
        src_port = packet_info.get('src_port')
        if src_port:
            src = f"{src}:{src_port}"
        self.setItem(row, 2, QTableWidgetItem(src))
        
        # Destination
        dst = packet_info.get('dst_ip', '')
        dst_port = packet_info.get('dst_port')
        if dst_port:
            dst = f"{dst}:{dst_port}"
        self.setItem(row, 3, QTableWidgetItem(dst))
        
        # Protocol
        protocol = packet_info.get('protocol', 'Unknown')
        protocol_item = QTableWidgetItem(protocol)
        
        # Color code by protocol
        color = self.get_protocol_color(protocol)
        protocol_item.setForeground(QBrush(color))
        self.setItem(row, 4, protocol_item)
        
        # Length
        length = packet_info.get('size', 0)
        self.setItem(row, 5, QTableWidgetItem(str(length)))
        
        # Info
        info = packet_info.get('info', '')
        self.setItem(row, 6, QTableWidgetItem(info))
        
        # Auto-scroll to bottom
        self.scrollToBottom()
        
    def get_protocol_color(self, protocol: str) -> QColor:
        """Get color for protocol"""
        colors = {
            'TCP': QColor('#569cd6'),
            'UDP': QColor('#4ec9b0'),
            'ICMP': QColor('#c586c0'),
            'DNS': QColor('#dcdcaa'),
            'HTTP': QColor('#ce9178'),
            'HTTPS': QColor('#4fc1ff'),
            'ARP': QColor('#b5cea8'),
            'DHCP': QColor('#9cdcfe'),
        }
        return colors.get(protocol, QColor('#d4d4d4'))
        
    def on_selection_changed(self):
        """Handle selection change"""
        selected_rows = self.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            if row < len(self.packets):
                self.packet_selected.emit(self.packets[row])
                
    def show_context_menu(self, position):
        """Show context menu"""
        menu = QMenu(self)
        
        copy_action = menu.addAction("Copy")
        copy_src_action = menu.addAction("Copy Source IP")
        copy_dst_action = menu.addAction("Copy Destination IP")
        menu.addSeparator()
        follow_stream_action = menu.addAction("Follow Stream")
        filter_action = menu.addAction("Apply as Filter")
        
        action = menu.exec(self.mapToGlobal(position))
        
        if action == copy_action:
            self.copy_selected()
        elif action == copy_src_action:
            self.copy_source_ip()
        elif action == copy_dst_action:
            self.copy_destination_ip()
            
    def copy_selected(self):
        """Copy selected row"""
        # Implementation
        pass
        
    def copy_source_ip(self):
        """Copy source IP"""
        # Implementation
        pass
        
    def copy_destination_ip(self):
        """Copy destination IP"""
        # Implementation
        pass
        
    def clear(self):
        """Clear all packets"""
        self.setRowCount(0)
        self.packets.clear()
