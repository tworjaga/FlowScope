"""
Packet Details Panel
Displays detailed information about selected packets
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLabel, QPushButton, QGroupBox, QTabWidget
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PacketDetailsPanel(QWidget):
    """Panel for displaying packet details"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_packet = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Title
        title_layout = QHBoxLayout()
        title_label = QLabel("📦 Packet Details")
        title_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title_layout.addWidget(title_label)
        
        title_layout.addStretch()
        
        # Copy button
        copy_btn = QPushButton("📋 Copy")
        copy_btn.setMaximumWidth(80)
        copy_btn.clicked.connect(self.copy_details)
        title_layout.addWidget(copy_btn)
        
        layout.addLayout(title_layout)
        
        # Tabs for different detail views
        tabs = QTabWidget()
        
        # Summary tab
        summary_widget = QWidget()
        summary_layout = QVBoxLayout(summary_widget)
        
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 9))
        summary_layout.addWidget(self.summary_text)
        
        tabs.addTab(summary_widget, "Summary")
        
        # Hex dump tab
        hex_widget = QWidget()
        hex_layout = QVBoxLayout(hex_widget)
        
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Consolas", 9))
        hex_layout.addWidget(self.hex_text)
        
        tabs.addTab(hex_widget, "Hex Dump")
        
        # Raw data tab
        raw_widget = QWidget()
        raw_layout = QVBoxLayout(raw_widget)
        
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setFont(QFont("Consolas", 9))
        raw_layout.addWidget(self.raw_text)
        
        tabs.addTab(raw_widget, "Raw Data")
        
        layout.addWidget(tabs)
        
    def set_packet(self, packet_info: Dict[str, Any]):
        """Set packet to display"""
        self.current_packet = packet_info
        self.update_display()
        
    def update_display(self):
        """Update packet details display"""
        if not self.current_packet:
            self.summary_text.setText("No packet selected")
            self.hex_text.clear()
            self.raw_text.clear()
            return
        
        # Build summary
        summary_lines = []
        summary_lines.append("=" * 60)
        summary_lines.append("PACKET DETAILS")
        summary_lines.append("=" * 60)
        summary_lines.append("")
        
        # Basic info
        summary_lines.append("BASIC INFORMATION:")
        timestamp = self.current_packet.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            summary_lines.append(f"  Timestamp:    {timestamp}")
        else:
            summary_lines.append(f"  Timestamp:    {timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        
        summary_lines.append(f"  Protocol:     {self.current_packet.get('protocol', 'Unknown')}")
        summary_lines.append(f"  Length:       {self.current_packet.get('size', 0)} bytes")
        summary_lines.append("")
        
        # Network layer
        src_ip = self.current_packet.get('src_ip')
        dst_ip = self.current_packet.get('dst_ip')
        
        if src_ip or dst_ip:
            summary_lines.append("NETWORK LAYER:")
            if src_ip:
                summary_lines.append(f"  Source IP:    {src_ip}")
            if dst_ip:
                summary_lines.append(f"  Dest IP:      {dst_ip}")
            summary_lines.append("")
        
        # Transport layer
        src_port = self.current_packet.get('src_port')
        dst_port = self.current_packet.get('dst_port')
        
        if src_port or dst_port:
            summary_lines.append("TRANSPORT LAYER:")
            if src_port:
                summary_lines.append(f"  Source Port:  {src_port}")
            if dst_port:
                summary_lines.append(f"  Dest Port:    {dst_port}")
            
            # TCP specific
            flags = self.current_packet.get('flags')
            if flags and flags != 'None':
                summary_lines.append(f"  TCP Flags:    {flags}")
            
            seq = self.current_packet.get('seq')
            if seq is not None:
                summary_lines.append(f"  Sequence:     {seq}")
            
            ack = self.current_packet.get('ack')
            if ack is not None:
                summary_lines.append(f"  Acknowledge:  {ack}")
            
            summary_lines.append("")
        
        # Application layer
        info = self.current_packet.get('info')
        if info:
            summary_lines.append("APPLICATION LAYER:")
            summary_lines.append(f"  Info:         {info}")
            summary_lines.append("")
        
        # DNS specific
        dns_query = self.current_packet.get('dns_query')
        if dns_query:
            summary_lines.append("DNS INFORMATION:")
            summary_lines.append(f"  Query:        {dns_query}")
            summary_lines.append("")
        
        # ICMP specific
        icmp_type = self.current_packet.get('icmp_type')
        if icmp_type is not None:
            summary_lines.append("ICMP INFORMATION:")
            summary_lines.append(f"  Type:         {icmp_type}")
            summary_lines.append(f"  Code:         {self.current_packet.get('icmp_code', 0)}")
            summary_lines.append("")
        
        # ARP specific
        src_mac = self.current_packet.get('src_mac')
        dst_mac = self.current_packet.get('dst_mac')
        if src_mac or dst_mac:
            summary_lines.append("ARP INFORMATION:")
            if src_mac:
                summary_lines.append(f"  Source MAC:   {src_mac}")
            if dst_mac:
                summary_lines.append(f"  Dest MAC:     {dst_mac}")
            summary_lines.append("")
        
        summary_lines.append("=" * 60)
        
        self.summary_text.setText('\n'.join(summary_lines))
        
        # Update hex dump
        self.update_hex_dump()
        
        # Update raw data
        self.update_raw_data()
        
    def update_hex_dump(self):
        """Update hex dump view"""
        raw_packet = self.current_packet.get('raw_packet')
        if not raw_packet:
            self.hex_text.setText("No raw packet data available")
            return
        
        try:
            # Convert packet to bytes
            packet_bytes = bytes(raw_packet)
            
            # Create hex dump
            hex_lines = []
            hex_lines.append("Offset    Hex                                              ASCII")
            hex_lines.append("-" * 70)
            
            for i in range(0, len(packet_bytes), 16):
                chunk = packet_bytes[i:i+16]
                
                # Offset
                offset = f"{i:08x}"
                
                # Hex values
                hex_part = ' '.join(f"{b:02x}" for b in chunk)
                hex_part = hex_part.ljust(48)
                
                # ASCII representation
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                
                hex_lines.append(f"{offset}  {hex_part}  {ascii_part}")
            
            self.hex_text.setText('\n'.join(hex_lines))
            
        except Exception as e:
            self.hex_text.setText(f"Error generating hex dump: {e}")
            logger.error(f"Error generating hex dump: {e}")
    
    def update_raw_data(self):
        """Update raw data view"""
        raw_packet = self.current_packet.get('raw_packet')
        if not raw_packet:
            self.raw_text.setText("No raw packet data available")
            return
        
        try:
            # Show packet summary
            self.raw_text.setText(str(raw_packet.show(dump=True)))
        except Exception as e:
            self.raw_text.setText(f"Error displaying raw data: {e}")
            logger.error(f"Error displaying raw data: {e}")
    
    def copy_details(self):
        """Copy packet details to clipboard"""
        from PyQt6.QtWidgets import QApplication
        
        if self.current_packet:
            QApplication.clipboard().setText(self.summary_text.toPlainText())
            logger.info("Packet details copied to clipboard")
    
    def clear(self):
        """Clear packet details"""
        self.current_packet = None
        self.summary_text.clear()
        self.hex_text.clear()
        self.raw_text.clear()
