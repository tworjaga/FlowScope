"""
Anomaly Detection Panel
Displays detected network anomalies with detailed information
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QTextEdit, QLabel, QPushButton,
    QSplitter, QGroupBox, QComboBox, QCheckBox, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AnomalyPanel(QWidget):
    """Panel for displaying network anomalies"""
    
    anomaly_selected = pyqtSignal(dict)  # Emitted when anomaly is selected
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.anomalies = []
        self.selected_anomaly = None
        self.init_ui()
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_table)
        self.refresh_timer.start(1000)  # Refresh every second
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Top toolbar
        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Top: Anomalies table
        table_widget = self.create_table_widget()
        splitter.addWidget(table_widget)
        
        # Bottom: Anomaly details
        details_widget = self.create_details_widget()
        splitter.addWidget(details_widget)
        
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        
    def create_toolbar(self) -> QWidget:
        """Create toolbar"""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Title
        title = QLabel("⚠️ Anomaly Detection")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(title)
        
        layout.addStretch()
        
        # Severity filter
        layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.currentTextChanged.connect(self.apply_filters)
        layout.addWidget(self.severity_filter)
        
        # Type filter
        layout.addWidget(QLabel("Type:"))
        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "All", "Port Scan", "DNS Anomaly", "DDoS", "Beaconing",
            "Rate Limit", "VPN", "DoH", "Suspicious Port"
        ])
        self.type_filter.currentTextChanged.connect(self.apply_filters)
        layout.addWidget(self.type_filter)
        
        # Auto-scroll checkbox
        self.auto_scroll = QCheckBox("Auto-scroll")
        self.auto_scroll.setChecked(True)
        layout.addWidget(self.auto_scroll)
        
        # Clear button
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.setMaximumWidth(80)
        clear_btn.clicked.connect(self.clear_anomalies)
        layout.addWidget(clear_btn)
        
        # Export button
        export_btn = QPushButton("📤 Export")
        export_btn.setMaximumWidth(80)
        export_btn.clicked.connect(self.export_anomalies)
        layout.addWidget(export_btn)
        
        return toolbar
        
    def create_table_widget(self) -> QWidget:
        """Create anomalies table"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Time", "Severity", "Type", "Source", "Description", "Count"
        ])
        
        # Set column widths
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        
        layout.addWidget(self.table)
        
        return widget
        
    def create_details_widget(self) -> QWidget:
        """Create anomaly details widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Title
        title_layout = QHBoxLayout()
        title_label = QLabel("📋 Anomaly Details")
        title_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title_layout.addWidget(title_label)
        
        title_layout.addStretch()
        
        # Copy button
        copy_btn = QPushButton("📋 Copy")
        copy_btn.setMaximumWidth(80)
        copy_btn.clicked.connect(self.copy_details)
        title_layout.addWidget(copy_btn)
        
        layout.addLayout(title_layout)
        
        # Details text
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.details_text)
        
        return widget
        
    def add_anomaly(self, anomaly: Dict):
        """Add anomaly to display"""
        self.anomalies.append(anomaly)
        
        # Limit buffer size
        if len(self.anomalies) > 1000:
            self.anomalies = self.anomalies[-1000:]
        
        # Add to table if it passes filters
        if self.passes_filters(anomaly):
            self.add_table_row(anomaly)
            
            # Auto-scroll to bottom
            if self.auto_scroll.isChecked():
                self.table.scrollToBottom()
        
    def add_table_row(self, anomaly: Dict):
        """Add row to table"""
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # Time
        timestamp = anomaly.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            time_str = timestamp
        else:
            time_str = timestamp.strftime('%H:%M:%S')
        self.table.setItem(row, 0, QTableWidgetItem(time_str))
        
        # Severity
        severity = anomaly.get('severity', 'unknown').upper()
        severity_item = QTableWidgetItem(severity)
        
        # Color code by severity
        if severity == 'CRITICAL':
            severity_item.setBackground(QBrush(QColor(220, 53, 69)))
            severity_item.setForeground(QBrush(QColor(255, 255, 255)))
        elif severity == 'HIGH':
            severity_item.setBackground(QBrush(QColor(255, 193, 7)))
        elif severity == 'MEDIUM':
            severity_item.setBackground(QBrush(QColor(255, 235, 59)))
        elif severity == 'LOW':
            severity_item.setBackground(QBrush(QColor(76, 175, 80)))
            severity_item.setForeground(QBrush(QColor(255, 255, 255)))
        else:
            severity_item.setBackground(QBrush(QColor(158, 158, 158)))
            severity_item.setForeground(QBrush(QColor(255, 255, 255)))
        
        self.table.setItem(row, 1, severity_item)
        
        # Type
        anomaly_type = anomaly.get('type', 'unknown').replace('_', ' ').title()
        self.table.setItem(row, 2, QTableWidgetItem(anomaly_type))
        
        # Source
        src_ip = anomaly.get('src_ip', anomaly.get('ip', 'N/A'))
        self.table.setItem(row, 3, QTableWidgetItem(str(src_ip)))
        
        # Description
        description = anomaly.get('description', 'No description')
        self.table.setItem(row, 4, QTableWidgetItem(description))
        
        # Count (if available)
        count = anomaly.get('count', 1)
        self.table.setItem(row, 5, QTableWidgetItem(str(count)))
        
    def passes_filters(self, anomaly: Dict) -> bool:
        """Check if anomaly passes current filters"""
        # Severity filter
        severity_filter = self.severity_filter.currentText()
        if severity_filter != "All":
            if anomaly.get('severity', '').upper() != severity_filter.upper():
                return False
        
        # Type filter
        type_filter = self.type_filter.currentText()
        if type_filter != "All":
            anomaly_type = anomaly.get('type', '').replace('_', ' ').title()
            if anomaly_type != type_filter:
                return False
        
        return True
        
    def apply_filters(self):
        """Apply current filters"""
        self.refresh_table()
        
    def refresh_table(self):
        """Refresh table with current anomalies"""
        # Store current selection
        current_row = self.table.currentRow()
        
        # Clear table
        self.table.setRowCount(0)
        
        # Re-add filtered anomalies
        for anomaly in self.anomalies:
            if self.passes_filters(anomaly):
                self.add_table_row(anomaly)
        
        # Restore selection if possible
        if current_row >= 0 and current_row < self.table.rowCount():
            self.table.selectRow(current_row)
        
    def on_selection_changed(self):
        """Handle selection change"""
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            self.details_text.clear()
            return
        
        row = self.table.currentRow()
        if row < 0 or row >= len(self.anomalies):
            return
        
        # Find corresponding anomaly
        visible_anomalies = [a for a in self.anomalies if self.passes_filters(a)]
        if row < len(visible_anomalies):
            self.selected_anomaly = visible_anomalies[row]
            self.display_anomaly_details(self.selected_anomaly)
            self.anomaly_selected.emit(self.selected_anomaly)
        
    def display_anomaly_details(self, anomaly: Dict):
        """Display detailed anomaly information"""
        details = []
        details.append("=" * 60)
        details.append("ANOMALY DETAILS")
        details.append("=" * 60)
        details.append("")
        
        # Basic info
        details.append("BASIC INFORMATION:")
        timestamp = anomaly.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            details.append(f"  Timestamp:    {timestamp}")
        else:
            details.append(f"  Timestamp:    {timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        
        details.append(f"  Severity:     {anomaly.get('severity', 'unknown').upper()}")
        details.append(f"  Type:         {anomaly.get('type', 'unknown').replace('_', ' ').title()}")
        details.append(f"  Description:  {anomaly.get('description', 'No description')}")
        details.append("")
        
        # Network info
        if anomaly.get('src_ip') or anomaly.get('ip'):
            details.append("NETWORK INFORMATION:")
            if anomaly.get('src_ip'):
                details.append(f"  Source IP:    {anomaly['src_ip']}")
            if anomaly.get('dst_ip'):
                details.append(f"  Dest IP:      {anomaly['dst_ip']}")
            if anomaly.get('ip'):
                details.append(f"  IP Address:   {anomaly['ip']}")
            if anomaly.get('src_port'):
                details.append(f"  Source Port:  {anomaly['src_port']}")
            if anomaly.get('dst_port'):
                details.append(f"  Dest Port:    {anomaly['dst_port']}")
            details.append("")
        
        # Type-specific details
        anomaly_type = anomaly.get('type', '')
        
        if anomaly_type == 'port_scan':
            details.append("PORT SCAN DETAILS:")
            details.append(f"  Ports Scanned: {len(anomaly.get('ports', []))}")
            ports = anomaly.get('ports', [])
            if ports:
                details.append(f"  Port List:     {', '.join(map(str, sorted(ports)[:20]))}")
                if len(ports) > 20:
                    details.append(f"                 ... and {len(ports) - 20} more")
            details.append("")
            
        elif anomaly_type == 'dns_anomaly':
            details.append("DNS ANOMALY DETAILS:")
            details.append(f"  Query Count:   {anomaly.get('query_count', 0)}")
            details.append(f"  Threshold:     {anomaly.get('threshold', 0)}")
            if anomaly.get('queries'):
                details.append(f"  Recent Queries: {len(anomaly['queries'])}")
            details.append("")
            
        elif anomaly_type == 'beaconing':
            details.append("BEACONING DETAILS:")
            details.append(f"  Interval:      {anomaly.get('interval', 0):.2f}s")
            details.append(f"  Occurrences:   {anomaly.get('count', 0)}")
            details.append(f"  Regularity:    High (potential C2 communication)")
            details.append("")
            
        elif anomaly_type == 'ddos':
            details.append("DDoS ATTACK DETAILS:")
            details.append(f"  Connection Rate: {anomaly.get('rate', 0):.1f} conn/s")
            details.append(f"  Total Attempts:  {anomaly.get('attempts', 0)}")
            details.append(f"  Attack Type:     {anomaly.get('attack_type', 'Unknown')}")
            details.append("")
            
        elif anomaly_type == 'rate_limit':
            details.append("RATE LIMIT EXCEEDED:")
            details.append(f"  Packets/sec:   {anomaly.get('pps', 0):.1f}")
            details.append(f"  Bytes/sec:     {anomaly.get('bps', 0):.1f}")
            details.append(f"  Limit:         {anomaly.get('limit', 0)}")
            details.append("")
            
        elif anomaly_type == 'vpn_detected':
            details.append("VPN DETECTION:")
            details.append(f"  VPN Type:      {anomaly.get('vpn_type', 'Unknown')}")
            details.append(f"  Indicators:    {', '.join(anomaly.get('indicators', []))}")
            details.append("")
            
        elif anomaly_type == 'doh_detected':
            details.append("DNS OVER HTTPS:")
            details.append(f"  DoH Server:    {anomaly.get('server', 'Unknown')}")
            details.append(f"  Provider:      {anomaly.get('provider', 'Unknown')}")
            details.append("")
        
        # Additional metadata
        if anomaly.get('count', 0) > 1:
            details.append("OCCURRENCE INFORMATION:")
            details.append(f"  Total Count:   {anomaly['count']}")
            details.append("")
        
        # Recommendations
        details.append("RECOMMENDATIONS:")
        recommendations = self.get_recommendations(anomaly)
        for rec in recommendations:
            details.append(f"  • {rec}")
        
        details.append("")
        details.append("=" * 60)
        
        self.details_text.setText('\n'.join(details))
        
    def get_recommendations(self, anomaly: Dict) -> List[str]:
        """Get recommendations based on anomaly type"""
        anomaly_type = anomaly.get('type', '')
        severity = anomaly.get('severity', '').lower()
        
        recommendations = []
        
        if anomaly_type == 'port_scan':
            recommendations.append("Block source IP if malicious")
            recommendations.append("Enable firewall rules to limit port scanning")
            recommendations.append("Monitor for follow-up exploitation attempts")
            
        elif anomaly_type == 'dns_anomaly':
            recommendations.append("Investigate DNS queries for data exfiltration")
            recommendations.append("Check for DNS tunneling activity")
            recommendations.append("Review DNS server logs")
            
        elif anomaly_type == 'beaconing':
            recommendations.append("CRITICAL: Possible C2 communication detected")
            recommendations.append("Isolate affected system immediately")
            recommendations.append("Perform malware scan on source system")
            recommendations.append("Analyze destination IP for known threats")
            
        elif anomaly_type == 'ddos':
            recommendations.append("Enable DDoS protection mechanisms")
            recommendations.append("Rate limit connections from source")
            recommendations.append("Contact ISP if attack persists")
            
        elif anomaly_type == 'rate_limit':
            recommendations.append("Investigate source for legitimate high traffic")
            recommendations.append("Apply rate limiting if malicious")
            
        elif anomaly_type == 'vpn_detected':
            recommendations.append("Verify VPN usage is authorized")
            recommendations.append("Check corporate VPN policy compliance")
            
        elif anomaly_type == 'doh_detected':
            recommendations.append("Verify DoH usage is authorized")
            recommendations.append("Consider blocking DoH if against policy")
        
        if severity in ['critical', 'high']:
            recommendations.insert(0, "⚠️ HIGH PRIORITY: Immediate action recommended")
        
        return recommendations
        
    def export_anomalies(self):
        """Export anomalies to file"""
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Anomalies",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            try:
                import json
                
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.anomalies, f, indent=2, default=str)
                elif filename.endswith('.csv'):
                    with open(filename, 'w') as f:
                        f.write('timestamp,severity,type,src_ip,dst_ip,description\n')
                        for a in self.anomalies:
                            f.write(f"{a.get('timestamp')},{a.get('severity')},{a.get('type')},"
                                  f"{a.get('src_ip', 'N/A')},{a.get('dst_ip', 'N/A')},"
                                  f"\"{a.get('description', '')}\"\n")
                
                logger.info(f"Exported {len(self.anomalies)} anomalies to {filename}")
            except Exception as e:
                logger.error(f"Error exporting anomalies: {e}")
                
    def clear_anomalies(self):
        """Clear all anomalies"""
        self.anomalies.clear()
        self.table.setRowCount(0)
        self.details_text.clear()
        logger.info("Cleared all anomalies")
        
    def copy_details(self):
        """Copy anomaly details to clipboard"""
        from PyQt6.QtWidgets import QApplication
        
        if self.selected_anomaly:
            QApplication.clipboard().setText(self.details_text.toPlainText())
            logger.info("Anomaly details copied to clipboard")
    
    def set_anomalies(self, anomalies: List[Dict]):
        """Set anomalies from external source"""
        self.anomalies = anomalies
        self.refresh_table()
