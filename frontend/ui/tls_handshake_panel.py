"""
TLS Handshake Panel
Display captured TLS handshakes with detailed information
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QTextEdit, QLabel, QPushButton,
    QSplitter, QGroupBox, QComboBox, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class TLSHandshakePanel(QWidget):
    """Panel for displaying TLS handshakes"""
    
    handshake_selected = pyqtSignal(dict)  # Emitted when handshake is selected
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.handshakes = []
        self.selected_handshake = None
        self.init_ui()
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_table)
        self.refresh_timer.start(2000)  # Refresh every 2 seconds
        
        # NOTE: TLS handshake capturing works best on Linux systems
        # Windows may have limitations with raw packet capture
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Top toolbar
        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Top: Handshakes table
        table_widget = self.create_table_widget()
        splitter.addWidget(table_widget)
        
        # Bottom: Handshake details
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
        
        # Title with platform note
        title_layout = QVBoxLayout()
        title = QLabel("🔒 TLS Handshakes")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title_layout.addWidget(title)
        
        # Platform note
        note = QLabel("⚠️ Note: TLS handshake capturing works best on Linux systems")
        note.setStyleSheet("color: #ff9800; font-size: 9px;")
        title_layout.addWidget(note)
        
        title_widget = QWidget()
        title_widget.setLayout(title_layout)
        layout.addWidget(title_widget)
        
        layout.addStretch()
        
        # Filter by version
        layout.addWidget(QLabel("Version:"))
        self.version_filter = QComboBox()
        self.version_filter.addItems(["All", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"])
        self.version_filter.currentTextChanged.connect(self.apply_filters)
        layout.addWidget(self.version_filter)
        
        # Show only complete
        self.complete_only_check = QCheckBox("Complete only")
        self.complete_only_check.setChecked(True)
        self.complete_only_check.stateChanged.connect(self.apply_filters)
        layout.addWidget(self.complete_only_check)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_table)
        layout.addWidget(refresh_btn)
        
        # Export button
        export_btn = QPushButton("💾 Export")
        export_btn.clicked.connect(self.export_handshakes)
        layout.addWidget(export_btn)
        
        # Clear button
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.clicked.connect(self.clear_handshakes)
        layout.addWidget(clear_btn)
        
        return toolbar
        
    def create_table_widget(self) -> QWidget:
        """Create handshakes table"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Statistics label
        self.stats_label = QLabel("Total: 0 | Complete: 0 | In Progress: 0")
        layout.addWidget(self.stats_label)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels([
            "Timestamp",
            "Source IP",
            "Destination IP",
            "TLS Version",
            "Cipher Suite",
            "SNI",
            "Duration (ms)",
            "Status",
            "JA3",
            "Certificate"
        ])
        
        # Set column widths
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 80)
        self.table.setColumnWidth(4, 200)
        self.table.setColumnWidth(5, 150)
        self.table.setColumnWidth(6, 100)
        self.table.setColumnWidth(7, 100)
        self.table.setColumnWidth(8, 100)
        self.table.setColumnWidth(9, 150)
        
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self.on_handshake_selected)
        
        layout.addWidget(self.table)
        
        return widget
        
    def create_details_widget(self) -> QWidget:
        """Create handshake details widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Details group
        details_group = QGroupBox("Handshake Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 9))
        details_layout.addWidget(self.details_text)
        
        layout.addWidget(details_group)
        
        return widget
        
    def add_handshake(self, handshake: Dict):
        """Add handshake to display"""
        self.handshakes.append(handshake)
        self.refresh_table()
        
    def refresh_table(self):
        """Refresh handshakes table"""
        # Apply filters
        filtered = self.apply_filters()
        
        # Update statistics
        total = len(self.handshakes)
        complete = sum(1 for h in self.handshakes if h.get('is_complete', False))
        in_progress = total - complete
        self.stats_label.setText(f"Total: {total} | Complete: {complete} | In Progress: {in_progress}")
        
        # Update table
        self.table.setRowCount(0)
        
        for handshake in filtered:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # Timestamp
            timestamp = handshake.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                timestamp_str = timestamp
            else:
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            self.table.setItem(row, 0, QTableWidgetItem(timestamp_str))
            
            # Source IP
            self.table.setItem(row, 1, QTableWidgetItem(handshake.get('src_ip', '')))
            
            # Destination IP
            self.table.setItem(row, 2, QTableWidgetItem(handshake.get('dst_ip', '')))
            
            # TLS Version
            version_item = QTableWidgetItem(handshake.get('tls_version', 'Unknown'))
            # Color code by version
            if 'TLS 1.3' in handshake.get('tls_version', ''):
                version_item.setForeground(QColor('#4ec9b0'))  # Green
            elif 'TLS 1.2' in handshake.get('tls_version', ''):
                version_item.setForeground(QColor('#569cd6'))  # Blue
            else:
                version_item.setForeground(QColor('#ce9178'))  # Orange (older)
            self.table.setItem(row, 3, version_item)
            
            # Cipher Suite
            cipher = handshake.get('cipher_suite', 'Unknown')
            if len(cipher) > 30:
                cipher = cipher[:27] + '...'
            self.table.setItem(row, 4, QTableWidgetItem(cipher))
            
            # SNI
            sni = handshake.get('sni', '-')
            if len(sni) > 25:
                sni = sni[:22] + '...'
            self.table.setItem(row, 5, QTableWidgetItem(sni))
            
            # Duration
            duration = handshake.get('handshake_duration')
            if duration:
                duration_str = f"{duration*1000:.1f}"
            else:
                duration_str = '-'
            self.table.setItem(row, 6, QTableWidgetItem(duration_str))
            
            # Status
            status_item = QTableWidgetItem('✓ Complete' if handshake.get('is_complete') else '⏳ In Progress')
            if handshake.get('is_complete'):
                status_item.setForeground(QColor('#4ec9b0'))  # Green
            else:
                status_item.setForeground(QColor('#dcdcaa'))  # Yellow
            self.table.setItem(row, 7, status_item)
            
            # JA3
            ja3 = handshake.get('ja3_hash', '-')
            if len(ja3) > 12:
                ja3 = ja3[:12] + '...'
            self.table.setItem(row, 8, QTableWidgetItem(ja3))
            
            # Certificate
            cert = handshake.get('cert_subject', '-')
            if len(cert) > 20:
                cert = cert[:17] + '...'
            self.table.setItem(row, 9, QTableWidgetItem(cert))
            
    def apply_filters(self) -> List[Dict]:
        """Apply filters and return filtered handshakes"""
        filtered = self.handshakes.copy()
        
        # Filter by version
        version_filter = self.version_filter.currentText()
        if version_filter != "All":
            filtered = [h for h in filtered if h.get('tls_version') == version_filter]
        
        # Filter by complete status
        if self.complete_only_check.isChecked():
            filtered = [h for h in filtered if h.get('is_complete', False)]
        
        return filtered
        
    def on_handshake_selected(self):
        """Handle handshake selection"""
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        filtered = self.apply_filters()
        
        if row < len(filtered):
            handshake = filtered[row]
            self.selected_handshake = handshake
            self.show_handshake_details(handshake)
            self.handshake_selected.emit(handshake)
            
    def show_handshake_details(self, handshake: Dict):
        """Show detailed handshake information"""
        details = []
        
        details.append("=" * 60)
        details.append("TLS HANDSHAKE DETAILS")
        details.append("=" * 60)
        details.append("")
        
        # Connection info
        details.append("CONNECTION:")
        details.append(f"  Source:      {handshake.get('src_ip')}:{handshake.get('src_port')}")
        details.append(f"  Destination: {handshake.get('dst_ip')}:{handshake.get('dst_port')}")
        details.append(f"  Timestamp:   {handshake.get('timestamp')}")
        details.append(f"  Duration:    {handshake.get('handshake_duration', 0)*1000:.2f} ms")
        details.append(f"  Status:      {'Complete' if handshake.get('is_complete') else 'In Progress'}")
        details.append("")
        
        # TLS info
        details.append("TLS INFORMATION:")
        details.append(f"  Version:     {handshake.get('tls_version', 'Unknown')}")
        details.append(f"  Cipher:      {handshake.get('cipher_suite', 'Unknown')}")
        details.append(f"  Compression: {handshake.get('compression_method', 'None')}")
        details.append("")
        
        # Extensions
        if handshake.get('sni'):
            details.append("EXTENSIONS:")
            details.append(f"  SNI:         {handshake.get('sni')}")
            
            alpn = handshake.get('alpn')
            if alpn:
                details.append(f"  ALPN:        {', '.join(alpn)}")
            details.append("")
        
        # Certificate
        if handshake.get('cert_subject'):
            details.append("CERTIFICATE:")
            details.append(f"  Subject:     {handshake.get('cert_subject')}")
            details.append(f"  Issuer:      {handshake.get('cert_issuer', 'Unknown')}")
            details.append(f"  Valid From:  {handshake.get('cert_valid_from', 'Unknown')}")
            details.append(f"  Valid To:    {handshake.get('cert_valid_to', 'Unknown')}")
            details.append(f"  Fingerprint: {handshake.get('cert_fingerprint', 'Unknown')}")
            details.append("")
        
        # JA3 Fingerprint
        if handshake.get('ja3_hash'):
            details.append("JA3 FINGERPRINT:")
            details.append(f"  Hash:        {handshake.get('ja3_hash')}")
            details.append(f"  String:      {handshake.get('ja3_string', 'N/A')[:60]}...")
            details.append("")
        
        # Handshake stages
        details.append("HANDSHAKE STAGES:")
        client_hello = handshake.get('client_hello')
        if client_hello:
            details.append(f"  ✓ ClientHello")
            details.append(f"      Version: {client_hello.get('version')}")
            details.append(f"      Ciphers: {client_hello.get('cipher_count')} offered")
        
        server_hello = handshake.get('server_hello')
        if server_hello:
            details.append(f"  ✓ ServerHello")
            details.append(f"      Version: {server_hello.get('version')}")
            details.append(f"      Cipher:  {server_hello.get('cipher_suite')}")
        
        if handshake.get('certificate'):
            details.append(f"  ✓ Certificate")
        
        if handshake.get('server_hello_done'):
            details.append(f"  ✓ ServerHelloDone")
        
        if handshake.get('client_key_exchange'):
            details.append(f"  ✓ ClientKeyExchange")
        
        if handshake.get('change_cipher_spec_client'):
            details.append(f"  ✓ ChangeCipherSpec (Client)")
        
        if handshake.get('change_cipher_spec_server'):
            details.append(f"  ✓ ChangeCipherSpec (Server)")
        
        if handshake.get('finished_client'):
            details.append(f"  ✓ Finished (Client)")
        
        if handshake.get('finished_server'):
            details.append(f"  ✓ Finished (Server)")
        
        details.append("")
        details.append("=" * 60)
        
        self.details_text.setText('\n'.join(details))
        
    def export_handshakes(self):
        """Export handshakes to file"""
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Handshakes",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            try:
                import json
                
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.handshakes, f, indent=2, default=str)
                elif filename.endswith('.csv'):
                    with open(filename, 'w') as f:
                        f.write('timestamp,src_ip,dst_ip,tls_version,cipher_suite,sni,duration,status\n')
                        for h in self.handshakes:
                            f.write(f"{h.get('timestamp')},{h.get('src_ip')},{h.get('dst_ip')},"
                                  f"{h.get('tls_version')},{h.get('cipher_suite')},{h.get('sni')},"
                                  f"{h.get('handshake_duration')},{'complete' if h.get('is_complete') else 'in_progress'}\n")
                
                logger.info(f"Exported {len(self.handshakes)} handshakes to {filename}")
            except Exception as e:
                logger.error(f"Error exporting handshakes: {e}")
                
    def clear_handshakes(self):
        """Clear all handshakes"""
        self.handshakes.clear()
        self.refresh_table()
        self.details_text.clear()
        logger.info("Cleared all handshakes")
        
    def set_handshakes(self, handshakes: List[Dict]):
        """Set handshakes from external source"""
        self.handshakes = handshakes
        self.refresh_table()
