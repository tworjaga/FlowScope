"""
WiFi Panel
GUI panel for WiFi network analysis
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QLabel, QGroupBox,
                             QProgressBar, QTextEdit, QSplitter, QHeaderView)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
import logging

from backend.core.wifi_analyzer import WiFiAnalyzer

logger = logging.getLogger(__name__)


class WiFiPanel(QWidget):
    """WiFi analysis panel"""
    
    scan_completed = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.wifi_analyzer = WiFiAnalyzer()
        self.init_ui()
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.scan_networks)
        
    def init_ui(self):
        """Initialize user interface"""
        layout = QVBoxLayout(self)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🔍 Scan Networks")
        self.scan_btn.clicked.connect(self.scan_networks)
        control_layout.addWidget(self.scan_btn)
        
        self.auto_refresh_btn = QPushButton("🔄 Auto Refresh: OFF")
        self.auto_refresh_btn.setCheckable(True)
        self.auto_refresh_btn.clicked.connect(self.toggle_auto_refresh)
        control_layout.addWidget(self.auto_refresh_btn)
        
        self.report_btn = QPushButton("📄 Generate Report")
        self.report_btn.clicked.connect(self.generate_report)
        control_layout.addWidget(self.report_btn)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Splitter for top and bottom sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Top section: Network list
        networks_group = QGroupBox("Available Networks")
        networks_layout = QVBoxLayout(networks_group)
        
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(7)
        self.networks_table.setHorizontalHeaderLabels([
            'SSID', 'Signal', 'Channel', 'Band', 'Security', 'BSSID', 'Quality'
        ])
        self.networks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.networks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.networks_table.itemSelectionChanged.connect(self.on_network_selected)
        networks_layout.addWidget(self.networks_table)
        
        splitter.addWidget(networks_group)
        
        # Bottom section: Analysis and recommendations
        bottom_widget = QWidget()
        bottom_layout = QHBoxLayout(bottom_widget)
        
        # Connected network info
        connected_group = QGroupBox("Connected Network")
        connected_layout = QVBoxLayout(connected_group)
        
        self.connected_label = QLabel("Not connected")
        self.connected_label.setWordWrap(True)
        connected_layout.addWidget(self.connected_label)
        
        self.signal_bar = QProgressBar()
        self.signal_bar.setRange(0, 100)
        connected_layout.addWidget(QLabel("Signal Strength:"))
        connected_layout.addWidget(self.signal_bar)
        
        connected_layout.addStretch()
        bottom_layout.addWidget(connected_group)
        
        # Channel analysis
        channel_group = QGroupBox("Channel Analysis")
        channel_layout = QVBoxLayout(channel_group)
        
        self.channel_text = QTextEdit()
        self.channel_text.setReadOnly(True)
        self.channel_text.setMaximumHeight(150)
        channel_layout.addWidget(self.channel_text)
        
        bottom_layout.addWidget(channel_group)
        
        # Recommendations
        recommendations_group = QGroupBox("Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.recommendations_text.setMaximumHeight(150)
        recommendations_layout.addWidget(self.recommendations_text)
        
        bottom_layout.addWidget(recommendations_group)
        
        splitter.addWidget(bottom_widget)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        
        # Status label
        self.status_label = QLabel("Ready to scan")
        layout.addWidget(self.status_label)
        
    def scan_networks(self):
        """Scan for WiFi networks"""
        self.status_label.setText("Scanning...")
        self.scan_btn.setEnabled(False)
        
        try:
            # Scan networks
            networks = self.wifi_analyzer.scan_networks()
            
            # Update table
            self.update_networks_table(networks)
            
            # Update connected network
            self.update_connected_network()
            
            # Update channel analysis
            self.update_channel_analysis()
            
            # Update recommendations
            self.update_recommendations(networks)
            
            self.status_label.setText(f"Found {len(networks)} networks")
            self.scan_completed.emit(networks)
            
        except Exception as e:
            self.status_label.setText(f"Error: {e}")
            logger.error(f"Error scanning networks: {e}")
            
        finally:
            self.scan_btn.setEnabled(True)
            
    def update_networks_table(self, networks):
        """Update networks table"""
        self.networks_table.setRowCount(len(networks))
        
        for row, network in enumerate(networks):
            # SSID
            ssid_item = QTableWidgetItem(network.get('ssid', 'Hidden'))
            self.networks_table.setItem(row, 0, ssid_item)
            
            # Signal
            signal = network.get('signal', 0)
            signal_item = QTableWidgetItem(f"{signal}%")
            signal_item.setData(Qt.ItemDataRole.UserRole, signal)
            
            # Color code by signal strength
            if signal >= 80:
                signal_item.setBackground(QColor(76, 201, 176))  # Green
            elif signal >= 60:
                signal_item.setBackground(QColor(156, 220, 254))  # Blue
            elif signal >= 40:
                signal_item.setBackground(QColor(220, 220, 170))  # Yellow
            else:
                signal_item.setBackground(QColor(244, 135, 113))  # Red
                
            self.networks_table.setItem(row, 1, signal_item)
            
            # Channel
            channel = network.get('channel', 0)
            channel_item = QTableWidgetItem(str(channel))
            self.networks_table.setItem(row, 2, channel_item)
            
            # Band
            band = '5GHz' if channel > 14 else '2.4GHz'
            band_item = QTableWidgetItem(band)
            self.networks_table.setItem(row, 3, band_item)
            
            # Security
            security = network.get('encryption', network.get('security', network.get('auth', 'Unknown')))
            security_item = QTableWidgetItem(security)
            
            # Color code by security
            if 'OPEN' in security.upper() or 'NONE' in security.upper():
                security_item.setBackground(QColor(244, 135, 113))  # Red - insecure
            elif 'WEP' in security.upper():
                security_item.setBackground(QColor(220, 220, 170))  # Yellow - weak
            elif 'WPA3' in security.upper():
                security_item.setBackground(QColor(76, 201, 176))  # Green - strong
            elif 'WPA2' in security.upper():
                security_item.setBackground(QColor(156, 220, 254))  # Blue - good
                
            self.networks_table.setItem(row, 4, security_item)
            
            # BSSID
            bssid_item = QTableWidgetItem(network.get('bssid', 'Unknown'))
            self.networks_table.setItem(row, 5, bssid_item)
            
            # Quality
            quality = self.wifi_analyzer._signal_to_quality(signal)
            quality_item = QTableWidgetItem(quality.capitalize())
            self.networks_table.setItem(row, 6, quality_item)
            
    def update_connected_network(self):
        """Update connected network information"""
        connected = self.wifi_analyzer.get_connected_network()
        
        if connected:
            ssid = connected.get('ssid', 'Unknown')
            signal = connected.get('signal', 0)
            channel = connected.get('channel', 0)
            bssid = connected.get('bssid', 'Unknown')
            
            info_text = f"""
<b>SSID:</b> {ssid}<br>
<b>Signal:</b> {signal}%<br>
<b>Channel:</b> {channel}<br>
<b>BSSID:</b> {bssid}<br>
<b>Quality:</b> {self.wifi_analyzer._signal_to_quality(signal).capitalize()}
            """
            
            self.connected_label.setText(info_text)
            self.signal_bar.setValue(signal)
            
            # Analyze signal
            analysis = self.wifi_analyzer.analyze_signal_strength(ssid)
            if analysis.get('status') != 'no_data':
                stability = analysis.get('stability', 'unknown')
                self.connected_label.setText(
                    info_text + f"<br><b>Stability:</b> {stability.capitalize()}"
                )
        else:
            self.connected_label.setText("Not connected to any network")
            self.signal_bar.setValue(0)
            
    def update_channel_analysis(self):
        """Update channel congestion analysis"""
        congestion = self.wifi_analyzer.analyze_channel_congestion()
        
        # Get best channels
        best_24 = self.wifi_analyzer.get_best_channel('2.4GHz')
        best_5 = self.wifi_analyzer.get_best_channel('5GHz')
        
        # Build analysis text
        text = f"<b>Best Channels:</b><br>"
        text += f"2.4GHz: Channel {best_24}<br>"
        text += f"5GHz: Channel {best_5}<br><br>"
        
        text += "<b>2.4GHz Band Congestion:</b><br>"
        for ch in [1, 6, 11]:  # Non-overlapping channels
            data = congestion.get(ch, {})
            level = data.get('congestion_level', 'unknown')
            count = data.get('networks', 0)
            text += f"Channel {ch}: {level.capitalize()} ({count} networks)<br>"
            
        text += "<br><b>5GHz Band (Sample):</b><br>"
        for ch in [36, 40, 44, 48]:
            data = congestion.get(ch, {})
            level = data.get('congestion_level', 'unknown')
            count = data.get('networks', 0)
            text += f"Channel {ch}: {level.capitalize()} ({count} networks)<br>"
            
        self.channel_text.setHtml(text)
        
    def update_recommendations(self, networks):
        """Update recommendations"""
        congestion = self.wifi_analyzer.analyze_channel_congestion()
        recommendations = self.wifi_analyzer._generate_recommendations(networks, congestion)
        
        # Add security warnings
        for network in networks:
            issues = self.wifi_analyzer.detect_security_issues(network)
            if issues:
                recommendations.extend([f"⚠️ {network.get('ssid', 'Unknown')}: {issue}" for issue in issues[:2]])
                
        text = "<b>Recommendations:</b><br><br>"
        for i, rec in enumerate(recommendations[:10], 1):
            text += f"{i}. {rec}<br>"
            
        self.recommendations_text.setHtml(text)
        
    def on_network_selected(self):
        """Handle network selection"""
        selected_rows = self.networks_table.selectedItems()
        if selected_rows:
            row = selected_rows[0].row()
            ssid = self.networks_table.item(row, 0).text()
            
            # Show detailed info for selected network
            if ssid in self.wifi_analyzer.networks:
                network = self.wifi_analyzer.networks[ssid]
                issues = self.wifi_analyzer.detect_security_issues(network)
                
                if issues:
                    info = f"<b>Security Issues for {ssid}:</b><br>"
                    for issue in issues:
                        info += f"• {issue}<br>"
                    self.status_label.setText(f"Selected: {ssid} - {len(issues)} security issues")
                else:
                    self.status_label.setText(f"Selected: {ssid} - No security issues detected")
                    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh"""
        if self.auto_refresh_btn.isChecked():
            self.refresh_timer.start(10000)  # Refresh every 10 seconds
            self.auto_refresh_btn.setText("🔄 Auto Refresh: ON")
            self.scan_networks()  # Initial scan
        else:
            self.refresh_timer.stop()
            self.auto_refresh_btn.setText("🔄 Auto Refresh: OFF")
            
    def generate_report(self):
        """Generate WiFi analysis report"""
        try:
            report = self.wifi_analyzer.generate_wifi_report()
            
            # Format report
            text = f"<h2>WiFi Analysis Report</h2>"
            text += f"<b>Generated:</b> {report['timestamp']}<br><br>"
            
            if report.get('connected_network'):
                cn = report['connected_network']
                text += f"<b>Connected Network:</b> {cn.get('ssid', 'Unknown')}<br>"
                text += f"Signal: {cn.get('signal', 0)}%<br><br>"
                
            stats = report.get('statistics', {})
            text += f"<b>Statistics:</b><br>"
            text += f"Total Networks: {stats.get('total_networks', 0)}<br>"
            
            by_band = stats.get('by_band', {})
            text += f"2.4GHz Networks: {by_band.get('2.4GHz', 0)}<br>"
            text += f"5GHz Networks: {by_band.get('5GHz', 0)}<br><br>"
            
            text += "<b>Recommendations:</b><br>"
            for rec in report.get('recommendations', []):
                text += f"• {rec}<br>"
                
            # Show in recommendations area
            self.recommendations_text.setHtml(text)
            self.status_label.setText("Report generated")
            
        except Exception as e:
            self.status_label.setText(f"Error generating report: {e}")
            logger.error(f"Error generating report: {e}")
