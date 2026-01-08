"""
Main Window
Primary GUI interface for FlowScope
"""

import sys
import time
import logging
from pathlib import Path

from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTabWidget, QMenuBar, QMenu, QToolBar, QStatusBar,
                             QLabel, QPushButton, QMessageBox, QFileDialog,
                             QDockWidget, QSplitter)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QFont

from backend.core.packet_capture import PacketCaptureEngine
from backend.core.filter_engine import FilterEngine
from backend.core.statistics import StatisticsEngine
from backend.core.anomaly_detector import AnomalyDetector
from backend.database.session_manager import SessionManager
from config.settings import Settings
from frontend.themes.dark_theme import DarkTheme
from frontend.ui.packet_table import PacketTableWidget
from frontend.ui.statistics_panel import StatisticsPanel
from frontend.ui.filters_panel import FiltersPanel
from frontend.ui.graphs import GraphsWidget
from frontend.ui.wifi_panel import WiFiPanel
from frontend.ui.tls_handshake_panel import TLSHandshakePanel
from frontend.ui.packet_details_panel import PacketDetailsPanel

logger = logging.getLogger(__name__)


class CaptureThread(QThread):
    """Thread for packet capture"""
    packet_received = pyqtSignal(dict)
    statistics_updated = pyqtSignal(dict)
    
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.running = False
        
    def run(self):
        """Run capture thread"""
        self.running = True
        # Capture loop handled by async engine
        

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        super().__init__()
        
        # Load settings
        self.settings = Settings(config_path)
        
        # Initialize components
        self.capture_engine = None
        self.filter_engine = FilterEngine()
        self.stats_engine = StatisticsEngine()
        self.anomaly_detector = AnomalyDetector()
        self.session_manager = SessionManager()
        
        # TLS Analyzer
        from backend.core.tls_analyzer import TLSAnalyzer
        self.tls_analyzer = TLSAnalyzer()
        
        # State
        self.is_capturing = False
        self.current_session = None
        
        # Setup UI
        self.init_ui()
        self.apply_theme()
        self.setup_connections()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(self.settings.update_interval)
        
        logger.info("Main window initialized")
        
    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle("FlowScope")
        self.setGeometry(100, 100, 
                        self.settings.get('ui.window_width', 1600),
                        self.settings.get('ui.window_height', 900))
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create main horizontal splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side: Packet table and tabs (vertical splitter)
        left_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Top section: Packet table
        self.packet_table = PacketTableWidget()
        left_splitter.addWidget(self.packet_table)
        
        # Bottom section: Tabs for different views
        self.tab_widget = QTabWidget()
        
        # Statistics tab
        self.stats_panel = StatisticsPanel()
        self.tab_widget.addTab(self.stats_panel, "📊 Statistics")
        
        # Graphs tab
        self.graphs_widget = GraphsWidget()
        self.tab_widget.addTab(self.graphs_widget, "📈 Graphs")
        
        # Filters tab
        self.filters_panel = FiltersPanel(self.filter_engine)
        self.tab_widget.addTab(self.filters_panel, "🔍 Filters")
        
        # WiFi tab
        self.wifi_panel = WiFiPanel()
        self.tab_widget.addTab(self.wifi_panel, "📡 WiFi Analysis")
        
        # TLS Handshake tab
        self.tls_panel = TLSHandshakePanel()
        self.tab_widget.addTab(self.tls_panel, "🔒 TLS Handshakes")
        
        left_splitter.addWidget(self.tab_widget)
        left_splitter.setStretchFactor(0, 3)
        left_splitter.setStretchFactor(1, 1)
        
        # Add left splitter to main splitter
        main_splitter.addWidget(left_splitter)
        
        # Right side: Packet details panel
        self.packet_details_panel = PacketDetailsPanel()
        main_splitter.addWidget(self.packet_details_panel)
        
        # Set stretch factors for main splitter
        main_splitter.setStretchFactor(0, 3)  # Left side (table + tabs)
        main_splitter.setStretchFactor(1, 1)  # Right side (details)
        
        main_layout.addWidget(main_splitter)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create status bar
        self.create_status_bar()
        
        # Create dock widgets
        self.create_dock_widgets()
        
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        new_session_action = QAction("&New Session", self)
        new_session_action.setShortcut(QKeySequence.StandardKey.New)
        new_session_action.triggered.connect(self.new_session)
        file_menu.addAction(new_session_action)
        
        open_session_action = QAction("&Open Session", self)
        open_session_action.setShortcut(QKeySequence.StandardKey.Open)
        open_session_action.triggered.connect(self.open_session)
        file_menu.addAction(open_session_action)
        
        save_session_action = QAction("&Save Session", self)
        save_session_action.setShortcut(QKeySequence.StandardKey.Save)
        save_session_action.triggered.connect(self.save_session)
        file_menu.addAction(save_session_action)
        
        file_menu.addSeparator()
        
        export_menu = file_menu.addMenu("&Export")
        
        export_csv_action = QAction("Export to &CSV", self)
        export_csv_action.setShortcut("Ctrl+E")
        export_csv_action.triggered.connect(self.export_csv)
        export_menu.addAction(export_csv_action)
        
        export_pcap_action = QAction("Export to &PCAP", self)
        export_pcap_action.triggered.connect(self.export_pcap)
        export_menu.addAction(export_pcap_action)
        
        export_html_action = QAction("Export to &HTML", self)
        export_html_action.triggered.connect(self.export_html)
        export_menu.addAction(export_html_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Capture menu
        capture_menu = menubar.addMenu("&Capture")
        
        self.start_action = QAction("&Start Capture", self)
        self.start_action.setShortcut("Ctrl+P")
        self.start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(self.start_action)
        
        self.stop_action = QAction("S&top Capture", self)
        self.stop_action.setShortcut("Ctrl+T")
        self.stop_action.setEnabled(False)
        self.stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(self.stop_action)
        
        capture_menu.addSeparator()
        
        reset_stats_action = QAction("&Reset Statistics", self)
        reset_stats_action.setShortcut("Ctrl+R")
        reset_stats_action.triggered.connect(self.reset_statistics)
        capture_menu.addAction(reset_stats_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        fullscreen_action = QAction("&Fullscreen", self)
        fullscreen_action.setShortcut("F11")
        fullscreen_action.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscreen_action)
        
        view_menu.addSeparator()
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        settings_action = QAction("&Settings", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_toolbar(self):
        """Create toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Interface selector
        toolbar.addWidget(QLabel("Interface:"))
        
        from PyQt6.QtWidgets import QComboBox
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        self.refresh_interfaces()
        toolbar.addWidget(self.interface_combo)
        
        refresh_btn = QPushButton("🔄")
        refresh_btn.setToolTip("Refresh interfaces")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        toolbar.addWidget(refresh_btn)
        
        toolbar.addSeparator()
        
        # Start/Stop buttons
        self.start_btn = QPushButton("▶ Start")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setStyleSheet("QPushButton { padding: 5px 15px; }")
        toolbar.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { padding: 5px 15px; }")
        toolbar.addWidget(self.stop_btn)
        
        toolbar.addSeparator()
        
        # Quick filter buttons
        toolbar.addWidget(QLabel("Quick Filters:"))
        
        http_btn = QPushButton("HTTP/HTTPS")
        http_btn.clicked.connect(lambda: self.apply_quick_filter('http'))
        toolbar.addWidget(http_btn)
        
        dns_btn = QPushButton("DNS")
        dns_btn.clicked.connect(lambda: self.apply_quick_filter('dns'))
        toolbar.addWidget(dns_btn)
        
        clear_filter_btn = QPushButton("Clear Filters")
        clear_filter_btn.clicked.connect(self.clear_filters)
        toolbar.addWidget(clear_filter_btn)
        
    def create_status_bar(self):
        """Create status bar"""
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        # Status labels
        self.status_label = QLabel("Ready")
        self.statusBar.addWidget(self.status_label)
        
        self.statusBar.addPermanentWidget(QLabel("|"))
        
        self.packets_label = QLabel("Packets: 0")
        self.statusBar.addPermanentWidget(self.packets_label)
        
        self.statusBar.addPermanentWidget(QLabel("|"))
        
        self.rate_label = QLabel("Rate: 0 pps")
        self.statusBar.addPermanentWidget(self.rate_label)
        
    def create_dock_widgets(self):
        """Create dockable panels"""
        # Anomaly detection dock
        anomaly_dock = QDockWidget("🚨 Anomalies", self)
        anomaly_dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | 
                                     Qt.DockWidgetArea.RightDockWidgetArea)
        
        from PyQt6.QtWidgets import QListWidget, QListWidgetItem
        
        anomaly_widget = QWidget()
        anomaly_layout = QVBoxLayout(anomaly_widget)
        anomaly_layout.setContentsMargins(5, 5, 5, 5)
        
        # Title and controls
        title_layout = QHBoxLayout()
        title_label = QLabel("Anomaly Detection")
        title_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        title_layout.addWidget(title_label)
        
        clear_btn = QPushButton("Clear")
        clear_btn.setMaximumWidth(60)
        clear_btn.clicked.connect(self.clear_anomalies)
        title_layout.addWidget(clear_btn)
        
        anomaly_layout.addLayout(title_layout)
        
        # Anomaly list
        self.anomaly_list = QListWidget()
        self.anomaly_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                border: 1px solid #3c3c3c;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #2d2d2d;
            }
            QListWidget::item:selected {
                background-color: #094771;
            }
        """)
        anomaly_layout.addWidget(self.anomaly_list)
        
        # Statistics
        self.anomaly_stats_label = QLabel("Total: 0 | Critical: 0 | High: 0 | Medium: 0")
        self.anomaly_stats_label.setStyleSheet("color: #888; font-size: 9pt;")
        anomaly_layout.addWidget(self.anomaly_stats_label)
        
        anomaly_dock.setWidget(anomaly_widget)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, anomaly_dock)
        
        # Track anomaly counts
        self.anomaly_counts = {'critical': 0, 'high': 0, 'medium': 0, 'info': 0}
    
    def clear_anomalies(self):
        """Clear anomaly list"""
        self.anomaly_list.clear()
        self.anomaly_counts = {'critical': 0, 'high': 0, 'medium': 0, 'info': 0}
        self.update_anomaly_stats()
    
    def update_anomaly_stats(self):
        """Update anomaly statistics display"""
        total = sum(self.anomaly_counts.values())
        self.anomaly_stats_label.setText(
            f"Total: {total} | Critical: {self.anomaly_counts['critical']} | "
            f"High: {self.anomaly_counts['high']} | Medium: {self.anomaly_counts['medium']}"
        )
        
    def apply_theme(self):
        """Apply dark theme"""
        theme = DarkTheme(self.settings)
        self.setStyleSheet(theme.get_stylesheet())
        
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        from backend.core.packet_capture import PacketCaptureEngine
        
        self.interface_combo.clear()
        interfaces = PacketCaptureEngine.get_available_interfaces()
        
        for iface_info in interfaces:
            # Get friendly name and GUID
            name = iface_info['name']
            guid = iface_info['guid']
            ip = iface_info['ip']
            iface_type = iface_info['type']
            
            # Add icon based on type
            if iface_type == 'wifi':
                icon = "📡"
            elif iface_type == 'ethernet':
                icon = "🔌"
            else:
                icon = "🌐"
            
            # Display format: "Icon Name (IP)"
            display_text = f"{icon} {name} ({ip})"
            
            # Store GUID as data
            self.interface_combo.addItem(display_text, guid)
        
        # Auto-select best interface
        if interfaces:
            best_guid = PacketCaptureEngine.get_best_interface()
            if best_guid:
                for i in range(self.interface_combo.count()):
                    if self.interface_combo.itemData(i) == best_guid:
                        self.interface_combo.setCurrentIndex(i)
                        break
        
        logger.info(f"Found {len(interfaces)} valid interfaces")
        
    def setup_connections(self):
        """Setup signal/slot connections"""
        # Connect filter panel signals
        self.filters_panel.filter_applied.connect(self.on_filter_applied)
        
        # Connect packet table selection to details panel
        self.packet_table.packet_selected.connect(self.on_packet_selected)
    
    def on_packet_selected(self, packet_info):
        """Handle packet selection"""
        try:
            self.packet_details_panel.set_packet(packet_info)
        except Exception as e:
            logger.error(f"Error displaying packet details: {e}")
        
    def start_capture(self):
        """Start packet capture"""
        if self.is_capturing:
            return
            
        try:
            # Create new session
            self.current_session = self.session_manager.create_session(
                name=f"Capture_{int(time.time())}",
                interface=self.settings.default_interface
            )
            
            # Get selected interface
            selected_interface = self.interface_combo.currentData()
            if not selected_interface:
                selected_interface = self.settings.default_interface
                
            logger.info(f"Starting capture on selected interface: {selected_interface}")
            
            # Initialize capture engine
            self.capture_engine = PacketCaptureEngine(
                interface=selected_interface
            )
            
            # Add callbacks
            self.capture_engine.add_packet_callback(self.on_packet_received)
            self.capture_engine.add_statistics_callback(self.on_statistics_updated)
            
            # Add TLS analyzer callback
            self.tls_analyzer.add_handshake_callback(self.on_tls_handshake)
            
            # Start capture in thread
            import threading
            capture_thread = threading.Thread(target=self._run_capture, daemon=True)
            capture_thread.start()
            
            self.is_capturing = True
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.start_action.setEnabled(False)
            self.stop_action.setEnabled(True)
            
            self.status_label.setText("Capturing...")
            logger.info("Capture started")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture: {e}")
            logger.error(f"Failed to start capture: {e}")
            
    def _run_capture(self):
        """Run capture in separate thread with event loop"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.capture_engine.start())
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            loop.close()
            
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_capturing:
            return
            
        try:
            if self.capture_engine:
                # Stop capture in thread
                import threading
                stop_thread = threading.Thread(target=self._stop_capture_async, daemon=True)
                stop_thread.start()
                
            self.is_capturing = False
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.start_action.setEnabled(True)
            self.stop_action.setEnabled(False)
            
            self.status_label.setText("Stopped")
            logger.info("Capture stopped")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop capture: {e}")
            logger.error(f"Failed to stop capture: {e}")
            
    def _stop_capture_async(self):
        """Stop capture asynchronously"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.capture_engine.stop())
        except Exception as e:
            logger.error(f"Stop capture error: {e}")
        finally:
            loop.close()
            
    def on_packet_received(self, packet_info):
        """Handle received packet"""
        # Apply filters
        if not self.filter_engine.apply_filters(packet_info):
            return
            
        # Update statistics
        self.stats_engine.update(packet_info)
        
        # Check for anomalies
        anomalies = self.anomaly_detector.analyze_packet(packet_info)
        if anomalies:
            self.on_anomalies_detected(anomalies)
        
        # Analyze for TLS handshakes
        if packet_info.get('raw_packet'):
            self.tls_analyzer.analyze_packet(packet_info['raw_packet'])
        
        # Add to packet table
        self.packet_table.add_packet(packet_info)
    
    def on_tls_handshake(self, handshake):
        """Handle completed TLS handshake"""
        try:
            self.tls_panel.add_handshake(handshake.to_dict())
        except Exception as e:
            logger.error(f"Error adding TLS handshake to panel: {e}")
    
    def on_anomalies_detected(self, anomalies):
        """Handle detected anomalies"""
        from PyQt6.QtWidgets import QListWidgetItem
        from PyQt6.QtGui import QColor
        
        for anomaly in anomalies:
            try:
                # Add to anomaly panel
                if hasattr(self, 'anomaly_list'):
                    # Format anomaly text
                    severity = anomaly.get('severity', 'info')
                    anomaly_type = anomaly.get('type', 'unknown')
                    description = anomaly.get('description', 'No description')
                    timestamp = anomaly.get('timestamp', '')
                    
                    # Create list item
                    item_text = f"[{severity.upper()}] {description}"
                    item = QListWidgetItem(item_text)
                    
                    # Color code by severity
                    if severity == 'critical':
                        item.setForeground(QColor('#ff4444'))
                        self.anomaly_counts['critical'] += 1
                    elif severity == 'high':
                        item.setForeground(QColor('#ff8800'))
                        self.anomaly_counts['high'] += 1
                    elif severity == 'medium':
                        item.setForeground(QColor('#ffaa00'))
                        self.anomaly_counts['medium'] += 1
                    else:
                        item.setForeground(QColor('#88ccff'))
                        self.anomaly_counts['info'] += 1
                    
                    # Add to list
                    self.anomaly_list.addItem(item)
                    
                    # Update statistics
                    self.update_anomaly_stats()
                    
                    # Auto-scroll to bottom
                    self.anomaly_list.scrollToBottom()
            except Exception as e:
                logger.error(f"Error adding anomaly to panel: {e}")
        
    def on_statistics_updated(self, stats):
        """Handle statistics update"""
        # Update status bar
        total_packets = stats.get('total_packets', 0)
        pps = stats.get('pps', stats.get('avg_pps', 0))
        
        self.packets_label.setText(f"Packets: {total_packets}")
        self.rate_label.setText(f"Rate: {pps:.0f} pps")
        
        # Get additional statistics from stats engine
        if hasattr(self, 'stats_engine'):
            # Add top IPs and ports to stats
            stats['top_ips'] = self.stats_engine.get_top_ips(10)
            stats['top_ports'] = self.stats_engine.get_top_ports(10)
        
        # Update statistics panel
        self.stats_panel.update_statistics(stats)
        
        # Update graphs
        self.graphs_widget.update_data(stats)
        
    def on_filter_applied(self, filter_config):
        """Handle filter application"""
        logger.info(f"Filter applied: {filter_config}")
        
    def apply_quick_filter(self, filter_type):
        """Apply quick filter"""
        from backend.core.filter_engine import QuickFilters
        
        self.filter_engine.clear_filters()
        
        if filter_type == 'http':
            self.filter_engine.add_filter(QuickFilters.http_https(), "HTTP/HTTPS")
        elif filter_type == 'dns':
            self.filter_engine.add_filter(QuickFilters.dns(), "DNS")
            
        self.status_label.setText(f"Filter applied: {filter_type.upper()}")
        
    def clear_filters(self):
        """Clear all filters"""
        self.filter_engine.clear_filters()
        self.status_label.setText("Filters cleared")
        
    def update_display(self):
        """Update display periodically"""
        if self.is_capturing and self.capture_engine:
            stats = self.capture_engine.get_statistics()
            self.on_statistics_updated(stats)
            
    def reset_statistics(self):
        """Reset all statistics"""
        self.stats_engine.reset()
        self.packet_table.clear()
        self.status_label.setText("Statistics reset")
        
    def new_session(self):
        """Create new session"""
        # Implementation
        pass
        
    def open_session(self):
        """Open existing session"""
        # Implementation
        pass
        
    def save_session(self):
        """Save current session"""
        # Implementation
        pass
        
    def export_csv(self):
        """Export to CSV"""
        filename, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV Files (*.csv)")
        if filename:
            # Implementation
            pass
            
    def export_pcap(self):
        """Export to PCAP"""
        filename, _ = QFileDialog.getSaveFileName(self, "Export PCAP", "", "PCAP Files (*.pcap)")
        if filename:
            # Implementation
            pass
            
    def export_html(self):
        """Export to HTML"""
        filename, _ = QFileDialog.getSaveFileName(self, "Export HTML", "", "HTML Files (*.html)")
        if filename:
            # Implementation
            pass
            
    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
            
    def show_settings(self):
        """Show settings dialog"""
        # Implementation
        pass
        
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About FlowScope",
                         "FlowScope v1.0\n\n"
                         "Professional network traffic analyzer\n"
                         "with advanced protocol analysis and anomaly detection.")
        
    def closeEvent(self, event):
        """Handle window close"""
        if self.is_capturing:
            reply = QMessageBox.question(self, "Confirm Exit",
                                        "Capture is still running. Stop and exit?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_capture()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
