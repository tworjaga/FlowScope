"""
Investigation Workspace
Context-rich investigation interface for security analysts
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QTextEdit, QLabel,
    QPushButton, QLineEdit, QComboBox, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QGroupBox, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class InvestigationWorkspace(QWidget):
    """Investigation workspace with context panels"""
    
    entity_selected = pyqtSignal(str, str)  # entity_type, entity_value
    filter_requested = pyqtSignal(str)  # filter_expression
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_entity = None
        self.current_entity_type = None
        self.bookmarks = []
        self.notes = {}
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Top toolbar
        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel: Entity selector and context
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Center panel: Timeline and related data
        center_panel = self.create_center_panel()
        splitter.addWidget(center_panel)
        
        # Right panel: Notes and bookmarks
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setStretchFactor(2, 1)
        
        layout.addWidget(splitter)
        
    def create_toolbar(self) -> QWidget:
        """Create investigation toolbar"""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Entity input
        layout.addWidget(QLabel("Investigate:"))
        
        self.entity_type_combo = QComboBox()
        self.entity_type_combo.addItems(["IP Address", "Domain", "Port", "Flow"])
        layout.addWidget(self.entity_type_combo)
        
        self.entity_input = QLineEdit()
        self.entity_input.setPlaceholderText("Enter IP, domain, port, or flow ID...")
        self.entity_input.returnPressed.connect(self.investigate_entity)
        layout.addWidget(self.entity_input)
        
        investigate_btn = QPushButton("🔍 Investigate")
        investigate_btn.clicked.connect(self.investigate_entity)
        layout.addWidget(investigate_btn)
        
        layout.addStretch()
        
        # Quick actions
        bookmark_btn = QPushButton("⭐ Bookmark")
        bookmark_btn.clicked.connect(self.add_bookmark)
        layout.addWidget(bookmark_btn)
        
        note_btn = QPushButton("📝 Add Note")
        note_btn.clicked.connect(self.add_note)
        layout.addWidget(note_btn)
        
        export_btn = QPushButton("💾 Export Workspace")
        export_btn.clicked.connect(self.export_workspace)
        layout.addWidget(export_btn)
        
        return toolbar
        
    def create_left_panel(self) -> QWidget:
        """Create left context panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Entity info
        info_group = QGroupBox("Entity Information")
        info_layout = QVBoxLayout(info_group)
        
        self.entity_label = QLabel("No entity selected")
        self.entity_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        info_layout.addWidget(self.entity_label)
        
        self.entity_details = QTextEdit()
        self.entity_details.setReadOnly(True)
        self.entity_details.setMaximumHeight(150)
        info_layout.addWidget(self.entity_details)
        
        layout.addWidget(info_group)
        
        # Quick stats
        stats_group = QGroupBox("Quick Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(2)
        self.stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self.stats_table.horizontalHeader().setStretchLastSection(True)
        self.stats_table.setMaximumHeight(200)
        stats_layout.addWidget(self.stats_table)
        
        layout.addWidget(stats_group)
        
        # Related entities
        related_group = QGroupBox("Related Entities")
        related_layout = QVBoxLayout(related_group)
        
        self.related_tree = QTreeWidget()
        self.related_tree.setHeaderLabels(["Type", "Value", "Count"])
        self.related_tree.itemClicked.connect(self.on_related_entity_clicked)
        related_layout.addWidget(self.related_tree)
        
        layout.addWidget(related_group)
        
        layout.addStretch()
        
        return panel
        
    def create_center_panel(self) -> QWidget:
        """Create center timeline panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Tabs for different views
        tabs = QTabWidget()
        
        # Timeline tab
        timeline_tab = self.create_timeline_tab()
        tabs.addTab(timeline_tab, "📅 Timeline")
        
        # DNS tab
        dns_tab = self.create_dns_tab()
        tabs.addTab(dns_tab, "🌐 DNS Queries")
        
        # TLS tab
        tls_tab = self.create_tls_tab()
        tabs.addTab(tls_tab, "🔒 TLS Connections")
        
        # Flows tab
        flows_tab = self.create_flows_tab()
        tabs.addTab(flows_tab, "🔄 Flows")
        
        # Anomalies tab
        anomalies_tab = self.create_anomalies_tab()
        tabs.addTab(anomalies_tab, "⚠️ Anomalies")
        
        layout.addWidget(tabs)
        
        return panel
        
    def create_timeline_tab(self) -> QWidget:
        """Create timeline view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Timeline controls
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Time Range:"))
        
        self.time_range_combo = QComboBox()
        self.time_range_combo.addItems([
            "Last 5 minutes",
            "Last 15 minutes",
            "Last hour",
            "Last 24 hours",
            "All time"
        ])
        self.time_range_combo.currentTextChanged.connect(self.update_timeline)
        controls.addWidget(self.time_range_combo)
        
        controls.addStretch()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.update_timeline)
        controls.addWidget(refresh_btn)
        
        layout.addLayout(controls)
        
        # Timeline table
        self.timeline_table = QTableWidget()
        self.timeline_table.setColumnCount(5)
        self.timeline_table.setHorizontalHeaderLabels([
            "Timestamp", "Event", "Source", "Destination", "Details"
        ])
        self.timeline_table.horizontalHeader().setStretchLastSection(True)
        self.timeline_table.itemDoubleClicked.connect(self.on_timeline_item_clicked)
        layout.addWidget(self.timeline_table)
        
        return widget
        
    def create_dns_tab(self) -> QWidget:
        """Create DNS queries view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(4)
        self.dns_table.setHorizontalHeaderLabels([
            "Timestamp", "Query", "Response", "Count"
        ])
        self.dns_table.horizontalHeader().setStretchLastSection(True)
        self.dns_table.itemDoubleClicked.connect(self.on_dns_item_clicked)
        layout.addWidget(self.dns_table)
        
        return widget
        
    def create_tls_tab(self) -> QWidget:
        """Create TLS connections view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.tls_table = QTableWidget()
        self.tls_table.setColumnCount(5)
        self.tls_table.setHorizontalHeaderLabels([
            "Timestamp", "SNI", "Version", "Cipher", "Certificate"
        ])
        self.tls_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.tls_table)
        
        return widget
        
    def create_flows_tab(self) -> QWidget:
        """Create flows view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.flows_table = QTableWidget()
        self.flows_table.setColumnCount(7)
        self.flows_table.setHorizontalHeaderLabels([
            "Start", "Duration", "Source", "Destination", "Protocol", "Bytes", "State"
        ])
        self.flows_table.horizontalHeader().setStretchLastSection(True)
        self.flows_table.itemDoubleClicked.connect(self.on_flow_item_clicked)
        layout.addWidget(self.flows_table)
        
        return widget
        
    def create_anomalies_tab(self) -> QWidget:
        """Create anomalies view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(5)
        self.anomalies_table.setHorizontalHeaderLabels([
            "Timestamp", "Severity", "Category", "Title", "Confidence"
        ])
        self.anomalies_table.horizontalHeader().setStretchLastSection(True)
        self.anomalies_table.itemDoubleClicked.connect(self.on_anomaly_item_clicked)
        layout.addWidget(self.anomalies_table)
        
        return widget
        
    def create_right_panel(self) -> QWidget:
        """Create right notes/bookmarks panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Notes section
        notes_group = QGroupBox("Investigation Notes")
        notes_layout = QVBoxLayout(notes_group)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Add investigation notes here...")
        notes_layout.addWidget(self.notes_edit)
        
        save_note_btn = QPushButton("💾 Save Note")
        save_note_btn.clicked.connect(self.save_note)
        notes_layout.addWidget(save_note_btn)
        
        layout.addWidget(notes_group)
        
        # Bookmarks section
        bookmarks_group = QGroupBox("Bookmarks")
        bookmarks_layout = QVBoxLayout(bookmarks_group)
        
        self.bookmarks_list = QTreeWidget()
        self.bookmarks_list.setHeaderLabels(["Entity", "Timestamp"])
        self.bookmarks_list.itemDoubleClicked.connect(self.on_bookmark_clicked)
        bookmarks_layout.addWidget(self.bookmarks_list)
        
        clear_bookmarks_btn = QPushButton("🗑️ Clear All")
        clear_bookmarks_btn.clicked.connect(self.clear_bookmarks)
        bookmarks_layout.addWidget(clear_bookmarks_btn)
        
        layout.addWidget(bookmarks_group)
        
        return panel
        
    def investigate_entity(self):
        """Start investigating an entity"""
        entity_type = self.entity_type_combo.currentText()
        entity_value = self.entity_input.text().strip()
        
        if not entity_value:
            return
        
        self.current_entity = entity_value
        self.current_entity_type = entity_type
        
        # Update UI
        self.entity_label.setText(f"{entity_type}: {entity_value}")
        
        # Emit signal
        self.entity_selected.emit(entity_type, entity_value)
        
        # Update all panels
        self.update_entity_details()
        self.update_quick_stats()
        self.update_related_entities()
        self.update_timeline()
        self.update_dns_queries()
        self.update_tls_connections()
        self.update_flows()
        self.update_anomalies()
        
        logger.info(f"Investigating {entity_type}: {entity_value}")
        
    def update_entity_details(self):
        """Update entity details"""
        if not self.current_entity:
            return
        
        # This would be populated with real data from the backend
        details = f"""
Entity Type: {self.current_entity_type}
Value: {self.current_entity}
First Seen: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Last Seen: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Status: Active
        """
        
        self.entity_details.setText(details.strip())
        
    def update_quick_stats(self):
        """Update quick statistics"""
        self.stats_table.setRowCount(0)
        
        # Example stats (would be real data)
        stats = [
            ("Total Flows", "42"),
            ("Total Bytes", "1.2 MB"),
            ("DNS Queries", "15"),
            ("TLS Connections", "8"),
            ("Anomalies", "2")
        ]
        
        for metric, value in stats:
            row = self.stats_table.rowCount()
            self.stats_table.insertRow(row)
            self.stats_table.setItem(row, 0, QTableWidgetItem(metric))
            self.stats_table.setItem(row, 1, QTableWidgetItem(value))
        
    def update_related_entities(self):
        """Update related entities tree"""
        self.related_tree.clear()
        
        # Example related entities (would be real data)
        # IPs
        ips_item = QTreeWidgetItem(["IPs", "", ""])
        self.related_tree.addTopLevelItem(ips_item)
        
        ip1 = QTreeWidgetItem(["", "192.168.1.100", "25"])
        ips_item.addChild(ip1)
        
        # Domains
        domains_item = QTreeWidgetItem(["Domains", "", ""])
        self.related_tree.addTopLevelItem(domains_item)
        
        domain1 = QTreeWidgetItem(["", "example.com", "10"])
        domains_item.addChild(domain1)
        
        self.related_tree.expandAll()
        
    def update_timeline(self):
        """Update timeline view"""
        self.timeline_table.setRowCount(0)
        
        # Example timeline events (would be real data)
        events = [
            (datetime.now(), "DNS Query", "192.168.1.100", "8.8.8.8", "example.com"),
            (datetime.now(), "TLS Handshake", "192.168.1.100", "93.184.216.34", "SNI: example.com"),
        ]
        
        for timestamp, event, src, dst, details in events:
            row = self.timeline_table.rowCount()
            self.timeline_table.insertRow(row)
            self.timeline_table.setItem(row, 0, QTableWidgetItem(timestamp.strftime('%H:%M:%S')))
            self.timeline_table.setItem(row, 1, QTableWidgetItem(event))
            self.timeline_table.setItem(row, 2, QTableWidgetItem(src))
            self.timeline_table.setItem(row, 3, QTableWidgetItem(dst))
            self.timeline_table.setItem(row, 4, QTableWidgetItem(details))
        
    def update_dns_queries(self):
        """Update DNS queries view"""
        self.dns_table.setRowCount(0)
        # Would be populated with real data
        
    def update_tls_connections(self):
        """Update TLS connections view"""
        self.tls_table.setRowCount(0)
        # Would be populated with real data
        
    def update_flows(self):
        """Update flows view"""
        self.flows_table.setRowCount(0)
        # Would be populated with real data
        
    def update_anomalies(self):
        """Update anomalies view"""
        self.anomalies_table.setRowCount(0)
        # Would be populated with real data
        
    def add_bookmark(self):
        """Add current entity to bookmarks"""
        if not self.current_entity:
            return
        
        bookmark = {
            'entity_type': self.current_entity_type,
            'entity_value': self.current_entity,
            'timestamp': datetime.now()
        }
        
        self.bookmarks.append(bookmark)
        
        # Update bookmarks list
        item = QTreeWidgetItem([
            f"{self.current_entity_type}: {self.current_entity}",
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ])
        self.bookmarks_list.addTopLevelItem(item)
        
        logger.info(f"Bookmarked: {self.current_entity}")
        
    def add_note(self):
        """Add note for current entity"""
        if not self.current_entity:
            return
        
        # Focus notes editor
        self.notes_edit.setFocus()
        
    def save_note(self):
        """Save current note"""
        if not self.current_entity:
            return
        
        note_text = self.notes_edit.toPlainText()
        if not note_text:
            return
        
        self.notes[self.current_entity] = {
            'text': note_text,
            'timestamp': datetime.now()
        }
        
        logger.info(f"Saved note for: {self.current_entity}")
        
    def clear_bookmarks(self):
        """Clear all bookmarks"""
        self.bookmarks.clear()
        self.bookmarks_list.clear()
        logger.info("Cleared all bookmarks")
        
    def export_workspace(self):
        """Export workspace to file"""
        # Would export bookmarks, notes, and current investigation state
        logger.info("Exporting workspace...")
        
    def on_related_entity_clicked(self, item, column):
        """Handle related entity click"""
        if item.parent():  # Is a child item
            entity_value = item.text(1)
            if entity_value:
                self.entity_input.setText(entity_value)
                self.investigate_entity()
        
    def on_timeline_item_clicked(self, item):
        """Handle timeline item double-click"""
        # Could show detailed packet view
        pass
        
    def on_dns_item_clicked(self, item):
        """Handle DNS item double-click"""
        # Could investigate domain
        pass
        
    def on_flow_item_clicked(self, item):
        """Handle flow item double-click"""
        # Could show flow details
        pass
        
    def on_anomaly_item_clicked(self, item):
        """Handle anomaly item double-click"""
        # Could show anomaly details with explanation
        pass
        
    def on_bookmark_clicked(self, item, column):
        """Handle bookmark double-click"""
        entity_text = item.text(0)
        # Parse entity type and value
        if ": " in entity_text:
            entity_type, entity_value = entity_text.split(": ", 1)
            self.entity_type_combo.setCurrentText(entity_type)
            self.entity_input.setText(entity_value)
            self.investigate_entity()
