"""
Graphs Widget
Real-time traffic visualization
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTabWidget
from PyQt6.QtCore import Qt
import pyqtgraph as pg
from collections import deque
from typing import Dict, Any


class GraphsWidget(QWidget):
    """Real-time graphs widget"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
        # Data buffers
        self.time_data = deque(maxlen=100)
        self.pps_data = deque(maxlen=100)
        self.bps_data = deque(maxlen=100)
        
    def setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        
        # Create tab widget for different graphs
        tabs = QTabWidget()
        
        # Traffic graph
        self.traffic_widget = pg.PlotWidget()
        self.traffic_widget.setBackground('#1e1e1e')
        self.traffic_widget.setLabel('left', 'Packets/sec', color='#d4d4d4')
        self.traffic_widget.setLabel('bottom', 'Time', color='#d4d4d4')
        self.traffic_widget.showGrid(x=True, y=True, alpha=0.3)
        
        self.pps_curve = self.traffic_widget.plot(pen=pg.mkPen(color='#007acc', width=2))
        
        tabs.addTab(self.traffic_widget, "📈 Traffic Rate")
        
        # Bandwidth graph
        self.bandwidth_widget = pg.PlotWidget()
        self.bandwidth_widget.setBackground('#1e1e1e')
        self.bandwidth_widget.setLabel('left', 'Bytes/sec', color='#d4d4d4')
        self.bandwidth_widget.setLabel('bottom', 'Time', color='#d4d4d4')
        self.bandwidth_widget.showGrid(x=True, y=True, alpha=0.3)
        
        self.bps_curve = self.bandwidth_widget.plot(pen=pg.mkPen(color='#4ec9b0', width=2))
        
        tabs.addTab(self.bandwidth_widget, "📊 Bandwidth")
        
        # Protocol distribution (placeholder)
        self.protocol_widget = pg.PlotWidget()
        self.protocol_widget.setBackground('#1e1e1e')
        tabs.addTab(self.protocol_widget, "🥧 Protocol Distribution")
        
        layout.addWidget(tabs)
        
    def update_data(self, stats: Dict[str, Any]):
        """Update graph data"""
        import time
        
        current_time = time.time()
        pps = stats.get('pps', 0)
        bps = stats.get('bps', 0)
        
        # Add data points
        self.time_data.append(current_time)
        self.pps_data.append(pps)
        self.bps_data.append(bps)
        
        # Update curves
        if len(self.time_data) > 1:
            # Normalize time to start from 0
            time_normalized = [t - self.time_data[0] for t in self.time_data]
            
            self.pps_curve.setData(time_normalized, list(self.pps_data))
            self.bps_curve.setData(time_normalized, list(self.bps_data))
            
    def clear(self):
        """Clear all graphs"""
        self.time_data.clear()
        self.pps_data.clear()
        self.bps_data.clear()
        self.pps_curve.setData([], [])
        self.bps_curve.setData([], [])
