"""
Statistics Engine
Real-time traffic statistics and metrics calculation
"""

import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class StatisticsEngine:
    """Real-time statistics calculation"""
    
    def __init__(self, window_size: int = 60):
        self.window_size = window_size  # seconds
        
        # Time-series data
        self.packet_timeline = deque(maxlen=1000)
        self.byte_timeline = deque(maxlen=1000)
        
        # Protocol statistics
        self.protocol_packets = defaultdict(int)
        self.protocol_bytes = defaultdict(int)
        
        # IP statistics
        self.ip_packets = defaultdict(int)
        self.ip_bytes = defaultdict(int)
        
        # Port statistics
        self.port_packets = defaultdict(int)
        self.port_bytes = defaultdict(int)
        
        # Domain statistics (DNS/SNI)
        self.domain_queries = defaultdict(int)
        
        # Connection tracking
        self.connections = {}
        
        # Traffic spikes
        self.spike_threshold = 1000  # packets per second
        self.spikes = []
        
        # Idle/active periods
        self.idle_threshold = 10  # packets per second
        self.activity_periods = []
        
        # Rate calculations
        self.last_update = time.time()
        self.packets_since_update = 0
        self.bytes_since_update = 0
        
    def update(self, packet_info: Dict[str, Any]):
        """Update statistics with new packet"""
        current_time = time.time()
        timestamp = packet_info.get('timestamp', datetime.now())
        
        # Update counters
        self.packets_since_update += 1
        packet_size = packet_info.get('size', 0)
        self.bytes_since_update += packet_size
        
        # Update protocol stats
        protocol = packet_info.get('protocol', 'Unknown')
        self.protocol_packets[protocol] += 1
        self.protocol_bytes[protocol] += packet_size
        
        # Update IP stats
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        if src_ip:
            self.ip_packets[src_ip] += 1
            self.ip_bytes[src_ip] += packet_size
            
        if dst_ip:
            self.ip_packets[dst_ip] += 1
            self.ip_bytes[dst_ip] += packet_size
            
        # Update port stats
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        if src_port:
            self.port_packets[src_port] += 1
            self.port_bytes[src_port] += packet_size
            
        if dst_port:
            self.port_packets[dst_port] += 1
            self.port_bytes[dst_port] += packet_size
            
        # Update domain stats
        dns_query = packet_info.get('dns_query')
        if dns_query:
            self.domain_queries[dns_query] += 1
            
        # Track connections
        if src_ip and dst_ip and src_port and dst_port:
            conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            if conn_key not in self.connections:
                self.connections[conn_key] = {
                    'start_time': timestamp,
                    'packets': 0,
                    'bytes': 0,
                    'protocol': protocol
                }
            self.connections[conn_key]['packets'] += 1
            self.connections[conn_key]['bytes'] += packet_size
            self.connections[conn_key]['last_seen'] = timestamp
            
        # Update timeline (every second)
        if current_time - self.last_update >= 1.0:
            pps = self.packets_since_update / (current_time - self.last_update)
            bps = self.bytes_since_update / (current_time - self.last_update)
            
            self.packet_timeline.append({
                'timestamp': datetime.now(),
                'pps': pps,
                'packets': self.packets_since_update
            })
            
            self.byte_timeline.append({
                'timestamp': datetime.now(),
                'bps': bps,
                'bytes': self.bytes_since_update
            })
            
            # Detect spikes
            if pps > self.spike_threshold:
                self.spikes.append({
                    'timestamp': datetime.now(),
                    'pps': pps,
                    'bps': bps
                })
                logger.warning(f"Traffic spike detected: {pps:.0f} pps")
                
            # Track activity
            if pps < self.idle_threshold:
                activity = 'idle'
            else:
                activity = 'active'
                
            if not self.activity_periods or self.activity_periods[-1]['type'] != activity:
                self.activity_periods.append({
                    'type': activity,
                    'start': datetime.now(),
                    'end': None
                })
            else:
                self.activity_periods[-1]['end'] = datetime.now()
                
            # Reset counters
            self.packets_since_update = 0
            self.bytes_since_update = 0
            self.last_update = current_time
            
    def get_top_ips(self, count: int = 10, by: str = 'bytes') -> List[Tuple[str, int]]:
        """Get top IPs by traffic"""
        if by == 'bytes':
            data = self.ip_bytes
        else:
            data = self.ip_packets
            
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:count]
        
    def get_top_ports(self, count: int = 10, by: str = 'bytes') -> List[Tuple[int, int]]:
        """Get top ports by traffic"""
        if by == 'bytes':
            data = self.port_bytes
        else:
            data = self.port_packets
            
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:count]
        
    def get_top_domains(self, count: int = 10) -> List[Tuple[str, int]]:
        """Get top domains by query count"""
        return sorted(self.domain_queries.items(), key=lambda x: x[1], reverse=True)[:count]
        
    def get_protocol_distribution(self) -> Dict[str, Dict[str, int]]:
        """Get protocol distribution"""
        return {
            'packets': dict(self.protocol_packets),
            'bytes': dict(self.protocol_bytes)
        }
        
    def get_current_rates(self) -> Dict[str, float]:
        """Get current PPS and BPS"""
        if not self.packet_timeline:
            return {'pps': 0.0, 'bps': 0.0}
            
        latest = self.packet_timeline[-1]
        latest_bytes = self.byte_timeline[-1]
        
        return {
            'pps': latest['pps'],
            'bps': latest_bytes['bps']
        }
        
    def get_average_rates(self, window: int = None) -> Dict[str, float]:
        """Get average rates over time window"""
        if window is None:
            window = self.window_size
            
        cutoff_time = datetime.now() - timedelta(seconds=window)
        
        # Filter timeline data
        recent_packets = [p for p in self.packet_timeline if p['timestamp'] >= cutoff_time]
        recent_bytes = [b for b in self.byte_timeline if b['timestamp'] >= cutoff_time]
        
        if not recent_packets:
            return {'avg_pps': 0.0, 'avg_bps': 0.0}
            
        avg_pps = sum(p['pps'] for p in recent_packets) / len(recent_packets)
        avg_bps = sum(b['bps'] for b in recent_bytes) / len(recent_bytes)
        
        return {
            'avg_pps': avg_pps,
            'avg_bps': avg_bps
        }
        
    def get_traffic_histogram(self, bins: int = 20) -> Dict[str, List]:
        """Get traffic histogram data"""
        if not self.packet_timeline:
            return {'timestamps': [], 'pps': [], 'bps': []}
            
        # Get recent data
        recent_packets = list(self.packet_timeline)[-bins:]
        recent_bytes = list(self.byte_timeline)[-bins:]
        
        return {
            'timestamps': [p['timestamp'] for p in recent_packets],
            'pps': [p['pps'] for p in recent_packets],
            'bps': [b['bps'] for b in recent_bytes]
        }
        
    def get_spikes(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent traffic spikes"""
        return self.spikes[-count:]
        
    def get_activity_periods(self) -> List[Dict[str, Any]]:
        """Get idle/active periods"""
        return self.activity_periods
        
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        active_connections = sum(1 for c in self.connections.values() 
                                if (datetime.now() - c['last_seen']).seconds < 60)
        
        return {
            'total_connections': len(self.connections),
            'active_connections': active_connections,
            'top_connections': sorted(
                self.connections.items(),
                key=lambda x: x[1]['bytes'],
                reverse=True
            )[:10]
        }
        
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive statistics summary"""
        rates = self.get_current_rates()
        avg_rates = self.get_average_rates()
        
        return {
            'current': {
                'pps': rates['pps'],
                'bps': rates['bps']
            },
            'average': {
                'pps': avg_rates['avg_pps'],
                'bps': avg_rates['avg_bps']
            },
            'protocols': self.get_protocol_distribution(),
            'top_ips': self.get_top_ips(10),
            'top_ports': self.get_top_ports(10),
            'top_domains': self.get_top_domains(10),
            'connections': self.get_connection_stats(),
            'spikes': len(self.spikes),
            'activity_periods': len(self.activity_periods)
        }
        
    def reset(self):
        """Reset all statistics"""
        self.packet_timeline.clear()
        self.byte_timeline.clear()
        self.protocol_packets.clear()
        self.protocol_bytes.clear()
        self.ip_packets.clear()
        self.ip_bytes.clear()
        self.port_packets.clear()
        self.port_bytes.clear()
        self.domain_queries.clear()
        self.connections.clear()
        self.spikes.clear()
        self.activity_periods.clear()
        self.last_update = time.time()
        self.packets_since_update = 0
        self.bytes_since_update = 0
        logger.info("Statistics reset")


class BandwidthMonitor:
    """Monitor bandwidth usage"""
    
    def __init__(self):
        self.samples = deque(maxlen=3600)  # 1 hour of samples
        
    def add_sample(self, bytes_count: int, timestamp: datetime = None):
        """Add bandwidth sample"""
        if timestamp is None:
            timestamp = datetime.now()
            
        self.samples.append({
            'timestamp': timestamp,
            'bytes': bytes_count
        })
        
    def get_bandwidth(self, window: int = 60) -> float:
        """Get bandwidth in bytes per second"""
        cutoff = datetime.now() - timedelta(seconds=window)
        recent = [s for s in self.samples if s['timestamp'] >= cutoff]
        
        if len(recent) < 2:
            return 0.0
            
        total_bytes = sum(s['bytes'] for s in recent)
        time_span = (recent[-1]['timestamp'] - recent[0]['timestamp']).total_seconds()
        
        return total_bytes / time_span if time_span > 0 else 0.0
        
    def get_peak_bandwidth(self, window: int = 3600) -> float:
        """Get peak bandwidth"""
        cutoff = datetime.now() - timedelta(seconds=window)
        recent = [s for s in self.samples if s['timestamp'] >= cutoff]
        
        if not recent:
            return 0.0
            
        return max(s['bytes'] for s in recent)
