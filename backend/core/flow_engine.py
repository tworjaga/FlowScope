"""
Flow Engine
Connection tracking and flow-based analysis
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import hashlib

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FlowKey:
    """5-tuple flow identifier"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    def reverse(self) -> 'FlowKey':
        """Get reverse flow key"""
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )
    
    def to_string(self) -> str:
        """Convert to string representation"""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"
    
    def hash(self) -> str:
        """Get hash of flow key"""
        s = self.to_string()
        return hashlib.md5(s.encode()).hexdigest()[:16]


@dataclass
class FlowState:
    """Flow state tracking"""
    flow_key: FlowKey
    start_time: datetime
    last_seen: datetime
    
    # Packet counts
    packets_forward: int = 0
    packets_backward: int = 0
    
    # Byte counts
    bytes_forward: int = 0
    bytes_backward: int = 0
    
    # TCP specific
    tcp_state: str = "UNKNOWN"  # SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED
    tcp_flags_seen: Set[str] = field(default_factory=set)
    syn_time: Optional[datetime] = None
    syn_ack_time: Optional[datetime] = None
    established_time: Optional[datetime] = None
    fin_time: Optional[datetime] = None
    
    # RTT estimation
    rtt_samples: List[float] = field(default_factory=list)
    
    # Application layer
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    dns_queries: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)
    
    # Behavioral
    is_long_lived: bool = False
    is_beaconing: bool = False
    beacon_interval: Optional[float] = None
    
    # Metadata
    tags: Set[str] = field(default_factory=set)
    
    @property
    def total_packets(self) -> int:
        return self.packets_forward + self.packets_backward
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_forward + self.bytes_backward
    
    @property
    def duration(self) -> float:
        return (self.last_seen - self.start_time).total_seconds()
    
    @property
    def avg_rtt(self) -> Optional[float]:
        if not self.rtt_samples:
            return None
        return sum(self.rtt_samples) / len(self.rtt_samples)
    
    @property
    def is_bidirectional(self) -> bool:
        return self.packets_backward > 0
    
    @property
    def direction_ratio(self) -> float:
        """Ratio of forward to backward packets"""
        if self.packets_backward == 0:
            return float('inf')
        return self.packets_forward / self.packets_backward


class TCPStateMachine:
    """TCP connection state tracking"""
    
    STATES = {
        'CLOSED': 0,
        'SYN_SENT': 1,
        'SYN_RECEIVED': 2,
        'ESTABLISHED': 3,
        'FIN_WAIT_1': 4,
        'FIN_WAIT_2': 5,
        'CLOSE_WAIT': 6,
        'CLOSING': 7,
        'LAST_ACK': 8,
        'TIME_WAIT': 9
    }
    
    def __init__(self):
        self.state = 'CLOSED'
        
    def process_flags(self, flags: Set[str], direction: str) -> str:
        """Process TCP flags and update state"""
        
        # Check if flags is None or empty
        if not flags:
            return self.state
        
        if 'RST' in flags:
            self.state = 'CLOSED'
            return self.state
        
        if self.state == 'CLOSED':
            if 'SYN' in flags and 'ACK' not in flags:
                self.state = 'SYN_SENT'
        
        elif self.state == 'SYN_SENT':
            if 'SYN' in flags and 'ACK' in flags:
                self.state = 'SYN_RECEIVED'
        
        elif self.state == 'SYN_RECEIVED':
            if 'ACK' in flags and 'SYN' not in flags:
                self.state = 'ESTABLISHED'
        
        elif self.state == 'ESTABLISHED':
            if 'FIN' in flags:
                self.state = 'FIN_WAIT_1' if direction == 'forward' else 'CLOSE_WAIT'
        
        elif self.state == 'FIN_WAIT_1':
            if 'ACK' in flags:
                self.state = 'FIN_WAIT_2'
            if 'FIN' in flags:
                self.state = 'CLOSING'
        
        elif self.state == 'FIN_WAIT_2':
            if 'FIN' in flags:
                self.state = 'TIME_WAIT'
        
        elif self.state == 'CLOSE_WAIT':
            if 'FIN' in flags:
                self.state = 'LAST_ACK'
        
        elif self.state == 'LAST_ACK':
            if 'ACK' in flags:
                self.state = 'CLOSED'
        
        elif self.state == 'TIME_WAIT':
            # Timeout to CLOSED (handled by flow expiration)
            pass
        
        return self.state


class FlowEngine:
    """Flow tracking and management"""
    
    def __init__(self, flow_timeout: int = 300, tcp_timeout: int = 3600):
        self.flows: Dict[FlowKey, FlowState] = {}
        self.flow_timeout = flow_timeout  # seconds
        self.tcp_timeout = tcp_timeout
        
        # Statistics
        self.total_flows = 0
        self.active_flows = 0
        self.expired_flows = 0
        
        # TCP state machines
        self.tcp_machines: Dict[FlowKey, TCPStateMachine] = {}
        
        # Callbacks
        self.new_flow_callbacks = []
        self.flow_update_callbacks = []
        self.flow_expire_callbacks = []
        
    def add_new_flow_callback(self, callback):
        """Add callback for new flows"""
        self.new_flow_callbacks.append(callback)
        
    def add_flow_update_callback(self, callback):
        """Add callback for flow updates"""
        self.flow_update_callbacks.append(callback)
        
    def add_flow_expire_callback(self, callback):
        """Add callback for expired flows"""
        self.flow_expire_callbacks.append(callback)
        
    def process_packet(self, packet_info: Dict) -> Optional[FlowState]:
        """Process packet and update flow state"""
        
        # Extract flow key
        flow_key = self._extract_flow_key(packet_info)
        if not flow_key:
            return None
        
        # Check for existing flow (forward or reverse)
        flow_state = self.flows.get(flow_key)
        reverse_key = flow_key.reverse()
        reverse_flow = self.flows.get(reverse_key)
        
        direction = 'forward'
        
        # Use reverse flow if it exists
        if reverse_flow and not flow_state:
            flow_state = reverse_flow
            flow_key = reverse_key
            direction = 'backward'
        
        # Create new flow if needed
        if not flow_state:
            flow_state = self._create_flow(flow_key, packet_info)
            self.flows[flow_key] = flow_state
            self.total_flows += 1
            self.active_flows += 1
            
            # Notify callbacks
            for callback in self.new_flow_callbacks:
                try:
                    callback(flow_state)
                except Exception as e:
                    logger.error(f"Error in new flow callback: {e}")
        
        # Update flow state
        self._update_flow(flow_state, packet_info, direction)
        
        # Notify update callbacks
        for callback in self.flow_update_callbacks:
            try:
                callback(flow_state)
            except Exception as e:
                logger.error(f"Error in flow update callback: {e}")
        
        return flow_state
    
    def _extract_flow_key(self, packet_info: Dict) -> Optional[FlowKey]:
        """Extract flow key from packet"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol', 'Unknown')
        
        if not src_ip or not dst_ip:
            return None
        
        return FlowKey(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
    
    def _create_flow(self, flow_key: FlowKey, packet_info: Dict) -> FlowState:
        """Create new flow state"""
        timestamp = packet_info.get('timestamp', datetime.now())
        
        flow_state = FlowState(
            flow_key=flow_key,
            start_time=timestamp,
            last_seen=timestamp
        )
        
        # Initialize TCP state machine if TCP
        if flow_key.protocol == 'TCP':
            self.tcp_machines[flow_key] = TCPStateMachine()
        
        return flow_state
    
    def _update_flow(self, flow_state: FlowState, packet_info: Dict, direction: str):
        """Update flow state with packet"""
        timestamp = packet_info.get('timestamp', datetime.now())
        packet_size = packet_info.get('size', 0)
        
        # Update timestamps
        flow_state.last_seen = timestamp
        
        # Update counters
        if direction == 'forward':
            flow_state.packets_forward += 1
            flow_state.bytes_forward += packet_size
        else:
            flow_state.packets_backward += 1
            flow_state.bytes_backward += packet_size
        
        # Update TCP state
        if flow_state.flow_key.protocol == 'TCP':
            self._update_tcp_state(flow_state, packet_info, direction)
        
        # Update application layer info
        self._update_application_layer(flow_state, packet_info)
        
        # Check for long-lived flows
        if flow_state.duration > 3600:  # 1 hour
            flow_state.is_long_lived = True
            flow_state.tags.add('long_lived')
        
        # Detect beaconing
        self._detect_beaconing(flow_state)
    
    def _update_tcp_state(self, flow_state: FlowState, packet_info: Dict, direction: str):
        """Update TCP-specific state"""
        flags = packet_info.get('flags')
        if not flags or flags == 'None':
            return
        
        # Parse flags
        flag_set = set(flags.split('|'))
        flow_state.tcp_flags_seen.update(flag_set)
        
        # Update state machine
        machine = self.tcp_machines.get(flow_state.flow_key)
        if machine:
            old_state = machine.state
            new_state = machine.process_flags(flag_set, direction)
            flow_state.tcp_state = new_state
            
            # Track handshake timing
            if old_state == 'CLOSED' and new_state == 'SYN_SENT':
                flow_state.syn_time = packet_info.get('timestamp')
            elif old_state == 'SYN_SENT' and new_state == 'SYN_RECEIVED':
                flow_state.syn_ack_time = packet_info.get('timestamp')
            elif old_state == 'SYN_RECEIVED' and new_state == 'ESTABLISHED':
                flow_state.established_time = packet_info.get('timestamp')
                # Calculate RTT
                if flow_state.syn_time and flow_state.syn_ack_time:
                    rtt = (flow_state.syn_ack_time - flow_state.syn_time).total_seconds()
                    flow_state.rtt_samples.append(rtt)
            elif 'FIN' in flag_set and not flow_state.fin_time:
                flow_state.fin_time = packet_info.get('timestamp')
    
    def _update_application_layer(self, flow_state: FlowState, packet_info: Dict):
        """Update application layer information"""
        
        # TLS/SNI
        if 'tls' in packet_info:
            tls_info = packet_info['tls']
            if 'sni' in tls_info and not flow_state.tls_sni:
                flow_state.tls_sni = tls_info['sni']
                flow_state.tags.add('tls')
            if 'version' in tls_info and not flow_state.tls_version:
                flow_state.tls_version = tls_info['version']
        
        # DNS
        dns_query = packet_info.get('dns_query')
        if dns_query and dns_query not in flow_state.dns_queries:
            flow_state.dns_queries.append(dns_query)
            flow_state.tags.add('dns')
        
        # HTTP
        if 'http' in packet_info:
            http_info = packet_info['http']
            host = http_info.get('host')
            if host and host not in flow_state.http_hosts:
                flow_state.http_hosts.append(host)
                flow_state.tags.add('http')
    
    def _detect_beaconing(self, flow_state: FlowState):
        """Detect beaconing behavior"""
        if flow_state.total_packets < 10:
            return
        
        # Simple beaconing detection based on packet timing
        # More sophisticated detection would analyze inter-packet intervals
        if flow_state.duration > 300 and flow_state.total_packets > 20:
            avg_interval = flow_state.duration / flow_state.total_packets
            if 5 < avg_interval < 300:  # Between 5 seconds and 5 minutes
                flow_state.is_beaconing = True
                flow_state.beacon_interval = avg_interval
                flow_state.tags.add('beaconing')
    
    def expire_flows(self, current_time: Optional[datetime] = None):
        """Expire old flows"""
        if current_time is None:
            current_time = datetime.now()
        
        expired_keys = []
        
        for flow_key, flow_state in self.flows.items():
            timeout = self.tcp_timeout if flow_key.protocol == 'TCP' else self.flow_timeout
            age = (current_time - flow_state.last_seen).total_seconds()
            
            if age > timeout:
                expired_keys.append(flow_key)
        
        # Remove expired flows
        for flow_key in expired_keys:
            flow_state = self.flows.pop(flow_key)
            self.expired_flows += 1
            self.active_flows -= 1
            
            # Remove TCP state machine
            if flow_key in self.tcp_machines:
                del self.tcp_machines[flow_key]
            
            # Notify callbacks
            for callback in self.flow_expire_callbacks:
                try:
                    callback(flow_state)
                except Exception as e:
                    logger.error(f"Error in flow expire callback: {e}")
        
        if expired_keys:
            logger.info(f"Expired {len(expired_keys)} flows")
    
    def get_flow(self, flow_key: FlowKey) -> Optional[FlowState]:
        """Get flow by key"""
        return self.flows.get(flow_key)
    
    def get_active_flows(self) -> List[FlowState]:
        """Get all active flows"""
        return list(self.flows.values())
    
    def get_flows_by_ip(self, ip: str) -> List[FlowState]:
        """Get flows involving specific IP"""
        return [
            flow for flow in self.flows.values()
            if flow.flow_key.src_ip == ip or flow.flow_key.dst_ip == ip
        ]
    
    def get_flows_by_port(self, port: int) -> List[FlowState]:
        """Get flows involving specific port"""
        return [
            flow for flow in self.flows.values()
            if flow.flow_key.src_port == port or flow.flow_key.dst_port == port
        ]
    
    def get_flows_by_protocol(self, protocol: str) -> List[FlowState]:
        """Get flows by protocol"""
        return [
            flow for flow in self.flows.values()
            if flow.flow_key.protocol == protocol
        ]
    
    def get_flows_by_tag(self, tag: str) -> List[FlowState]:
        """Get flows with specific tag"""
        return [
            flow for flow in self.flows.values()
            if tag in flow.tags
        ]
    
    def get_statistics(self) -> Dict:
        """Get flow statistics"""
        return {
            'total_flows': self.total_flows,
            'active_flows': self.active_flows,
            'expired_flows': self.expired_flows,
            'tcp_flows': len([f for f in self.flows.values() if f.flow_key.protocol == 'TCP']),
            'udp_flows': len([f for f in self.flows.values() if f.flow_key.protocol == 'UDP']),
            'long_lived_flows': len([f for f in self.flows.values() if f.is_long_lived]),
            'beaconing_flows': len([f for f in self.flows.values() if f.is_beaconing]),
            'tls_flows': len([f for f in self.flows.values() if 'tls' in f.tags]),
            'dns_flows': len([f for f in self.flows.values() if 'dns' in f.tags])
        }
    
    def reset(self):
        """Reset all flows"""
        self.flows.clear()
        self.tcp_machines.clear()
        self.total_flows = 0
        self.active_flows = 0
        self.expired_flows = 0
        logger.info("Flow engine reset")
