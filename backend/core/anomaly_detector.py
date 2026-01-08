"""
Anomaly Detection Engine
Detects suspicious network behavior and anomalies
"""

import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import math

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Network anomaly detection system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # DNS anomaly detection
        self.dns_queries = defaultdict(lambda: deque(maxlen=1000))
        self.dns_threshold = self.config.get('dns_threshold', 100)  # queries per minute
        
        # Port scanning detection
        self.port_scans = defaultdict(lambda: {'ports': set(), 'last_seen': None, 'first_seen': None})
        self.suspicious_ports = set(self.config.get('suspicious_ports', 
            [22, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 5432, 27017, 6379]))
        
        # Beaconing detection (C2 communication)
        self.beaconing_data = defaultdict(lambda: deque(maxlen=100))
        self.beaconing_threshold = self.config.get('beaconing_threshold', 10)
        
        # Rate limiting
        self.rate_limits = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'reset_time': time.time()})
        self.pps_limit = self.config.get('pps_limit', 1000)
        self.bps_limit = self.config.get('bps_limit', 10485760)  # 10 MB/s
        
        # DDoS detection
        self.connection_attempts = defaultdict(lambda: deque(maxlen=1000))
        self.syn_flood_threshold = self.config.get('syn_flood_threshold', 100)
        
        # Unusual SNI detection
        self.sni_patterns = defaultdict(int)
        self.sni_threshold = self.config.get('sni_threshold', 5)
        
        # VPN/Proxy detection
        self.vpn_indicators = set()
        self.proxy_indicators = set()
        
        # DNS over HTTPS detection
        self.doh_servers = {
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '8.8.8.8', '8.8.4.4',  # Google
            '9.9.9.9',             # Quad9
            '208.67.222.222', '208.67.220.220'  # OpenDNS
        }
        
        # Data exfiltration detection
        self.upload_data = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'start_time': time.time()})
        self.exfil_threshold = self.config.get('exfil_threshold', 10485760)  # 10 MB
        
        # Brute force detection
        self.failed_auth = defaultdict(lambda: deque(maxlen=100))
        self.brute_force_threshold = self.config.get('brute_force_threshold', 10)
        
        # Malware communication patterns
        self.malware_ips = set()  # Known malicious IPs
        self.suspicious_user_agents = set()
        
        # Geo-location anomalies
        self.geo_anomalies = defaultdict(set)
        
        # Protocol anomalies
        self.protocol_violations = defaultdict(int)
        
        # Anomaly log
        self.anomalies = deque(maxlen=10000)  # Increased buffer
        
        # Anomaly callbacks
        self.anomaly_callbacks = []
        
    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze packet for anomalies"""
        anomalies = []
        
        # DNS anomaly detection
        dns_anomaly = self._check_dns_anomaly(packet_info)
        if dns_anomaly:
            anomalies.append(dns_anomaly)
            
        # Port scanning detection
        port_scan = self._check_port_scan(packet_info)
        if port_scan:
            anomalies.append(port_scan)
            
        # Suspicious port detection
        suspicious_port = self._check_suspicious_port(packet_info)
        if suspicious_port:
            anomalies.append(suspicious_port)
            
        # Beaconing detection
        beaconing = self._check_beaconing(packet_info)
        if beaconing:
            anomalies.append(beaconing)
            
        # Rate limit detection
        rate_limit = self._check_rate_limit(packet_info)
        if rate_limit:
            anomalies.append(rate_limit)
            
        # Unusual SNI detection
        sni_anomaly = self._check_unusual_sni(packet_info)
        if sni_anomaly:
            anomalies.append(sni_anomaly)
            
        # VPN detection
        vpn_detected = self._check_vpn(packet_info)
        if vpn_detected:
            anomalies.append(vpn_detected)
            
        # DNS over HTTPS detection
        doh_detected = self._check_doh(packet_info)
        if doh_detected:
            anomalies.append(doh_detected)
            
        # Log anomalies and notify callbacks
        for anomaly in anomalies:
            self.anomalies.append(anomaly)
            logger.warning(f"Anomaly detected: {anomaly['type']} - {anomaly['description']}")
            
            # Notify callbacks
            for callback in self.anomaly_callbacks:
                try:
                    callback(anomaly)
                except Exception as e:
                    logger.error(f"Error in anomaly callback: {e}")
            
        return anomalies
        
    def _check_dns_anomaly(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for excessive DNS queries"""
        if packet_info.get('protocol') != 'DNS':
            return None
            
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return None
            
        # Add query timestamp
        self.dns_queries[src_ip].append(time.time())
        
        # Check query rate
        recent_queries = [t for t in self.dns_queries[src_ip] if time.time() - t < 60]
        
        if len(recent_queries) > self.dns_threshold:
            return {
                'type': 'excessive_dns',
                'severity': 'high',
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'description': f"Excessive DNS queries: {len(recent_queries)} queries in 60 seconds",
                'query_count': len(recent_queries)
            }
            
        return None
        
    def _check_port_scan(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for port scanning activity"""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        flags = packet_info.get('flags')
        
        if not src_ip or not dst_port:
            return None
        
        # Check if flags is None or empty
        if not flags or flags == 'None':
            return None
            
        # Look for SYN packets (port scan indicator)
        if 'SYN' in flags and 'ACK' not in flags:
            scan_data = self.port_scans[src_ip]
            scan_data['ports'].add(dst_port)
            scan_data['last_seen'] = time.time()
            
            # Check if scanning multiple ports
            if len(scan_data['ports']) > 20:
                return {
                    'type': 'port_scan',
                    'severity': 'high',
                    'timestamp': datetime.now(),
                    'src_ip': src_ip,
                    'description': f"Port scan detected: {len(scan_data['ports'])} ports scanned",
                    'ports_scanned': len(scan_data['ports'])
                }
                
        return None
        
    def _check_suspicious_port(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for suspicious port usage"""
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        suspicious = None
        if dst_port in self.suspicious_ports:
            suspicious = dst_port
        elif src_port in self.suspicious_ports:
            suspicious = src_port
            
        if suspicious:
            port_names = {
                22: 'SSH',
                23: 'Telnet',
                135: 'RPC',
                139: 'NetBIOS',
                445: 'SMB',
                1433: 'MSSQL',
                3306: 'MySQL',
                3389: 'RDP',
                5900: 'VNC'
            }
            
            return {
                'type': 'suspicious_port',
                'severity': 'medium',
                'timestamp': datetime.now(),
                'src_ip': packet_info.get('src_ip'),
                'dst_ip': packet_info.get('dst_ip'),
                'port': suspicious,
                'description': f"Suspicious port activity: {port_names.get(suspicious, suspicious)}",
                'service': port_names.get(suspicious, 'Unknown')
            }
            
        return None
        
    def _check_beaconing(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for beaconing behavior (C2 communication)"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        if not src_ip or not dst_ip:
            return None
            
        # Track connection timing
        conn_key = f"{src_ip}->{dst_ip}"
        self.beaconing_data[conn_key].append(time.time())
        
        # Need at least 10 connections to detect pattern
        if len(self.beaconing_data[conn_key]) < self.beaconing_threshold:
            return None
            
        # Calculate time intervals
        timestamps = list(self.beaconing_data[conn_key])
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if len(intervals) < 5:
            return None
            
        # Check for regular intervals (beaconing pattern)
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # Low variance indicates regular beaconing
        if std_dev < avg_interval * 0.1 and avg_interval > 1:  # Regular intervals
            return {
                'type': 'beaconing',
                'severity': 'critical',
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'description': f"Beaconing detected: Regular connections every {avg_interval:.1f}s",
                'interval': avg_interval,
                'connection_count': len(timestamps)
            }
            
        return None
        
    def _check_rate_limit(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for rate limit violations"""
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return None
            
        current_time = time.time()
        rate_data = self.rate_limits[src_ip]
        
        # Reset counters every second
        if current_time - rate_data['reset_time'] >= 1.0:
            rate_data['packets'] = 0
            rate_data['bytes'] = 0
            rate_data['reset_time'] = current_time
            
        # Update counters
        rate_data['packets'] += 1
        rate_data['bytes'] += packet_info.get('size', 0)
        
        # Check limits
        if rate_data['packets'] > self.pps_limit:
            return {
                'type': 'rate_limit_pps',
                'severity': 'high',
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'description': f"PPS limit exceeded: {rate_data['packets']} pps",
                'pps': rate_data['packets']
            }
            
        if rate_data['bytes'] > self.bps_limit:
            return {
                'type': 'rate_limit_bps',
                'severity': 'high',
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'description': f"BPS limit exceeded: {rate_data['bytes']} bps",
                'bps': rate_data['bytes']
            }
            
        return None
        
    def _check_unusual_sni(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for unusual SNI patterns"""
        # This would be in TLS details from protocol analyzer
        raw_packet = packet_info.get('raw_packet')
        if not raw_packet:
            return None
            
        # Check for SNI in packet info (would be extracted by protocol analyzer)
        sni = packet_info.get('sni')
        if not sni:
            return None
            
        # Track SNI patterns
        self.sni_patterns[sni] += 1
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\.onion$',  # Tor
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP as SNI
            r'^[a-f0-9]{32,}',  # Long hex strings
        ]
        
        import re
        for pattern in suspicious_patterns:
            if re.search(pattern, sni):
                return {
                    'type': 'unusual_sni',
                    'severity': 'medium',
                    'timestamp': datetime.now(),
                    'src_ip': packet_info.get('src_ip'),
                    'sni': sni,
                    'description': f"Unusual SNI pattern detected: {sni}",
                    'pattern': pattern
                }
                
        return None
        
    def _check_vpn(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for VPN usage"""
        dst_port = packet_info.get('dst_port')
        src_port = packet_info.get('src_port')
        protocol = packet_info.get('protocol')
        
        # Common VPN ports
        vpn_ports = {
            1194: 'OpenVPN',
            500: 'IKE/IPSec',
            4500: 'IPSec NAT-T',
            1723: 'PPTP',
            1701: 'L2TP'
        }
        
        detected_port = None
        if dst_port in vpn_ports:
            detected_port = dst_port
        elif src_port in vpn_ports:
            detected_port = src_port
            
        if detected_port:
            vpn_type = vpn_ports[detected_port]
            self.vpn_indicators.add(packet_info.get('src_ip'))
            
            return {
                'type': 'vpn_detected',
                'severity': 'info',
                'timestamp': datetime.now(),
                'src_ip': packet_info.get('src_ip'),
                'dst_ip': packet_info.get('dst_ip'),
                'port': detected_port,
                'description': f"VPN traffic detected: {vpn_type}",
                'vpn_type': vpn_type
            }
            
        return None
        
    def _check_doh(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for DNS over HTTPS"""
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')
        
        # Check for HTTPS to known DoH servers
        if protocol == 'HTTPS' and dst_port == 443 and dst_ip in self.doh_servers:
            return {
                'type': 'doh_detected',
                'severity': 'info',
                'timestamp': datetime.now(),
                'src_ip': packet_info.get('src_ip'),
                'dst_ip': dst_ip,
                'description': f"DNS over HTTPS detected to {dst_ip}",
                'server': dst_ip
            }
            
        return None
        
    def get_anomalies(self, count: int = None, severity: str = None) -> List[Dict[str, Any]]:
        """Get detected anomalies"""
        anomalies = list(self.anomalies)
        
        # Filter by severity
        if severity:
            anomalies = [a for a in anomalies if a.get('severity') == severity]
            
        # Limit count
        if count:
            anomalies = anomalies[-count:]
            
        return anomalies
        
    def add_anomaly_callback(self, callback):
        """Add callback for anomaly detection"""
        self.anomaly_callbacks.append(callback)
    
    def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get anomaly detection summary"""
        anomaly_types = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for anomaly in self.anomalies:
            anomaly_types[anomaly['type']] += 1
            severity_counts[anomaly.get('severity', 'unknown')] += 1
            
        return {
            'total_anomalies': len(self.anomalies),
            'by_type': dict(anomaly_types),
            'by_severity': dict(severity_counts),
            'vpn_users': len(self.vpn_indicators),
            'recent_anomalies': list(self.anomalies)[-10:]
        }
        
    def reset(self):
        """Reset anomaly detection state"""
        self.dns_queries.clear()
        self.port_scans.clear()
        self.beaconing_data.clear()
        self.rate_limits.clear()
        self.connection_attempts.clear()
        self.sni_patterns.clear()
        self.vpn_indicators.clear()
        self.proxy_indicators.clear()
        self.anomalies.clear()
        logger.info("Anomaly detector reset")
