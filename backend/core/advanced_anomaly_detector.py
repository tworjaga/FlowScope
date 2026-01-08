"""
Advanced Anomaly Detection
Baseline learning, explainability, and confidence scoring
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import math
import logging

logger = logging.getLogger(__name__)


@dataclass
class AnomalyAlert:
    """Anomaly alert with explainability"""
    timestamp: datetime
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 - 1.0
    category: str
    title: str
    description: str
    explanation: str  # WHY this is anomalous
    affected_entities: List[str]
    related_flows: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity,
            'confidence': self.confidence,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'explanation': self.explanation,
            'affected_entities': self.affected_entities,
            'related_flows': self.related_flows,
            'metrics': self.metrics,
            'recommendations': self.recommendations
        }


class Baseline:
    """Statistical baseline for anomaly detection"""
    
    def __init__(self, window_size: int = 3600):
        self.window_size = window_size  # seconds
        self.samples = deque(maxlen=1000)
        
    def add_sample(self, value: float, timestamp: datetime):
        """Add sample to baseline"""
        self.samples.append((timestamp, value))
        
    def get_mean(self) -> float:
        """Get mean value"""
        if not self.samples:
            return 0.0
        return sum(v for _, v in self.samples) / len(self.samples)
    
    def get_stddev(self) -> float:
        """Get standard deviation"""
        if len(self.samples) < 2:
            return 0.0
        mean = self.get_mean()
        variance = sum((v - mean) ** 2 for _, v in self.samples) / len(self.samples)
        return math.sqrt(variance)
    
    def get_z_score(self, value: float) -> float:
        """Calculate z-score for value"""
        mean = self.get_mean()
        stddev = self.get_stddev()
        if stddev == 0:
            return 0.0
        return (value - mean) / stddev
    
    def is_anomalous(self, value: float, threshold: float = 3.0) -> Tuple[bool, float]:
        """Check if value is anomalous (returns is_anomalous, z_score)"""
        z_score = abs(self.get_z_score(value))
        return z_score > threshold, z_score


class EWMA:
    """Exponentially Weighted Moving Average"""
    
    def __init__(self, alpha: float = 0.3):
        self.alpha = alpha
        self.value = None
        
    def update(self, new_value: float) -> float:
        """Update EWMA with new value"""
        if self.value is None:
            self.value = new_value
        else:
            self.value = self.alpha * new_value + (1 - self.alpha) * self.value
        return self.value
    
    def get(self) -> Optional[float]:
        """Get current EWMA value"""
        return self.value


class AdvancedAnomalyDetector:
    """Advanced anomaly detection with baselines and explainability"""
    
    def __init__(self):
        # Baselines
        self.host_baselines: Dict[str, Dict[str, Baseline]] = defaultdict(lambda: {
            'pps': Baseline(),
            'bps': Baseline(),
            'connections': Baseline(),
            'dns_queries': Baseline()
        })
        
        self.protocol_baselines: Dict[str, Baseline] = defaultdict(Baseline)
        self.port_baselines: Dict[int, Baseline] = defaultdict(Baseline)
        
        # EWMA trackers
        self.ewma_trackers: Dict[str, EWMA] = {}
        
        # Domain tracking
        self.domain_frequencies: Dict[str, int] = defaultdict(int)
        self.domain_first_seen: Dict[str, datetime] = {}
        self.total_domains_seen = 0
        
        # Port tracking
        self.port_frequencies: Dict[int, int] = defaultdict(int)
        self.suspicious_ports = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 8080}
        
        # Beaconing detection
        self.beacon_candidates: Dict[str, List[datetime]] = defaultdict(list)
        
        # Alerts
        self.alerts: List[AnomalyAlert] = []
        self.alert_callbacks = []
        
    def add_alert_callback(self, callback):
        """Add callback for new alerts"""
        self.alert_callbacks.append(callback)
        
    def update_baselines(self, flow_state, current_time: datetime):
        """Update baselines with flow data"""
        src_ip = flow_state.flow_key.src_ip
        dst_ip = flow_state.flow_key.dst_ip
        protocol = flow_state.flow_key.protocol
        
        # Update host baselines
        self.host_baselines[src_ip]['pps'].add_sample(
            flow_state.packets_forward / max(flow_state.duration, 1),
            current_time
        )
        self.host_baselines[src_ip]['bps'].add_sample(
            flow_state.bytes_forward / max(flow_state.duration, 1),
            current_time
        )
        
        # Update protocol baselines
        self.protocol_baselines[protocol].add_sample(
            flow_state.total_bytes,
            current_time
        )
        
        # Update port baselines
        if flow_state.flow_key.dst_port:
            self.port_baselines[flow_state.flow_key.dst_port].add_sample(
                flow_state.total_packets,
                current_time
            )
    
    def detect_anomalies(self, flow_state, packet_info: Dict) -> List[AnomalyAlert]:
        """Detect anomalies in flow"""
        alerts = []
        current_time = datetime.now()
        
        # Update baselines
        self.update_baselines(flow_state, current_time)
        
        # 1. Detect unusual traffic volume
        volume_alert = self._detect_unusual_volume(flow_state, current_time)
        if volume_alert:
            alerts.append(volume_alert)
        
        # 2. Detect rare domains
        domain_alert = self._detect_rare_domain(flow_state, current_time)
        if domain_alert:
            alerts.append(domain_alert)
        
        # 3. Detect high entropy domains
        entropy_alert = self._detect_high_entropy_domain(flow_state, current_time)
        if entropy_alert:
            alerts.append(entropy_alert)
        
        # 4. Detect beaconing
        beacon_alert = self._detect_beaconing_advanced(flow_state, current_time)
        if beacon_alert:
            alerts.append(beacon_alert)
        
        # 5. Detect suspicious ports
        port_alert = self._detect_suspicious_port(flow_state, current_time)
        if port_alert:
            alerts.append(port_alert)
        
        # 6. Detect long-lived encrypted flows
        encrypted_alert = self._detect_long_encrypted_flow(flow_state, current_time)
        if encrypted_alert:
            alerts.append(encrypted_alert)
        
        # 7. Detect unusual traffic hours
        hours_alert = self._detect_unusual_hours(flow_state, current_time)
        if hours_alert:
            alerts.append(hours_alert)
        
        # 8. Detect new behavior
        behavior_alert = self._detect_new_behavior(flow_state, current_time)
        if behavior_alert:
            alerts.append(behavior_alert)
        
        # Store and notify
        for alert in alerts:
            self.alerts.append(alert)
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
        
        return alerts
    
    def _detect_unusual_volume(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Detect unusual traffic volume"""
        src_ip = flow_state.flow_key.src_ip
        baseline = self.host_baselines[src_ip]['bps']
        
        current_bps = flow_state.bytes_forward / max(flow_state.duration, 1)
        is_anomalous, z_score = baseline.is_anomalous(current_bps, threshold=3.0)
        
        if is_anomalous and len(baseline.samples) > 10:
            mean_bps = baseline.get_mean()
            
            return AnomalyAlert(
                timestamp=current_time,
                severity='HIGH' if z_score > 5 else 'MEDIUM',
                confidence=min(z_score / 10, 1.0),
                category='Traffic Volume',
                title=f'Unusual traffic volume from {src_ip}',
                description=f'Host {src_ip} is sending {current_bps:.0f} bytes/sec',
                explanation=f'This is {z_score:.1f} standard deviations above the baseline of {mean_bps:.0f} bytes/sec. '
                           f'Normal range is {mean_bps - 3*baseline.get_stddev():.0f} - {mean_bps + 3*baseline.get_stddev():.0f} bytes/sec.',
                affected_entities=[src_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'current_bps': current_bps,
                    'baseline_bps': mean_bps,
                    'z_score': z_score
                },
                recommendations=[
                    'Check if this is expected behavior (backup, update, etc.)',
                    'Investigate destination IPs and ports',
                    'Check for data exfiltration patterns'
                ]
            )
        
        return None
    
    def _detect_rare_domain(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Detect rare/new domains"""
        if not flow_state.dns_queries and not flow_state.tls_sni:
            return None
        
        domain = flow_state.tls_sni or (flow_state.dns_queries[0] if flow_state.dns_queries else None)
        if not domain:
            return None
        
        # Track domain
        self.domain_frequencies[domain] += 1
        if domain not in self.domain_first_seen:
            self.domain_first_seen[domain] = current_time
            self.total_domains_seen += 1
        
        # Check if domain is rare
        frequency = self.domain_frequencies[domain]
        age = (current_time - self.domain_first_seen[domain]).total_seconds()
        
        # New domain (first time seen)
        if frequency == 1 and self.total_domains_seen > 100:
            return AnomalyAlert(
                timestamp=current_time,
                severity='LOW',
                confidence=0.6,
                category='DNS',
                title=f'New domain observed: {domain}',
                description=f'First time seeing domain {domain}',
                explanation=f'This domain has never been seen before in {self.total_domains_seen} total domains observed. '
                           f'New domains can indicate malware C2, phishing, or legitimate new services.',
                affected_entities=[flow_state.flow_key.src_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'domain': domain,
                    'frequency': frequency,
                    'total_domains': self.total_domains_seen
                },
                recommendations=[
                    'Check domain reputation (VirusTotal, etc.)',
                    'Verify if this is expected user behavior',
                    'Monitor for repeated connections'
                ]
            )
        
        # Rare domain (seen few times over long period)
        if frequency < 5 and age > 3600:
            rarity_score = 1.0 - (frequency / 100)
            
            return AnomalyAlert(
                timestamp=current_time,
                severity='LOW',
                confidence=rarity_score,
                category='DNS',
                title=f'Rare domain: {domain}',
                description=f'Domain {domain} seen only {frequency} times in {age/3600:.1f} hours',
                explanation=f'This domain has been seen {frequency} times over {age/3600:.1f} hours, '
                           f'making it rare compared to typical domains. Rarity score: {rarity_score:.2f}',
                affected_entities=[flow_state.flow_key.src_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'domain': domain,
                    'frequency': frequency,
                    'age_hours': age / 3600,
                    'rarity_score': rarity_score
                },
                recommendations=[
                    'Investigate why this domain is rarely accessed',
                    'Check if domain is legitimate but unused',
                    'Monitor for pattern changes'
                ]
            )
        
        return None
    
    def _detect_high_entropy_domain(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Detect high entropy domains (DGA)"""
        domain = flow_state.tls_sni or (flow_state.dns_queries[0] if flow_state.dns_queries else None)
        if not domain:
            return None
        
        # Calculate Shannon entropy
        entropy = self._calculate_entropy(domain)
        
        # High entropy threshold (DGA domains typically > 4.0)
        if entropy > 4.0:
            return AnomalyAlert(
                timestamp=current_time,
                severity='HIGH',
                confidence=min((entropy - 3.0) / 2.0, 1.0),
                category='DNS',
                title=f'High entropy domain detected: {domain}',
                description=f'Domain {domain} has entropy {entropy:.2f}',
                explanation=f'Domain entropy of {entropy:.2f} is unusually high. '
                           f'Normal domains have entropy 2.5-3.5. High entropy suggests Domain Generation Algorithm (DGA) '
                           f'commonly used by malware for C2 communication.',
                affected_entities=[flow_state.flow_key.src_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'domain': domain,
                    'entropy': entropy,
                    'threshold': 4.0
                },
                recommendations=[
                    'URGENT: Check for malware on source host',
                    'Block domain at firewall/DNS level',
                    'Investigate all connections from this host',
                    'Run antivirus scan'
                ]
            )
        
        return None
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string"""
        if not s:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_beaconing_advanced(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Advanced beaconing detection"""
        if not flow_state.is_beaconing:
            return None
        
        flow_id = flow_state.flow_key.to_string()
        self.beacon_candidates[flow_id].append(current_time)
        
        # Need at least 10 samples
        if len(self.beacon_candidates[flow_id]) < 10:
            return None
        
        # Calculate inter-packet intervals
        timestamps = self.beacon_candidates[flow_id][-20:]  # Last 20
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return None
        
        # Calculate interval statistics
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        jitter = stddev / mean_interval if mean_interval > 0 else 0
        
        # Low jitter indicates beaconing
        if jitter < 0.3 and mean_interval > 5:
            return AnomalyAlert(
                timestamp=current_time,
                severity='CRITICAL',
                confidence=1.0 - jitter,
                category='Beaconing',
                title=f'Beaconing detected: {flow_state.flow_key.dst_ip}',
                description=f'Regular communication every {mean_interval:.1f}s with {jitter:.2%} jitter',
                explanation=f'Host {flow_state.flow_key.src_ip} is communicating with {flow_state.flow_key.dst_ip} '
                           f'at regular {mean_interval:.1f} second intervals with only {jitter:.2%} variation. '
                           f'This pattern is characteristic of malware beaconing to C2 servers.',
                affected_entities=[flow_state.flow_key.src_ip, flow_state.flow_key.dst_ip],
                related_flows=[flow_id],
                metrics={
                    'mean_interval': mean_interval,
                    'jitter': jitter,
                    'sample_count': len(intervals)
                },
                recommendations=[
                    'URGENT: Isolate affected host immediately',
                    'Block destination IP at firewall',
                    'Perform forensic analysis',
                    'Check for malware/backdoor',
                    'Review all connections from this host'
                ]
            )
        
        return None
    
    def _detect_suspicious_port(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Detect suspicious port usage"""
        dst_port = flow_state.flow_key.dst_port
        
        if dst_port in self.suspicious_ports:
            return AnomalyAlert(
                timestamp=current_time,
                severity='MEDIUM',
                confidence=0.7,
                category='Port',
                title=f'Suspicious port activity: {dst_port}',
                description=f'Connection to suspicious port {dst_port}',
                explanation=f'Port {dst_port} is commonly associated with remote access, database access, or exploitation. '
                           f'Connections to this port should be investigated.',
                affected_entities=[flow_state.flow_key.src_ip, flow_state.flow_key.dst_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'port': dst_port,
                    'protocol': flow_state.flow_key.protocol
                },
                recommendations=[
                    'Verify if this connection is authorized',
                    'Check if destination is internal or external',
                    'Review firewall rules',
                    'Monitor for data transfer'
                ]
            )
        
        return None
    
    def _detect_long_encrypted_flow(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Detect long-lived encrypted flows"""
        if not flow_state.is_long_lived or 'tls' not in flow_state.tags:
            return None
        
        if flow_state.duration > 7200:  # 2 hours
            return AnomalyAlert(
                timestamp=current_time,
                severity='MEDIUM',
                confidence=0.6,
                category='TLS',
                title=f'Long-lived encrypted connection',
                description=f'TLS connection active for {flow_state.duration/3600:.1f} hours',
                explanation=f'Encrypted connection to {flow_state.flow_key.dst_ip} has been active for '
                           f'{flow_state.duration/3600:.1f} hours. Long-lived encrypted connections can indicate '
                           f'data exfiltration, tunneling, or persistent backdoors.',
                affected_entities=[flow_state.flow_key.src_ip, flow_state.flow_key.dst_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'duration_hours': flow_state.duration / 3600,
                    'total_bytes': flow_state.total_bytes,
                    'sni': flow_state.tls_sni
                },
                recommendations=[
                    'Investigate purpose of long connection',
                    'Check data transfer volumes',
                    'Verify destination legitimacy',
                    'Consider connection timeout policies'
                ]
            )
        
        return None
    
    def _detect_unusual_hours(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Detect traffic during unusual hours"""
        hour = current_time.hour
        
        # Define unusual hours (e.g., 2 AM - 5 AM)
        if 2 <= hour <= 5:
            return AnomalyAlert(
                timestamp=current_time,
                severity='LOW',
                confidence=0.5,
                category='Timing',
                title=f'Activity during unusual hours',
                description=f'Network activity at {hour}:00',
                explanation=f'Network activity detected at {hour}:00, which is outside normal business hours. '
                           f'This could indicate automated processes, maintenance, or unauthorized access.',
                affected_entities=[flow_state.flow_key.src_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'hour': hour
                },
                recommendations=[
                    'Verify if this is scheduled maintenance',
                    'Check if user is authorized for off-hours access',
                    'Review activity logs'
                ]
            )
        
        return None
    
    def _detect_new_behavior(self, flow_state, current_time: datetime) -> Optional[AnomalyAlert]:
        """Detect new behavior per host"""
        src_ip = flow_state.flow_key.src_ip
        dst_port = flow_state.flow_key.dst_port
        
        # Track port usage per host
        key = f"{src_ip}:{dst_port}"
        if key not in self.port_frequencies:
            self.port_frequencies[key] = 0
        
        self.port_frequencies[key] += 1
        
        # First time this host connects to this port
        if self.port_frequencies[key] == 1:
            return AnomalyAlert(
                timestamp=current_time,
                severity='LOW',
                confidence=0.4,
                category='Behavior',
                title=f'New behavior: {src_ip} → port {dst_port}',
                description=f'First time {src_ip} connects to port {dst_port}',
                explanation=f'Host {src_ip} has never connected to port {dst_port} before. '
                           f'New behavior can indicate legitimate new usage or potential compromise.',
                affected_entities=[src_ip],
                related_flows=[flow_state.flow_key.to_string()],
                metrics={
                    'port': dst_port,
                    'protocol': flow_state.flow_key.protocol
                },
                recommendations=[
                    'Verify if this is expected user behavior',
                    'Check application logs',
                    'Monitor for repeated connections'
                ]
            )
        
        return None
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> List[AnomalyAlert]:
        """Get recent alerts"""
        alerts = self.alerts[-limit:]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return alerts
    
    def get_alert_summary(self) -> Dict:
        """Get alert summary statistics"""
        total = len(self.alerts)
        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        
        for alert in self.alerts:
            by_severity[alert.severity] += 1
            by_category[alert.category] += 1
        
        return {
            'total_alerts': total,
            'by_severity': dict(by_severity),
            'by_category': dict(by_category),
            'recent_alerts': [a.to_dict() for a in self.alerts[-10:]]
        }
