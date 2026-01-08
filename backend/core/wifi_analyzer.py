"""
WiFi Analyzer
Comprehensive WiFi network analysis and monitoring
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict
import subprocess
import re

logger = logging.getLogger(__name__)


class WiFiAnalyzer:
    """WiFi network analyzer"""
    
    def __init__(self):
        self.networks = {}
        self.connected_network = None
        self.signal_history = defaultdict(list)
        self.channel_usage = defaultdict(int)
        
        # Enhanced tracking
        self.network_history = defaultdict(list)  # Track network appearances over time
        self.rogue_ap_candidates = set()  # Potential rogue access points
        self.deauth_attacks = defaultdict(int)  # Deauthentication attack detection
        self.beacon_intervals = defaultdict(list)  # Track beacon timing
        self.vendor_database = self._load_vendor_database()  # MAC vendor lookup
        
    def scan_networks(self) -> List[Dict[str, Any]]:
        """Scan for available WiFi networks"""
        try:
            import platform
            system = platform.system()
            
            if system == "Windows":
                return self._scan_windows()
            elif system == "Linux":
                return self._scan_linux()
            elif system == "Darwin":  # macOS
                return self._scan_macos()
            else:
                logger.error(f"Unsupported platform: {system}")
                return []
                
        except Exception as e:
            logger.error(f"Error scanning networks: {e}")
            return []
            
    def _scan_windows(self) -> List[Dict[str, Any]]:
        """Scan WiFi networks on Windows"""
        networks = []
        
        try:
            # Run netsh command
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                encoding='cp866'  # Windows console encoding
            )
            
            if result.returncode != 0:
                logger.error("Failed to scan networks")
                return []
                
            # Parse output
            current_network = {}
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('SSID'):
                    if current_network and 'ssid' in current_network:
                        networks.append(current_network)
                    ssid = line.split(':', 1)[1].strip()
                    current_network = {'ssid': ssid}
                    
                elif 'Network type' in line:
                    current_network['type'] = line.split(':', 1)[1].strip()
                    
                elif 'Authentication' in line:
                    current_network['auth'] = line.split(':', 1)[1].strip()
                    
                elif 'Encryption' in line:
                    current_network['encryption'] = line.split(':', 1)[1].strip()
                    
                elif 'BSSID' in line:
                    current_network['bssid'] = line.split(':', 1)[1].strip()
                    
                elif 'Signal' in line:
                    signal_str = line.split(':', 1)[1].strip().replace('%', '')
                    try:
                        current_network['signal'] = int(signal_str)
                    except:
                        current_network['signal'] = 0
                        
                elif 'Channel' in line:
                    try:
                        channel = int(line.split(':', 1)[1].strip())
                        current_network['channel'] = channel
                        self.channel_usage[channel] += 1
                    except:
                        pass
                        
            if current_network and 'ssid' in current_network:
                networks.append(current_network)
                
            # Update networks cache
            for network in networks:
                ssid = network.get('ssid', '')
                if ssid:
                    self.networks[ssid] = network
                    self.signal_history[ssid].append({
                        'timestamp': datetime.now(),
                        'signal': network.get('signal', 0)
                    })
                    
            return networks
            
        except Exception as e:
            logger.error(f"Error scanning Windows networks: {e}")
            return []
            
    def _scan_linux(self) -> List[Dict[str, Any]]:
        """Scan WiFi networks on Linux"""
        networks = []
        
        try:
            # Try nmcli first
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'dev', 'wifi'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue
                        
                    parts = line.split(':')
                    if len(parts) >= 5:
                        network = {
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'channel': int(parts[2]) if parts[2].isdigit() else 0,
                            'signal': int(parts[3]) if parts[3].isdigit() else 0,
                            'security': parts[4]
                        }
                        networks.append(network)
                        
                        if network['channel']:
                            self.channel_usage[network['channel']] += 1
                            
            return networks
            
        except Exception as e:
            logger.error(f"Error scanning Linux networks: {e}")
            return []
            
    def _scan_macos(self) -> List[Dict[str, Any]]:
        """Scan WiFi networks on macOS"""
        networks = []
        
        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 7:
                        network = {
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'signal': int(parts[2]),
                            'channel': int(parts[3].split(',')[0]),
                            'security': ' '.join(parts[6:])
                        }
                        networks.append(network)
                        
                        if network['channel']:
                            self.channel_usage[network['channel']] += 1
                            
            return networks
            
        except Exception as e:
            logger.error(f"Error scanning macOS networks: {e}")
            return []
            
    def get_connected_network(self) -> Optional[Dict[str, Any]]:
        """Get currently connected WiFi network"""
        try:
            import platform
            system = platform.system()
            
            if system == "Windows":
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'interfaces'],
                    capture_output=True,
                    text=True,
                    encoding='cp866'
                )
                
                if result.returncode == 0:
                    network = {}
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if 'SSID' in line and 'BSSID' not in line:
                            network['ssid'] = line.split(':', 1)[1].strip()
                        elif 'BSSID' in line:
                            network['bssid'] = line.split(':', 1)[1].strip()
                        elif 'Signal' in line:
                            signal_str = line.split(':', 1)[1].strip().replace('%', '')
                            try:
                                network['signal'] = int(signal_str)
                            except:
                                pass
                        elif 'Channel' in line:
                            try:
                                network['channel'] = int(line.split(':', 1)[1].strip())
                            except:
                                pass
                                
                    if network:
                        self.connected_network = network
                        return network
                        
            elif system == "Linux":
                result = subprocess.run(
                    ['nmcli', '-t', '-f', 'ACTIVE,SSID,BSSID,CHAN,SIGNAL', 'dev', 'wifi'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.startswith('yes:'):
                            parts = line.split(':')
                            if len(parts) >= 5:
                                network = {
                                    'ssid': parts[1],
                                    'bssid': parts[2],
                                    'channel': int(parts[3]) if parts[3].isdigit() else 0,
                                    'signal': int(parts[4]) if parts[4].isdigit() else 0
                                }
                                self.connected_network = network
                                return network
                                
        except Exception as e:
            logger.error(f"Error getting connected network: {e}")
            
        return None
        
    def analyze_channel_congestion(self) -> Dict[int, Dict[str, Any]]:
        """Analyze WiFi channel congestion"""
        congestion = {}
        
        # 2.4 GHz channels
        for channel in range(1, 14):
            congestion[channel] = {
                'frequency': 2407 + (channel * 5),
                'band': '2.4GHz',
                'networks': self.channel_usage.get(channel, 0),
                'congestion_level': self._calculate_congestion(channel, '2.4GHz')
            }
            
        # 5 GHz channels
        for channel in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]:
            congestion[channel] = {
                'frequency': 5000 + (channel * 5),
                'band': '5GHz',
                'networks': self.channel_usage.get(channel, 0),
                'congestion_level': self._calculate_congestion(channel, '5GHz')
            }
            
        return congestion
        
    def _calculate_congestion(self, channel: int, band: str) -> str:
        """Calculate congestion level for a channel"""
        count = self.channel_usage.get(channel, 0)
        
        if band == '2.4GHz':
            if count == 0:
                return 'free'
            elif count <= 2:
                return 'low'
            elif count <= 5:
                return 'medium'
            else:
                return 'high'
        else:  # 5GHz
            if count == 0:
                return 'free'
            elif count <= 3:
                return 'low'
            elif count <= 7:
                return 'medium'
            else:
                return 'high'
                
    def get_best_channel(self, band: str = '2.4GHz') -> int:
        """Get best WiFi channel with least congestion"""
        congestion = self.analyze_channel_congestion()
        
        if band == '2.4GHz':
            channels = [1, 6, 11]  # Non-overlapping channels
        else:
            channels = [36, 40, 44, 48, 149, 153, 157, 161]
            
        best_channel = min(channels, key=lambda ch: self.channel_usage.get(ch, 0))
        return best_channel
        
    def analyze_signal_strength(self, ssid: str) -> Dict[str, Any]:
        """Analyze signal strength history for a network"""
        history = self.signal_history.get(ssid, [])
        
        if not history:
            return {'status': 'no_data'}
            
        signals = [h['signal'] for h in history]
        
        return {
            'current': signals[-1] if signals else 0,
            'average': sum(signals) / len(signals),
            'min': min(signals),
            'max': max(signals),
            'stability': self._calculate_stability(signals),
            'quality': self._signal_to_quality(signals[-1] if signals else 0)
        }
        
    def _calculate_stability(self, signals: List[int]) -> str:
        """Calculate signal stability"""
        if len(signals) < 2:
            return 'unknown'
            
        variance = sum((s - sum(signals)/len(signals))**2 for s in signals) / len(signals)
        std_dev = variance ** 0.5
        
        if std_dev < 5:
            return 'excellent'
        elif std_dev < 10:
            return 'good'
        elif std_dev < 15:
            return 'fair'
        else:
            return 'poor'
            
    def _signal_to_quality(self, signal: int) -> str:
        """Convert signal strength to quality rating"""
        if signal >= 80:
            return 'excellent'
        elif signal >= 60:
            return 'good'
        elif signal >= 40:
            return 'fair'
        elif signal >= 20:
            return 'weak'
        else:
            return 'very_weak'
            
    def _load_vendor_database(self) -> Dict[str, str]:
        """Load MAC vendor database (OUI lookup)"""
        # Common vendors (simplified - in production, use full OUI database)
        return {
            '00:50:F2': 'Microsoft',
            '00:0C:29': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:1B:63': 'Apple',
            '00:25:00': 'Apple',
            '00:26:BB': 'Apple',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            '00:0D:B9': 'Netgear',
            '00:1F:33': 'Netgear',
            '00:14:6C': 'Netgear',
            '00:24:B2': 'Linksys',
            '00:18:39': 'Linksys',
            '00:1D:7E': 'Linksys',
            '00:1C:DF': 'Belkin',
            '00:30:BD': 'Belkin',
            '94:10:3E': 'Belkin',
            '00:50:56': 'TP-Link',
            '00:27:19': 'TP-Link',
            'F4:EC:38': 'TP-Link',
            '00:1A:70': 'D-Link',
            '00:05:5D': 'D-Link',
            '00:17:9A': 'D-Link',
            '00:0F:B5': 'Asus',
            '00:1F:C6': 'Asus',
            '04:D4:C4': 'Asus'
        }
    
    def lookup_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC address"""
        if not mac or len(mac) < 8:
            return 'Unknown'
        
        # Extract OUI (first 3 octets)
        oui = mac[:8].upper()
        return self.vendor_database.get(oui, 'Unknown')
    
    def detect_security_issues(self, network: Dict[str, Any]) -> List[str]:
        """Detect security issues in WiFi network (enhanced)"""
        issues = []
        
        # Check encryption
        encryption = network.get('encryption', '').upper()
        auth = network.get('auth', '').upper()
        security = network.get('security', '').upper()
        
        if 'OPEN' in encryption or 'NONE' in encryption or 'OPEN' in security:
            issues.append('🔴 CRITICAL: No encryption - Network is open and insecure')
            
        if 'WEP' in encryption or 'WEP' in auth or 'WEP' in security:
            issues.append('🔴 CRITICAL: WEP encryption - Outdated and easily crackable')
            
        if 'WPA' in encryption and 'WPA2' not in encryption and 'WPA3' not in encryption:
            issues.append('🟡 WARNING: WPA encryption - Upgrade to WPA2 or WPA3 recommended')
        
        if 'WPA2' in encryption and 'WPA3' not in encryption:
            issues.append('🟢 INFO: WPA2 detected - Consider upgrading to WPA3 for enhanced security')
            
        # Check signal strength
        signal = network.get('signal', 0)
        if signal < 30:
            issues.append('🟡 WARNING: Weak signal - May indicate distance or interference')
        elif signal < 50:
            issues.append('🟢 INFO: Moderate signal strength')
        
        # Check for hidden SSID
        ssid = network.get('ssid', '')
        if not ssid or ssid == '':
            issues.append('🟡 WARNING: Hidden SSID detected - May indicate security through obscurity')
        
        # Check for suspicious SSID patterns
        if ssid:
            suspicious_patterns = ['free', 'public', 'guest', 'open', 'wifi', 'internet']
            if any(pattern in ssid.lower() for pattern in suspicious_patterns):
                issues.append('🟡 WARNING: Suspicious SSID pattern - Verify network authenticity')
        
        # Check channel
        channel = network.get('channel', 0)
        if channel in [1, 6, 11]:
            issues.append('🟢 INFO: Using non-overlapping 2.4GHz channel')
        elif 1 <= channel <= 14:
            issues.append('🟡 WARNING: Using overlapping 2.4GHz channel - May cause interference')
        
        return issues
    
    def detect_rogue_ap(self, network: Dict[str, Any]) -> bool:
        """Detect potential rogue access points"""
        ssid = network.get('ssid', '')
        bssid = network.get('bssid', '')
        
        # Check for duplicate SSIDs with different BSSIDs
        for known_ssid, known_network in self.networks.items():
            if known_ssid == ssid and known_network.get('bssid') != bssid:
                # Same SSID, different BSSID - potential rogue AP
                self.rogue_ap_candidates.add(bssid)
                logger.warning(f"Potential rogue AP detected: {ssid} ({bssid})")
                return True
        
        return False
    
    def analyze_interference(self) -> Dict[str, Any]:
        """Analyze WiFi interference and channel overlap"""
        interference = {
            '2.4GHz': {'channels': {}, 'overlap_score': 0},
            '5GHz': {'channels': {}, 'overlap_score': 0}
        }
        
        # Analyze 2.4GHz band (channels overlap)
        for channel in range(1, 14):
            overlapping_channels = []
            for ch in range(max(1, channel-4), min(14, channel+5)):
                if ch != channel and self.channel_usage.get(ch, 0) > 0:
                    overlapping_channels.append(ch)
            
            if overlapping_channels:
                interference['2.4GHz']['channels'][channel] = {
                    'networks': self.channel_usage.get(channel, 0),
                    'overlapping_with': overlapping_channels,
                    'interference_level': len(overlapping_channels)
                }
        
        # Calculate overall overlap score
        total_overlap = sum(len(data['overlapping_with']) for data in interference['2.4GHz']['channels'].values())
        interference['2.4GHz']['overlap_score'] = total_overlap
        
        # 5GHz channels don't overlap (20MHz channels)
        for channel in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]:
            if self.channel_usage.get(channel, 0) > 0:
                interference['5GHz']['channels'][channel] = {
                    'networks': self.channel_usage.get(channel, 0),
                    'overlapping_with': [],
                    'interference_level': 0
                }
        
        return interference
    
    def get_channel_recommendations(self) -> Dict[str, Any]:
        """Get detailed channel recommendations"""
        congestion = self.analyze_channel_congestion()
        interference = self.analyze_interference()
        
        # Find best channels for 2.4GHz
        best_24_channels = []
        for channel in [1, 6, 11]:  # Non-overlapping
            score = self.channel_usage.get(channel, 0)
            best_24_channels.append({
                'channel': channel,
                'networks': score,
                'congestion': congestion[channel]['congestion_level'],
                'recommended': score == min(self.channel_usage.get(ch, 0) for ch in [1, 6, 11])
            })
        
        # Find best channels for 5GHz
        best_5_channels = []
        for channel in [36, 40, 44, 48, 149, 153, 157, 161]:
            score = self.channel_usage.get(channel, 0)
            best_5_channels.append({
                'channel': channel,
                'networks': score,
                'congestion': congestion.get(channel, {}).get('congestion_level', 'unknown'),
                'recommended': score == 0  # Free channels are best
            })
        
        return {
            '2.4GHz': sorted(best_24_channels, key=lambda x: x['networks']),
            '5GHz': sorted(best_5_channels, key=lambda x: x['networks']),
            'overall_recommendation': self._get_overall_recommendation(best_24_channels, best_5_channels)
        }
    
    def _get_overall_recommendation(self, channels_24: List[Dict], channels_5: List[Dict]) -> str:
        """Get overall channel recommendation"""
        # Count networks on each band
        total_24 = sum(ch['networks'] for ch in channels_24)
        total_5 = sum(ch['networks'] for ch in channels_5)
        
        if total_5 < total_24 / 2:
            return "Switch to 5GHz band for better performance and less congestion"
        elif total_24 == 0:
            return "2.4GHz band is clear - Good for maximum range"
        else:
            return "Both bands are congested - Use recommended channels for best performance"
        
    def get_network_statistics(self) -> Dict[str, Any]:
        """Get overall WiFi network statistics"""
        networks = list(self.networks.values())
        
        if not networks:
            return {'status': 'no_networks'}
            
        return {
            'total_networks': len(networks),
            'by_band': {
                '2.4GHz': sum(1 for n in networks if n.get('channel', 0) <= 14),
                '5GHz': sum(1 for n in networks if n.get('channel', 0) > 14)
            },
            'by_security': self._count_by_security(networks),
            'average_signal': sum(n.get('signal', 0) for n in networks) / len(networks),
            'strongest_network': max(networks, key=lambda n: n.get('signal', 0)),
            'most_congested_channel': max(self.channel_usage.items(), key=lambda x: x[1])[0] if self.channel_usage else None,
            'channel_distribution': dict(self.channel_usage)
        }
        
    def _count_by_security(self, networks: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count networks by security type"""
        security_count = defaultdict(int)
        
        for network in networks:
            encryption = network.get('encryption', 'Unknown').upper()
            auth = network.get('auth', '').upper()
            security = network.get('security', '').upper()
            
            if 'OPEN' in encryption or 'NONE' in encryption or 'OPEN' in security:
                security_count['Open'] += 1
            elif 'WPA3' in encryption or 'WPA3' in auth or 'WPA3' in security:
                security_count['WPA3'] += 1
            elif 'WPA2' in encryption or 'WPA2' in auth or 'WPA2' in security:
                security_count['WPA2'] += 1
            elif 'WPA' in encryption or 'WPA' in auth or 'WPA' in security:
                security_count['WPA'] += 1
            elif 'WEP' in encryption or 'WEP' in auth or 'WEP' in security:
                security_count['WEP'] += 1
            else:
                security_count['Unknown'] += 1
                
        return dict(security_count)
        
    def generate_wifi_report(self) -> Dict[str, Any]:
        """Generate comprehensive WiFi analysis report"""
        networks = self.scan_networks()
        connected = self.get_connected_network()
        congestion = self.analyze_channel_congestion()
        stats = self.get_network_statistics()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'connected_network': connected,
            'available_networks': networks,
            'network_count': len(networks),
            'statistics': stats,
            'channel_analysis': congestion,
            'recommendations': self._generate_recommendations(networks, congestion)
        }
        
        return report
        
    def _generate_recommendations(self, networks: List[Dict[str, Any]], 
                                  congestion: Dict[int, Dict[str, Any]]) -> List[str]:
        """Generate WiFi optimization recommendations"""
        recommendations = []
        
        # Check for open networks
        open_networks = [n for n in networks if 'OPEN' in n.get('encryption', '').upper() or 
                        'OPEN' in n.get('security', '').upper()]
        if open_networks:
            recommendations.append(f"Found {len(open_networks)} open networks - Avoid connecting to unsecured networks")
            
        # Check for WEP networks
        wep_networks = [n for n in networks if 'WEP' in n.get('encryption', '').upper()]
        if wep_networks:
            recommendations.append(f"Found {len(wep_networks)} networks using WEP - These are insecure")
            
        # Channel recommendations
        best_24 = self.get_best_channel('2.4GHz')
        best_5 = self.get_best_channel('5GHz')
        recommendations.append(f"Best 2.4GHz channel: {best_24}")
        recommendations.append(f"Best 5GHz channel: {best_5}")
        
        # Congestion warnings
        high_congestion = [ch for ch, data in congestion.items() 
                          if data['congestion_level'] == 'high' and data['band'] == '2.4GHz']
        if high_congestion:
            recommendations.append(f"High congestion on 2.4GHz channels: {', '.join(map(str, high_congestion))}")
            recommendations.append("Consider switching to 5GHz band for better performance")
            
        return recommendations
