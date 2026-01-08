"""
Packet Capture Engine
Asynchronous packet capture with protocol analysis
"""

import asyncio
import time
from scapy.all import AsyncSniffer, conf, get_if_list, get_working_if
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    
from typing import Callable, Optional, Dict, Any, List
import logging
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)


class PacketCaptureEngine:
    """Asynchronous packet capture engine"""
    
    def __init__(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None):
        # Get proper interface
        if interface and interface != 'auto':
            self.interface = interface
        else:
            self.interface = self._get_default_interface()
        
        logger.info(f"Using interface: {self.interface}")
        self.bpf_filter = bpf_filter
        self.sniffer: Optional[AsyncSniffer] = None
        self.is_running = False
        self.is_paused = False
        
        # Statistics
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = None
        self.packets_per_protocol = {}
        self.bytes_per_protocol = {}
        
        # Packet buffer (circular buffer)
        self.max_buffer_size = 100000
        self.packet_buffer = deque(maxlen=self.max_buffer_size)
        
        # Callbacks
        self.packet_callbacks = []
        self.statistics_callbacks = []
        
        # Performance metrics
        self.last_stats_time = time.time()
        self.packets_since_last_stats = 0
        self.bytes_since_last_stats = 0
        
        # Task management
        self.stats_task = None
        
    def _get_default_interface(self) -> str:
        """Get default network interface"""
        # Use smart auto-selection
        best_iface = self.get_best_interface()
        if best_iface:
            return best_iface
            
        # Fallback to old method
        try:
            iface = get_working_if()
            if iface:
                logger.info(f"Scapy detected interface: {iface}")
                return iface
        except Exception as e:
            logger.warning(f"Scapy interface detection failed: {e}")
            
        logger.warning(f"Using fallback interface: {conf.iface}")
        return conf.iface
        
    @staticmethod
    def get_available_interfaces() -> List[Dict[str, str]]:
        """Get list of available network interfaces with friendly names"""
        try:
            from scapy.all import get_if_addr, IFACES
            interfaces = []
            
            for iface in get_if_list():
                try:
                    # Get IP address
                    ip = get_if_addr(iface)
                    
                    # Skip loopback
                    if 'Loopback' in iface:
                        continue
                        
                    # Skip interfaces without IP or with APIPA
                    if not ip or ip == '0.0.0.0' or ip.startswith('169.254'):
                        continue
                    
                    # Try to get friendly name from IFACES
                    friendly_name = iface
                    try:
                        if hasattr(IFACES, 'data') and iface in IFACES.data:
                            iface_data = IFACES.data[iface]
                            if hasattr(iface_data, 'description'):
                                friendly_name = iface_data.description
                            elif hasattr(iface_data, 'name'):
                                friendly_name = iface_data.name
                    except:
                        pass
                    
                    # Determine interface type
                    iface_lower = friendly_name.lower()
                    if 'wi-fi' in iface_lower or 'wireless' in iface_lower or 'wlan' in iface_lower or '802.11' in iface_lower:
                        iface_type = 'wifi'
                    elif 'ethernet' in iface_lower or 'eth' in iface_lower or 'realtek' in iface_lower or 'intel' in iface_lower:
                        iface_type = 'ethernet'
                    else:
                        iface_type = 'other'
                    
                    interfaces.append({
                        'guid': iface,
                        'name': friendly_name,
                        'ip': ip,
                        'type': iface_type
                    })
                    
                except Exception as e:
                    logger.debug(f"Skipping interface {iface}: {e}")
                    continue
                    
            logger.info(f"Found {len(interfaces)} valid interfaces")
            return interfaces
            
        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
            return []
    
    @staticmethod
    def get_best_interface() -> Optional[str]:
        """Get best interface for capture (auto-select)"""
        interfaces = PacketCaptureEngine.get_available_interfaces()
        
        if not interfaces:
            return None
        
        # Priority: Wi-Fi > Ethernet > Other
        wifi_ifaces = [i for i in interfaces if i['type'] == 'wifi']
        if wifi_ifaces:
            logger.info(f"Auto-selected Wi-Fi interface: {wifi_ifaces[0]['name']}")
            return wifi_ifaces[0]['guid']
        
        ethernet_ifaces = [i for i in interfaces if i['type'] == 'ethernet']
        if ethernet_ifaces:
            logger.info(f"Auto-selected Ethernet interface: {ethernet_ifaces[0]['name']}")
            return ethernet_ifaces[0]['guid']
        
        # Fallback to first available
        logger.info(f"Auto-selected interface: {interfaces[0]['name']}")
        return interfaces[0]['guid']
        
    def add_packet_callback(self, callback: Callable):
        """Add callback for packet processing"""
        self.packet_callbacks.append(callback)
        
    def add_statistics_callback(self, callback: Callable):
        """Add callback for statistics updates"""
        self.statistics_callbacks.append(callback)
        
    async def start(self):
        """Start packet capture"""
        if self.is_running:
            logger.warning("Capture already running")
            return
            
        logger.info(f"Starting capture on interface: {self.interface}")
        if self.bpf_filter:
            logger.info(f"Using BPF filter: {self.bpf_filter}")
            
        self.is_running = True
        self.is_paused = False
        self.start_time = time.time()
        
        # Create async sniffer with proper parameters
        try:
            logger.info(f"Creating sniffer on interface: {self.interface}")
            # Use default filter if none specified
            capture_filter = self.bpf_filter or "tcp or udp"
            
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._process_packet,
                filter=capture_filter,
                store=False,
                count=0  # Capture indefinitely
            )
            
            logger.info(f"Using capture filter: {capture_filter}")
            
            # Start sniffer
            logger.info("Starting sniffer...")
            self.sniffer.start()
            
            # Wait a moment to ensure sniffer is running
            await asyncio.sleep(0.5)
            
            if not self.sniffer.running:
                raise Exception("Sniffer failed to start")
                
        except Exception as e:
            logger.error(f"Failed to start sniffer: {e}")
            raise
        
        # Start statistics update task
        self.stats_task = asyncio.create_task(self._update_statistics())
        
        logger.info("Capture started successfully")
        
    async def stop(self):
        """Stop packet capture"""
        if not self.is_running:
            return
            
        logger.info("Stopping capture...")
        self.is_running = False
        
        # Cancel statistics task
        if self.stats_task and not self.stats_task.done():
            self.stats_task.cancel()
            try:
                await self.stats_task
            except asyncio.CancelledError:
                pass
        
        if self.sniffer:
            self.sniffer.stop()
            
        logger.info("Capture stopped")
        
    def pause(self):
        """Pause packet capture"""
        self.is_paused = True
        logger.info("Capture paused")
        
    def resume(self):
        """Resume packet capture"""
        self.is_paused = False
        logger.info("Capture resumed")
        
    def _process_packet(self, packet):
        """Process captured packet"""
        if self.is_paused:
            return
            
        try:
            # Update statistics
            self.total_packets += 1
            packet_size = len(packet)
            self.total_bytes += packet_size
            self.packets_since_last_stats += 1
            self.bytes_since_last_stats += packet_size
            
            # Determine protocol
            protocol = self._get_protocol(packet)
            self.packets_per_protocol[protocol] = self.packets_per_protocol.get(protocol, 0) + 1
            self.bytes_per_protocol[protocol] = self.bytes_per_protocol.get(protocol, 0) + packet_size
            
            # Extract packet info
            packet_info = self._extract_packet_info(packet)
            
            # Store raw packet for detailed analysis
            packet_info['raw_packet'] = packet

            # Add to buffer
            self.packet_buffer.append(packet_info)
            
            # Call packet callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            
    def _get_protocol(self, packet) -> str:
        """Determine packet protocol"""
        if packet.haslayer(TCP):
            # Check for specific protocols on TCP
            if packet.haslayer(DNS):
                return "DNS"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport == 80 or dport == 80:
                return "HTTP"
            elif sport == 443 or dport == 443:
                return "HTTPS"
            elif sport == 22 or dport == 22:
                return "SSH"
            elif sport == 21 or dport == 21:
                return "FTP"
            elif sport == 25 or dport == 25:
                return "SMTP"
            return "TCP"
        elif packet.haslayer(UDP):
            if packet.haslayer(DNS):
                return "DNS"
            elif packet.haslayer(DHCP):
                return "DHCP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if sport == 123 or dport == 123:
                return "NTP"
            elif sport == 5353 or dport == 5353:
                return "mDNS"
            elif sport == 1900 or dport == 1900:
                return "SSDP"
            elif dport == 443 or sport == 443:
                return "QUIC"
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(IPv6):
            return "IPv6"
        else:
            return "Other"
            
    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """Extract detailed packet information"""
        info = {
            'timestamp': datetime.now(),
            'size': len(packet),
            'protocol': self._get_protocol(packet),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'info': '',
            'raw_packet': packet
        }
        
        # Extract IP layer info
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
        elif packet.haslayer(IPv6):
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst
            
        # Extract TCP info
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info['src_port'] = tcp.sport
            info['dst_port'] = tcp.dport
            info['flags'] = self._get_tcp_flags(tcp)
            info['seq'] = tcp.seq
            info['ack'] = tcp.ack
            
        # Extract UDP info
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info['src_port'] = udp.sport
            info['dst_port'] = udp.dport
            
        # Extract ICMP info
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info['icmp_type'] = icmp.type
            info['icmp_code'] = icmp.code
            info['info'] = self._get_icmp_info(icmp)
            
        # Extract ARP info
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            info['src_ip'] = arp.psrc
            info['dst_ip'] = arp.pdst
            info['src_mac'] = arp.hwsrc
            info['dst_mac'] = arp.hwdst
            info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
            
        # Extract DNS info
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qd:
                info['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore')
                info['info'] = f"DNS Query: {info['dns_query']}"
                
        # Extract DHCP info
        if packet.haslayer(DHCP):
            info['info'] = "DHCP"
            
        return info
        
    def _get_tcp_flags(self, tcp) -> str:
        """Get TCP flags as string"""
        if not tcp or not hasattr(tcp, 'flags'):
            return 'None'
        
        # Check if flags is None
        if tcp.flags is None:
            return 'None'
            
        flags = []
        try:
            # Safely check each flag attribute
            flags_obj = tcp.flags
            if hasattr(flags_obj, 'F') and 'F' in str(flags_obj): flags.append('FIN')
            if hasattr(flags_obj, 'S') and 'S' in str(flags_obj): flags.append('SYN')
            if hasattr(flags_obj, 'R') and 'R' in str(flags_obj): flags.append('RST')
            if hasattr(flags_obj, 'P') and 'P' in str(flags_obj): flags.append('PSH')
            if hasattr(flags_obj, 'A') and 'A' in str(flags_obj): flags.append('ACK')
            if hasattr(flags_obj, 'U') and 'U' in str(flags_obj): flags.append('URG')
            if hasattr(flags_obj, 'E') and 'E' in str(flags_obj): flags.append('ECE')
            if hasattr(flags_obj, 'C') and 'C' in str(flags_obj): flags.append('CWR')
        except (AttributeError, TypeError, ValueError) as e:
            logger.debug(f"Error parsing TCP flags: {e}")
            return 'None'
            
        return '|'.join(flags) if flags else 'None'
        
    def _get_icmp_info(self, icmp) -> str:
        """Get ICMP type description"""
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply"
        }
        return icmp_types.get(icmp.type, f"Type {icmp.type}")
        
    async def _update_statistics(self):
        """Periodically update statistics"""
        while self.is_running:
            await asyncio.sleep(1.0)
            
            current_time = time.time()
            time_delta = current_time - self.last_stats_time
            
            if time_delta >= 1.0:
                # Calculate rates
                pps = self.packets_since_last_stats / time_delta
                bps = self.bytes_since_last_stats / time_delta
                
                stats = {
                    'total_packets': self.total_packets,
                    'total_bytes': self.total_bytes,
                    'pps': pps,
                    'bps': bps,
                    'duration': current_time - self.start_time if self.start_time else 0,
                    'packets_per_protocol': self.packets_per_protocol.copy(),
                    'bytes_per_protocol': self.bytes_per_protocol.copy()
                }
                
                # Call statistics callbacks
                for callback in self.statistics_callbacks:
                    try:
                        callback(stats)
                    except Exception as e:
                        logger.error(f"Error in statistics callback: {e}")
                        
                # Reset counters
                self.packets_since_last_stats = 0
                self.bytes_since_last_stats = 0
                self.last_stats_time = current_time
                
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics"""
        duration = time.time() - self.start_time if self.start_time else 0
        
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'duration': duration,
            'avg_pps': self.total_packets / duration if duration > 0 else 0,
            'avg_bps': self.total_bytes / duration if duration > 0 else 0,
            'packets_per_protocol': self.packets_per_protocol.copy(),
            'bytes_per_protocol': self.bytes_per_protocol.copy(),
            'buffer_size': len(self.packet_buffer)
        }
        
    def get_packets(self, count: Optional[int] = None) -> list:
        """Get packets from buffer"""
        if count is None:
            return list(self.packet_buffer)
        else:
            return list(self.packet_buffer)[-count:]
            
    def clear_buffer(self):
        """Clear packet buffer"""
        self.packet_buffer.clear()
        logger.info("Packet buffer cleared")
        
    def reset_statistics(self):
        """Reset all statistics"""
        self.total_packets = 0
        self.total_bytes = 0
        self.packets_per_protocol.clear()
        self.bytes_per_protocol.clear()
        self.start_time = time.time()
        logger.info("Statistics reset")
