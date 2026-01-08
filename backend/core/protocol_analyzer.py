"""
Protocol Analyzer
Deep packet inspection and protocol analysis
"""

import struct
import logging
from typing import Dict, Any, Optional
from scapy.all import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from datetime import datetime

logger = logging.getLogger(__name__)


class ProtocolAnalyzer:
    """Advanced protocol analysis"""
    
    def __init__(self):
        self.tls_versions = {
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3"
        }
        
    def analyze_packet(self, packet) -> Dict[str, Any]:
        """Perform deep packet analysis"""
        analysis = {
            'timestamp': datetime.now(),
            'protocols': [],
            'details': {}
        }
        
        # Analyze each protocol layer
        if packet.haslayer(TCP):
            analysis['protocols'].append('TCP')
            analysis['details']['tcp'] = self.analyze_tcp(packet)
            
            # Check for TLS/HTTPS
            if packet.haslayer(Raw):
                tls_info = self.analyze_tls(packet)
                if tls_info:
                    analysis['protocols'].append('TLS')
                    analysis['details']['tls'] = tls_info
                    
        if packet.haslayer(UDP):
            analysis['protocols'].append('UDP')
            analysis['details']['udp'] = self.analyze_udp(packet)
            
            # Check for QUIC
            quic_info = self.analyze_quic(packet)
            if quic_info:
                analysis['protocols'].append('QUIC')
                analysis['details']['quic'] = quic_info
                
        if packet.haslayer(DNS):
            analysis['protocols'].append('DNS')
            analysis['details']['dns'] = self.analyze_dns(packet)
            
        return analysis
        
    def analyze_tcp(self, packet) -> Dict[str, Any]:
        """Analyze TCP packet"""
        tcp = packet[TCP]
        
        flags = {
            'FIN': bool(tcp.flags.F),
            'SYN': bool(tcp.flags.S),
            'RST': bool(tcp.flags.R),
            'PSH': bool(tcp.flags.P),
            'ACK': bool(tcp.flags.A),
            'URG': bool(tcp.flags.U),
            'ECE': bool(tcp.flags.E),
            'CWR': bool(tcp.flags.C)
        }
        
        return {
            'src_port': tcp.sport,
            'dst_port': tcp.dport,
            'seq': tcp.seq,
            'ack': tcp.ack,
            'flags': flags,
            'window': tcp.window,
            'checksum': tcp.chksum,
            'urgent_pointer': tcp.urgptr,
            'options': str(tcp.options) if tcp.options else None
        }
        
    def analyze_udp(self, packet) -> Dict[str, Any]:
        """Analyze UDP packet"""
        udp = packet[UDP]
        
        return {
            'src_port': udp.sport,
            'dst_port': udp.dport,
            'length': udp.len,
            'checksum': udp.chksum
        }
        
    def analyze_dns(self, packet) -> Dict[str, Any]:
        """Analyze DNS packet"""
        dns = packet[DNS]
        
        queries = []
        answers = []
        
        # Extract queries
        if dns.qd:
            try:
                qname = dns.qd.qname.decode('utf-8', errors='ignore')
                queries.append({
                    'name': qname,
                    'type': dns.qd.qtype,
                    'class': dns.qd.qclass
                })
            except:
                pass
                
        # Extract answers
        if dns.an:
            for i in range(dns.ancount):
                try:
                    answer = dns.an[i]
                    answers.append({
                        'name': answer.rrname.decode('utf-8', errors='ignore'),
                        'type': answer.type,
                        'class': answer.rclass,
                        'ttl': answer.ttl,
                        'data': str(answer.rdata)
                    })
                except:
                    pass
                    
        return {
            'id': dns.id,
            'is_response': dns.qr == 1,
            'opcode': dns.opcode,
            'queries': queries,
            'answers': answers,
            'query_count': dns.qdcount,
            'answer_count': dns.ancount
        }
        
    def analyze_tls(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze TLS/SSL packet"""
        if not packet.haslayer(Raw):
            return None
            
        try:
            payload = bytes(packet[Raw].load)
            
            # Check if it's a TLS packet (starts with 0x16 for handshake)
            if len(payload) < 5 or payload[0] not in [0x16, 0x17, 0x14, 0x15]:
                return None
                
            content_type = payload[0]
            version = struct.unpack('!H', payload[1:3])[0]
            length = struct.unpack('!H', payload[3:5])[0]
            
            result = {
                'content_type': self._get_tls_content_type(content_type),
                'version': self.tls_versions.get(version, f"Unknown (0x{version:04x})"),
                'length': length
            }
            
            # Try to extract SNI (Server Name Indication)
            if content_type == 0x16 and len(payload) > 43:  # Handshake
                sni = self._extract_sni(payload)
                if sni:
                    result['sni'] = sni
                    
                # Try to extract ALPN
                alpn = self._extract_alpn(payload)
                if alpn:
                    result['alpn'] = alpn
                    
            return result
            
        except Exception as e:
            logger.debug(f"Error analyzing TLS: {e}")
            return None
            
    def _get_tls_content_type(self, content_type: int) -> str:
        """Get TLS content type name"""
        types = {
            0x14: "ChangeCipherSpec",
            0x15: "Alert",
            0x16: "Handshake",
            0x17: "Application Data"
        }
        return types.get(content_type, f"Unknown ({content_type})")
        
    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Extract Server Name Indication from TLS ClientHello"""
        try:
            # Skip to extensions
            pos = 43  # Skip fixed header
            
            # Skip session ID
            if pos < len(payload):
                session_id_len = payload[pos]
                pos += 1 + session_id_len
                
            # Skip cipher suites
            if pos + 2 <= len(payload):
                cipher_suites_len = struct.unpack('!H', payload[pos:pos+2])[0]
                pos += 2 + cipher_suites_len
                
            # Skip compression methods
            if pos < len(payload):
                compression_len = payload[pos]
                pos += 1 + compression_len
                
            # Parse extensions
            if pos + 2 <= len(payload):
                extensions_len = struct.unpack('!H', payload[pos:pos+2])[0]
                pos += 2
                
                end = pos + extensions_len
                while pos + 4 <= end:
                    ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
                    ext_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
                    pos += 4
                    
                    # SNI extension (type 0)
                    if ext_type == 0 and pos + ext_len <= len(payload):
                        sni_data = payload[pos:pos+ext_len]
                        if len(sni_data) > 5:
                            name_len = struct.unpack('!H', sni_data[3:5])[0]
                            if len(sni_data) >= 5 + name_len:
                                return sni_data[5:5+name_len].decode('utf-8', errors='ignore')
                                
                    pos += ext_len
                    
        except Exception as e:
            logger.debug(f"Error extracting SNI: {e}")
            
        return None
        
    def _extract_alpn(self, payload: bytes) -> Optional[list]:
        """Extract ALPN protocols from TLS ClientHello"""
        try:
            pos = 43
            
            # Skip to extensions (same as SNI)
            if pos < len(payload):
                session_id_len = payload[pos]
                pos += 1 + session_id_len
                
            if pos + 2 <= len(payload):
                cipher_suites_len = struct.unpack('!H', payload[pos:pos+2])[0]
                pos += 2 + cipher_suites_len
                
            if pos < len(payload):
                compression_len = payload[pos]
                pos += 1 + compression_len
                
            if pos + 2 <= len(payload):
                extensions_len = struct.unpack('!H', payload[pos:pos+2])[0]
                pos += 2
                
                end = pos + extensions_len
                while pos + 4 <= end:
                    ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
                    ext_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
                    pos += 4
                    
                    # ALPN extension (type 16)
                    if ext_type == 16 and pos + ext_len <= len(payload):
                        alpn_data = payload[pos:pos+ext_len]
                        protocols = []
                        alpn_pos = 2  # Skip length
                        
                        while alpn_pos < len(alpn_data):
                            proto_len = alpn_data[alpn_pos]
                            alpn_pos += 1
                            if alpn_pos + proto_len <= len(alpn_data):
                                proto = alpn_data[alpn_pos:alpn_pos+proto_len].decode('utf-8', errors='ignore')
                                protocols.append(proto)
                                alpn_pos += proto_len
                            else:
                                break
                                
                        return protocols if protocols else None
                        
                    pos += ext_len
                    
        except Exception as e:
            logger.debug(f"Error extracting ALPN: {e}")
            
        return None
        
    def analyze_quic(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze QUIC packet"""
        if not packet.haslayer(UDP):
            return None
            
        udp = packet[UDP]
        
        # QUIC typically uses port 443
        if udp.dport != 443 and udp.sport != 443:
            return None
            
        if not packet.haslayer(Raw):
            return None
            
        try:
            payload = bytes(packet[Raw].load)
            
            if len(payload) < 1:
                return None
                
            # Check QUIC header flags
            first_byte = payload[0]
            
            # Long header (0x80 bit set)
            if first_byte & 0x80:
                return {
                    'header_type': 'long',
                    'version': 'QUIC',
                    'detected': True
                }
            # Short header
            else:
                return {
                    'header_type': 'short',
                    'version': 'QUIC',
                    'detected': True
                }
                
        except Exception as e:
            logger.debug(f"Error analyzing QUIC: {e}")
            
        return None
        
    def analyze_http(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze HTTP packet"""
        if not packet.haslayer(Raw):
            return None
            
        try:
            payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
            
            # Check for HTTP request
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                lines = payload.split('\r\n')
                method, path, version = lines[0].split(' ', 2)
                
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                        
                return {
                    'type': 'request',
                    'method': method,
                    'path': path,
                    'version': version,
                    'headers': headers,
                    'host': headers.get('Host', 'Unknown')
                }
                
            # Check for HTTP response
            elif payload.startswith('HTTP/'):
                lines = payload.split('\r\n')
                parts = lines[0].split(' ', 2)
                version = parts[0]
                status_code = int(parts[1]) if len(parts) > 1 else 0
                status_text = parts[2] if len(parts) > 2 else ''
                
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                        
                return {
                    'type': 'response',
                    'version': version,
                    'status_code': status_code,
                    'status_text': status_text,
                    'headers': headers
                }
                
        except Exception as e:
            logger.debug(f"Error analyzing HTTP: {e}")
            
        return None
