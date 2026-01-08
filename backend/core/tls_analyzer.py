"""
TLS/HTTPS Analyzer
Advanced TLS handshake capture and HTTPS decoding
"""

import struct
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import hashlib
import base64

logger = logging.getLogger(__name__)


@dataclass
class TLSHandshake:
    """TLS Handshake information"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    
    # Handshake stages
    client_hello: Optional[Dict] = None
    server_hello: Optional[Dict] = None
    certificate: Optional[Dict] = None
    server_key_exchange: Optional[Dict] = None
    server_hello_done: bool = False
    client_key_exchange: Optional[Dict] = None
    change_cipher_spec_client: bool = False
    change_cipher_spec_server: bool = False
    finished_client: bool = False
    finished_server: bool = False
    
    # Handshake status
    is_complete: bool = False
    handshake_duration: Optional[float] = None
    
    # TLS details
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    compression_method: Optional[int] = None
    
    # Extensions
    sni: Optional[str] = None
    alpn: Optional[List[str]] = None
    supported_groups: Optional[List[str]] = None
    signature_algorithms: Optional[List[str]] = None
    
    # Certificate details
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_valid_from: Optional[str] = None
    cert_valid_to: Optional[str] = None
    cert_serial: Optional[str] = None
    cert_fingerprint: Optional[str] = None
    
    # JA3 fingerprint
    ja3_hash: Optional[str] = None
    ja3_string: Optional[str] = None
    
    # Session
    session_id: Optional[bytes] = None
    session_ticket: Optional[bytes] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'is_complete': self.is_complete,
            'handshake_duration': self.handshake_duration,
            'tls_version': self.tls_version,
            'cipher_suite': self.cipher_suite,
            'sni': self.sni,
            'alpn': self.alpn,
            'cert_subject': self.cert_subject,
            'cert_issuer': self.cert_issuer,
            'cert_valid_from': self.cert_valid_from,
            'cert_valid_to': self.cert_valid_to,
            'ja3_hash': self.ja3_hash
        }


class TLSAnalyzer:
    """Advanced TLS/HTTPS analyzer"""
    
    # TLS versions
    TLS_VERSIONS = {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3"
    }
    
    # Common cipher suites
    CIPHER_SUITES = {
        0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256"
    }
    
    # Extension types
    EXTENSION_TYPES = {
        0: "server_name",
        1: "max_fragment_length",
        5: "status_request",
        10: "supported_groups",
        11: "ec_point_formats",
        13: "signature_algorithms",
        16: "application_layer_protocol_negotiation",
        18: "signed_certificate_timestamp",
        23: "extended_master_secret",
        35: "session_ticket",
        43: "supported_versions",
        45: "psk_key_exchange_modes",
        51: "key_share"
    }
    
    def __init__(self):
        self.handshakes: Dict[Tuple, TLSHandshake] = {}
        self.completed_handshakes: List[TLSHandshake] = []
        self.handshake_callbacks = []
        
    def add_handshake_callback(self, callback):
        """Add callback for completed handshakes"""
        self.handshake_callbacks.append(callback)
        
    def analyze_packet(self, packet) -> Optional[TLSHandshake]:
        """Analyze packet for TLS handshake"""
        try:
            from scapy.layers.inet import TCP, IP
            from scapy.packet import Raw
            
            if not packet.haslayer(TCP):
                return None

            tcp = packet[TCP]

            # Check if it's likely TLS (port 443 or other common TLS ports)
            tls_ports = {443, 8443, 4433, 10443}
            if tcp.dport not in tls_ports and tcp.sport not in tls_ports:
                return None

            if not packet.haslayer(Raw):
                return None
        except Exception as e:
            logger.debug(f"Error checking packet layers: {e}")
            return None
            
        try:
            from scapy.packet import Raw
            payload = bytes(packet[Raw].load)
            
            # Check TLS record header
            if len(payload) < 5:
                return None
                
            content_type = payload[0]
            
            # 0x16 = Handshake, 0x14 = ChangeCipherSpec, 0x17 = Application Data
            if content_type not in [0x16, 0x14, 0x17]:
                return None
            
            # Verify TLS version in record header
            tls_version_major = payload[1]
            tls_version_minor = payload[2]
            
            # TLS versions: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2), 0x0304 (TLS 1.3)
            if tls_version_major != 0x03:
                return None
                
            # Get or create handshake
            from scapy.layers.inet import IP
            flow_key = self._get_flow_key(packet)
            if flow_key not in self.handshakes:
                self.handshakes[flow_key] = TLSHandshake(
                    timestamp=datetime.now(),
                    src_ip=packet[IP].src,
                    dst_ip=packet[IP].dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport
                )
            
            handshake = self.handshakes[flow_key]
            
            # Process TLS record
            if content_type == 0x16:  # Handshake
                self._process_handshake_record(handshake, payload)
            elif content_type == 0x14:  # ChangeCipherSpec
                self._process_change_cipher_spec(handshake, packet)
            
            # Check if handshake is complete
            if self._is_handshake_complete(handshake):
                handshake.is_complete = True
                handshake.handshake_duration = (datetime.now() - handshake.timestamp).total_seconds()
                
                self.completed_handshakes.append(handshake)
                del self.handshakes[flow_key]
                
                # Notify callbacks
                for callback in self.handshake_callbacks:
                    try:
                        callback(handshake)
                    except Exception as e:
                        logger.error(f"Error in handshake callback: {e}")
                
                logger.info(f"TLS handshake complete: {handshake.src_ip}:{handshake.src_port} -> "
                          f"{handshake.dst_ip}:{handshake.dst_port} ({handshake.tls_version})")
            
            return handshake
            
        except Exception as e:
            logger.debug(f"Error analyzing TLS packet: {e}")
            return None
    
    def _get_flow_key(self, packet) -> Tuple:
        """Get flow key from packet"""
        from scapy.layers.inet import IP, TCP
        ip = packet[IP]
        tcp = packet[TCP]
        return (ip.src, tcp.sport, ip.dst, tcp.dport)
    
    def _process_handshake_record(self, handshake: TLSHandshake, payload: bytes):
        """Process TLS handshake record"""
        if len(payload) < 6:
            return
            
        # Skip record header (5 bytes)
        pos = 5
        
        while pos < len(payload):
            if pos + 4 > len(payload):
                break
                
            # Handshake message header
            msg_type = payload[pos]
            msg_length = struct.unpack('!I', b'\x00' + payload[pos+1:pos+4])[0]
            
            if pos + 4 + msg_length > len(payload):
                break
                
            msg_data = payload[pos+4:pos+4+msg_length]
            
            # Process based on message type
            if msg_type == 1:  # ClientHello
                self._process_client_hello(handshake, msg_data)
            elif msg_type == 2:  # ServerHello
                self._process_server_hello(handshake, msg_data)
            elif msg_type == 11:  # Certificate
                self._process_certificate(handshake, msg_data)
            elif msg_type == 12:  # ServerKeyExchange
                handshake.server_key_exchange = {'received': True}
            elif msg_type == 14:  # ServerHelloDone
                handshake.server_hello_done = True
            elif msg_type == 16:  # ClientKeyExchange
                handshake.client_key_exchange = {'received': True}
            elif msg_type == 20:  # Finished
                if handshake.change_cipher_spec_client and not handshake.finished_client:
                    handshake.finished_client = True
                elif handshake.change_cipher_spec_server and not handshake.finished_server:
                    handshake.finished_server = True
            
            pos += 4 + msg_length
    
    def _process_client_hello(self, handshake: TLSHandshake, data: bytes):
        """Process ClientHello message"""
        if len(data) < 38:
            return
            
        pos = 0
        
        # TLS version
        version = struct.unpack('!H', data[pos:pos+2])[0]
        handshake.tls_version = self.TLS_VERSIONS.get(version, f"Unknown (0x{version:04x})")
        pos += 2
        
        # Random (32 bytes) - used for session tracking
        client_random = data[pos:pos+32]
        pos += 32
        
        # Session ID
        session_id_len = data[pos]
        pos += 1
        if session_id_len > 0 and pos + session_id_len <= len(data):
            handshake.session_id = data[pos:pos+session_id_len]
            pos += session_id_len
        
        # Cipher suites
        if pos + 2 > len(data):
            return
        cipher_suites_len = struct.unpack('!H', data[pos:pos+2])[0]
        pos += 2
        
        cipher_suites = []
        cipher_end = pos + cipher_suites_len
        while pos < cipher_end and pos + 2 <= len(data):
            cipher = struct.unpack('!H', data[pos:pos+2])[0]
            cipher_suites.append(cipher)
            pos += 2
        
        # Compression methods
        if pos >= len(data):
            return
        compression_len = data[pos]
        pos += 1
        if pos + compression_len <= len(data):
            pos += compression_len
        
        # Extensions
        extensions_data = b''
        if pos + 2 <= len(data):
            extensions_data = data[pos:]
            self._process_extensions(handshake, extensions_data, is_client=True)
        
        # Calculate JA3 fingerprint (enhanced)
        handshake.ja3_string, handshake.ja3_hash = self._calculate_ja3(
            version, cipher_suites, extensions_data
        )
        
        # Store all cipher suites (not just first 10)
        handshake.client_hello = {
            'version': handshake.tls_version,
            'cipher_suites': [self.CIPHER_SUITES.get(c, f"0x{c:04x}") for c in cipher_suites],
            'cipher_count': len(cipher_suites),
            'random': client_random.hex() if client_random else None
        }
    
    def _process_server_hello(self, handshake: TLSHandshake, data: bytes):
        """Process ServerHello message"""
        if len(data) < 38:
            return
            
        pos = 0
        
        # TLS version
        version = struct.unpack('!H', data[pos:pos+2])[0]
        if not handshake.tls_version:
            handshake.tls_version = self.TLS_VERSIONS.get(version, f"Unknown (0x{version:04x})")
        pos += 2
        
        # Random (32 bytes)
        server_random = data[pos:pos+32]
        pos += 32
        
        # Session ID
        session_id_len = data[pos]
        pos += 1 + session_id_len
        
        # Cipher suite
        if pos + 2 > len(data):
            return
        cipher = struct.unpack('!H', data[pos:pos+2])[0]
        handshake.cipher_suite = self.CIPHER_SUITES.get(cipher, f"0x{cipher:04x}")
        pos += 2
        
        # Compression method
        if pos < len(data):
            handshake.compression_method = data[pos]
            pos += 1
        
        # Extensions
        if pos + 2 <= len(data):
            self._process_extensions(handshake, data[pos:], is_client=False)
        
        handshake.server_hello = {
            'version': handshake.tls_version,
            'cipher_suite': handshake.cipher_suite,
            'compression': handshake.compression_method
        }
    
    def _process_certificate(self, handshake: TLSHandshake, data: bytes):
        """Process Certificate message (enhanced)"""
        if len(data) < 3:
            return
            
        # Certificates length
        certs_len = struct.unpack('!I', b'\x00' + data[0:3])[0]
        pos = 3
        
        # Parse first certificate (enhanced parsing)
        if pos + 3 <= len(data):
            cert_len = struct.unpack('!I', b'\x00' + data[pos:pos+3])[0]
            pos += 3
            
            if pos + cert_len <= len(data):
                cert_data = data[pos:pos+cert_len]
                
                # Calculate fingerprints
                handshake.cert_fingerprint = hashlib.sha256(cert_data).hexdigest()
                
                # Try to use cryptography library for proper parsing
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                    
                    # Extract subject
                    subject = cert.subject
                    cn = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                    if cn:
                        handshake.cert_subject = cn[0].value
                    
                    # Extract issuer
                    issuer = cert.issuer
                    issuer_cn = issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                    if issuer_cn:
                        handshake.cert_issuer = issuer_cn[0].value
                    
                    # Extract validity
                    handshake.cert_valid_from = cert.not_valid_before.isoformat()
                    handshake.cert_valid_to = cert.not_valid_after.isoformat()
                    
                    # Extract serial number
                    handshake.cert_serial = str(cert.serial_number)
                    
                    logger.info(f"Certificate parsed: {handshake.cert_subject}")
                    
                except ImportError:
                    # Fallback to basic parsing if cryptography not available
                    logger.debug("cryptography library not available, using basic parsing")
                    try:
                        cert_str = cert_data.decode('utf-8', errors='ignore')
                        if 'CN=' in cert_str:
                            cn_start = cert_str.find('CN=') + 3
                            cn_end = cert_str.find(',', cn_start)
                            if cn_end == -1:
                                cn_end = min(cn_start + 100, len(cert_str))
                            handshake.cert_subject = cert_str[cn_start:cn_end].strip()
                    except Exception as e:
                        logger.debug(f"Error in basic cert parsing: {e}")
                
                except Exception as e:
                    logger.debug(f"Error parsing certificate: {e}")
                
                handshake.certificate = {
                    'fingerprint': handshake.cert_fingerprint,
                    'subject': handshake.cert_subject,
                    'issuer': handshake.cert_issuer,
                    'size': cert_len,
                    'valid_from': handshake.cert_valid_from,
                    'valid_to': handshake.cert_valid_to
                }
    
    def _process_extensions(self, handshake: TLSHandshake, data: bytes, is_client: bool):
        """Process TLS extensions"""
        if len(data) < 2:
            return
            
        extensions_len = struct.unpack('!H', data[0:2])[0]
        pos = 2
        
        # Track all extensions for better fingerprinting
        extensions_found = []
        
        while pos + 4 <= len(data) and pos < 2 + extensions_len:
            ext_type = struct.unpack('!H', data[pos:pos+2])[0]
            ext_len = struct.unpack('!H', data[pos+2:pos+4])[0]
            pos += 4
            
            if pos + ext_len > len(data):
                break
                
            ext_data = data[pos:pos+ext_len]
            extensions_found.append(ext_type)
            
            # Server Name Indication (SNI)
            if ext_type == 0 and len(ext_data) > 5:
                try:
                    name_len = struct.unpack('!H', ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        handshake.sni = ext_data[5:5+name_len].decode('utf-8', errors='ignore')
                        logger.info(f"TLS SNI detected: {handshake.sni}")
                except Exception as e:
                    logger.debug(f"Error parsing SNI: {e}")
            
            # ALPN
            elif ext_type == 16 and len(ext_data) > 2:
                try:
                    alpn_len = struct.unpack('!H', ext_data[0:2])[0]
                    alpn_data = ext_data[2:2+alpn_len]
                    protocols = []
                    alpn_pos = 0
                    while alpn_pos < len(alpn_data):
                        proto_len = alpn_data[alpn_pos]
                        alpn_pos += 1
                        if alpn_pos + proto_len <= len(alpn_data):
                            proto = alpn_data[alpn_pos:alpn_pos+proto_len].decode('utf-8', errors='ignore')
                            protocols.append(proto)
                            alpn_pos += proto_len
                        else:
                            break
                    handshake.alpn = protocols
                except Exception as e:
                    logger.debug(f"Error parsing ALPN: {e}")
            
            # Supported Groups (Elliptic Curves)
            elif ext_type == 10 and len(ext_data) > 2:
                try:
                    groups_len = struct.unpack('!H', ext_data[0:2])[0]
                    groups = []
                    for i in range(2, 2 + groups_len, 2):
                        if i + 2 <= len(ext_data):
                            group = struct.unpack('!H', ext_data[i:i+2])[0]
                            groups.append(group)
                    handshake.supported_groups = [str(g) for g in groups]
                except Exception as e:
                    logger.debug(f"Error parsing supported groups: {e}")
            
            # Signature Algorithms
            elif ext_type == 13 and len(ext_data) > 2:
                try:
                    sig_len = struct.unpack('!H', ext_data[0:2])[0]
                    algorithms = []
                    for i in range(2, 2 + sig_len, 2):
                        if i + 2 <= len(ext_data):
                            alg = struct.unpack('!H', ext_data[i:i+2])[0]
                            algorithms.append(alg)
                    handshake.signature_algorithms = [str(a) for a in algorithms]
                except Exception as e:
                    logger.debug(f"Error parsing signature algorithms: {e}")
            
            pos += ext_len
    
    def _calculate_ja3(self, version: int, cipher_suites: List[int], extensions_data: bytes) -> Tuple[str, str]:
        """Calculate JA3 fingerprint (enhanced)"""
        try:
            # Parse extensions from data
            extensions = []
            curves = []
            point_formats = []
            
            if len(extensions_data) >= 2:
                ext_len = struct.unpack('!H', extensions_data[0:2])[0]
                pos = 2
                
                while pos + 4 <= len(extensions_data) and pos < 2 + ext_len:
                    ext_type = struct.unpack('!H', extensions_data[pos:pos+2])[0]
                    ext_data_len = struct.unpack('!H', extensions_data[pos+2:pos+4])[0]
                    
                    extensions.append(ext_type)
                    
                    # Extract curves (supported_groups, ext_type 10)
                    if ext_type == 10 and pos + 4 + ext_data_len <= len(extensions_data):
                        curve_data = extensions_data[pos+4:pos+4+ext_data_len]
                        if len(curve_data) >= 2:
                            curve_len = struct.unpack('!H', curve_data[0:2])[0]
                            for i in range(2, 2 + curve_len, 2):
                                if i + 2 <= len(curve_data):
                                    curve = struct.unpack('!H', curve_data[i:i+2])[0]
                                    curves.append(curve)
                    
                    # Extract point formats (ext_type 11)
                    elif ext_type == 11 and pos + 4 + ext_data_len <= len(extensions_data):
                        pf_data = extensions_data[pos+4:pos+4+ext_data_len]
                        if len(pf_data) >= 1:
                            pf_len = pf_data[0]
                            for i in range(1, 1 + pf_len):
                                if i < len(pf_data):
                                    point_formats.append(pf_data[i])
                    
                    pos += 4 + ext_data_len
            
            # JA3 = Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            ja3_parts = [
                str(version),
                '-'.join(str(c) for c in cipher_suites),
                '-'.join(str(e) for e in extensions),
                '-'.join(str(c) for c in curves),
                '-'.join(str(p) for p in point_formats)
            ]
            
            ja3_string = ','.join(ja3_parts)
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            
            logger.debug(f"JA3 calculated: {ja3_hash}")
            return ja3_string, ja3_hash
        except Exception as e:
            logger.debug(f"Error calculating JA3: {e}")
            return '', ''
    
    def _process_change_cipher_spec(self, handshake: TLSHandshake, packet):
        """Process ChangeCipherSpec message"""
        from scapy.layers.inet import IP
        # Determine direction
        if packet[IP].src == handshake.src_ip:
            handshake.change_cipher_spec_client = True
        else:
            handshake.change_cipher_spec_server = True
    
    def _is_handshake_complete(self, handshake: TLSHandshake) -> bool:
        """Check if handshake is complete"""
        # Full handshake: ClientHello, ServerHello, Certificate, ServerHelloDone,
        # ClientKeyExchange, ChangeCipherSpec (both), Finished (both)
        return (
            handshake.client_hello is not None and
            handshake.server_hello is not None and
            handshake.server_hello_done and
            handshake.change_cipher_spec_client and
            handshake.change_cipher_spec_server and
            handshake.finished_client and
            handshake.finished_server
        )
    
    def get_handshakes(self, completed_only: bool = True) -> List[TLSHandshake]:
        """Get captured handshakes"""
        if completed_only:
            return self.completed_handshakes
        else:
            return list(self.handshakes.values()) + self.completed_handshakes
    
    def get_handshake_by_ip(self, ip: str) -> List[TLSHandshake]:
        """Get handshakes involving specific IP"""
        return [
            h for h in self.completed_handshakes
            if h.src_ip == ip or h.dst_ip == ip
        ]
    
    def get_handshake_statistics(self) -> Dict:
        """Get handshake statistics"""
        total = len(self.completed_handshakes)
        
        versions = defaultdict(int)
        ciphers = defaultdict(int)
        snis = defaultdict(int)
        
        for h in self.completed_handshakes:
            if h.tls_version:
                versions[h.tls_version] += 1
            if h.cipher_suite:
                ciphers[h.cipher_suite] += 1
            if h.sni:
                snis[h.sni] += 1
        
        return {
            'total_handshakes': total,
            'in_progress': len(self.handshakes),
            'tls_versions': dict(versions),
            'top_ciphers': dict(sorted(ciphers.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_snis': dict(sorted(snis.items(), key=lambda x: x[1], reverse=True)[:10]),
            'avg_duration': sum(h.handshake_duration for h in self.completed_handshakes if h.handshake_duration) / total if total > 0 else 0
        }
    
    def export_handshakes(self, format: str = 'json') -> str:
        """Export handshakes"""
        if format == 'json':
            import json
            return json.dumps([h.to_dict() for h in self.completed_handshakes], indent=2)
        elif format == 'csv':
            lines = ['timestamp,src_ip,dst_ip,tls_version,cipher_suite,sni,duration']
            for h in self.completed_handshakes:
                lines.append(f"{h.timestamp.isoformat()},{h.src_ip},{h.dst_ip},"
                           f"{h.tls_version},{h.cipher_suite},{h.sni},{h.handshake_duration}")
            return '\n'.join(lines)
        else:
            return ''
