"""
Filter Engine
Advanced packet filtering with multiple criteria
"""

import re
import ipaddress
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class FilterEngine:
    """Advanced packet filtering system"""
    
    def __init__(self):
        self.active_filters = []
        self.filter_presets = {}
        
    def add_filter(self, filter_func: Callable, name: str = None):
        """Add a filter function"""
        self.active_filters.append({
            'name': name or f"Filter_{len(self.active_filters)}",
            'func': filter_func
        })
        
    def remove_filter(self, name: str):
        """Remove a filter by name"""
        self.active_filters = [f for f in self.active_filters if f['name'] != name]
        
    def clear_filters(self):
        """Clear all active filters"""
        self.active_filters.clear()
        
    def apply_filters(self, packet_info: Dict[str, Any]) -> bool:
        """Apply all active filters to a packet"""
        if not self.active_filters:
            return True
            
        for filter_dict in self.active_filters:
            try:
                if not filter_dict['func'](packet_info):
                    return False
            except Exception as e:
                logger.error(f"Error applying filter {filter_dict['name']}: {e}")
                
        return True
        
    def create_ip_filter(self, ip_range: str, direction: str = 'both') -> Callable:
        """Create IP range filter"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            
            def filter_func(packet_info: Dict[str, Any]) -> bool:
                src_ip = packet_info.get('src_ip')
                dst_ip = packet_info.get('dst_ip')
                
                if not src_ip and not dst_ip:
                    return False
                    
                try:
                    if direction in ['src', 'both'] and src_ip:
                        if ipaddress.ip_address(src_ip) in network:
                            return True
                            
                    if direction in ['dst', 'both'] and dst_ip:
                        if ipaddress.ip_address(dst_ip) in network:
                            return True
                            
                except ValueError:
                    pass
                    
                return False
                
            return filter_func
            
        except ValueError as e:
            logger.error(f"Invalid IP range: {ip_range}")
            return lambda x: True
            
    def create_port_filter(self, ports: List[int], direction: str = 'both') -> Callable:
        """Create port filter"""
        port_set = set(ports)
        
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            
            if direction in ['src', 'both'] and src_port in port_set:
                return True
                
            if direction in ['dst', 'both'] and dst_port in port_set:
                return True
                
            return False
            
        return filter_func
        
    def create_protocol_filter(self, protocols: List[str]) -> Callable:
        """Create protocol filter"""
        protocol_set = set(p.upper() for p in protocols)
        
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            protocol = packet_info.get('protocol', '').upper()
            return protocol in protocol_set
            
        return filter_func
        
    def create_direction_filter(self, direction: str, local_networks: List[str]) -> Callable:
        """Create direction filter (inbound/outbound)"""
        networks = [ipaddress.ip_network(net, strict=False) for net in local_networks]
        
        def is_local(ip: str) -> bool:
            try:
                ip_addr = ipaddress.ip_address(ip)
                return any(ip_addr in net for net in networks)
            except ValueError:
                return False
                
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            
            if not src_ip or not dst_ip:
                return False
                
            src_local = is_local(src_ip)
            dst_local = is_local(dst_ip)
            
            if direction == 'in':
                return not src_local and dst_local
            elif direction == 'out':
                return src_local and not dst_local
            elif direction == 'local':
                return src_local and dst_local
            else:
                return True
                
        return filter_func
        
    def create_time_filter(self, start_time: datetime, end_time: datetime) -> Callable:
        """Create time-based filter"""
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            timestamp = packet_info.get('timestamp')
            if not timestamp:
                return False
            return start_time <= timestamp <= end_time
            
        return filter_func
        
    def create_size_filter(self, min_size: int = 0, max_size: int = 65535) -> Callable:
        """Create packet size filter"""
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            size = packet_info.get('size', 0)
            return min_size <= size <= max_size
            
        return filter_func
        
    def create_dns_filter(self, domain_pattern: str) -> Callable:
        """Create DNS domain filter"""
        pattern = re.compile(domain_pattern, re.IGNORECASE)
        
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            dns_query = packet_info.get('dns_query', '')
            return bool(pattern.search(dns_query))
            
        return filter_func
        
    def create_flags_filter(self, required_flags: List[str]) -> Callable:
        """Create TCP flags filter"""
        flag_set = set(f.upper() for f in required_flags)
        
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            flags = packet_info.get('flags')
            if not flags or flags == 'None':
                return False
            packet_flags = set(flags.split('|'))
            return flag_set.issubset(packet_flags)
            
        return filter_func
        
    def create_combined_filter(self, filters: List[Callable], operator: str = 'AND') -> Callable:
        """Create combined filter with AND/OR logic"""
        def filter_func(packet_info: Dict[str, Any]) -> bool:
            if operator.upper() == 'AND':
                return all(f(packet_info) for f in filters)
            elif operator.upper() == 'OR':
                return any(f(packet_info) for f in filters)
            else:
                return True
                
        return filter_func
        
    def save_preset(self, name: str, filters: List[Dict[str, Any]]):
        """Save filter preset"""
        self.filter_presets[name] = filters
        logger.info(f"Filter preset '{name}' saved")
        
    def load_preset(self, name: str) -> bool:
        """Load filter preset"""
        if name not in self.filter_presets:
            logger.warning(f"Filter preset '{name}' not found")
            return False
            
        self.clear_filters()
        
        for filter_config in self.filter_presets[name]:
            filter_type = filter_config.get('type')
            params = filter_config.get('params', {})
            
            if filter_type == 'ip':
                filter_func = self.create_ip_filter(**params)
            elif filter_type == 'port':
                filter_func = self.create_port_filter(**params)
            elif filter_type == 'protocol':
                filter_func = self.create_protocol_filter(**params)
            elif filter_type == 'direction':
                filter_func = self.create_direction_filter(**params)
            elif filter_type == 'time':
                filter_func = self.create_time_filter(**params)
            elif filter_type == 'size':
                filter_func = self.create_size_filter(**params)
            elif filter_type == 'dns':
                filter_func = self.create_dns_filter(**params)
            elif filter_type == 'flags':
                filter_func = self.create_flags_filter(**params)
            else:
                continue
                
            self.add_filter(filter_func, filter_config.get('name'))
            
        logger.info(f"Filter preset '{name}' loaded")
        return True
        
    def get_preset_names(self) -> List[str]:
        """Get list of saved preset names"""
        return list(self.filter_presets.keys())
        
    def delete_preset(self, name: str):
        """Delete a filter preset"""
        if name in self.filter_presets:
            del self.filter_presets[name]
            logger.info(f"Filter preset '{name}' deleted")


class QuickFilters:
    """Pre-defined quick filters"""
    
    @staticmethod
    def http_https():
        """Filter for HTTP/HTTPS traffic"""
        return lambda p: p.get('protocol') in ['HTTP', 'HTTPS']
        
    @staticmethod
    def dns():
        """Filter for DNS traffic"""
        return lambda p: p.get('protocol') == 'DNS'
        
    @staticmethod
    def local_network():
        """Filter for local network traffic"""
        def filter_func(p):
            src = p.get('src_ip') or ''
            dst = p.get('dst_ip') or ''
            return (src.startswith('192.168.') or src.startswith('10.') or 
                   dst.startswith('192.168.') or dst.startswith('10.'))
        return filter_func
        
    @staticmethod
    def external_traffic():
        """Filter for external traffic"""
        def filter_func(p):
            src = p.get('src_ip') or ''
            dst = p.get('dst_ip') or ''
            local_prefixes = ('192.168.', '10.', '172.16.', '127.')
            src_local = any(src.startswith(prefix) for prefix in local_prefixes) if src else False
            dst_local = any(dst.startswith(prefix) for prefix in local_prefixes) if dst else False
            return not (src_local and dst_local)
        return filter_func
        
    @staticmethod
    def suspicious_ports():
        """Filter for suspicious port traffic"""
        suspicious = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5900}
        def filter_func(p):
            src_port = p.get('src_port')
            dst_port = p.get('dst_port')
            return (src_port in suspicious if src_port else False) or (dst_port in suspicious if dst_port else False)
        return filter_func
        
    @staticmethod
    def large_packets():
        """Filter for large packets (>1000 bytes)"""
        return lambda p: p.get('size', 0) > 1000
        
    @staticmethod
    def syn_packets():
        """Filter for TCP SYN packets"""
        def filter_func(p):
            flags = p.get('flags')
            if not flags or flags == 'None':
                return False
            return 'SYN' in flags
        return filter_func
        
    @staticmethod
    def encrypted_traffic():
        """Filter for encrypted traffic"""
        return lambda p: p.get('protocol') in ['HTTPS', 'TLS', 'SSH', 'QUIC']
