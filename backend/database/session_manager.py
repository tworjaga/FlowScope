"""
Session Manager
Manages capture sessions and database operations
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from pathlib import Path
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from .models import Base, Session, Packet, SessionStatistics, FilterPreset, Anomaly, Configuration

logger = logging.getLogger(__name__)


class SessionManager:
    """Manage capture sessions and database"""
    
    def __init__(self, db_path: str = "sessions/analyzer.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create engine
        self.engine = create_engine(f'sqlite:///{self.db_path}', echo=False)
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        # Create session factory
        session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(session_factory)
        
        logger.info(f"Session manager initialized with database: {self.db_path}")
        
    def create_session(self, name: str, description: str = None, 
                      interface: str = None, filter_expr: str = None) -> Session:
        """Create a new capture session"""
        db_session = self.Session()
        
        try:
            session = Session(
                name=name,
                description=description,
                interface=interface,
                filter_expression=filter_expr,
                start_time=datetime.now()
            )
            
            db_session.add(session)
            db_session.commit()
            
            # Create statistics entry
            stats = SessionStatistics(session_id=session.id)
            db_session.add(stats)
            db_session.commit()
            
            logger.info(f"Created session: {name} (ID: {session.id})")
            return session
            
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error creating session: {e}")
            raise
        finally:
            db_session.close()
            
    def get_session(self, session_id: int) -> Optional[Session]:
        """Get session by ID"""
        db_session = self.Session()
        try:
            return db_session.query(Session).filter_by(id=session_id).first()
        finally:
            db_session.close()
            
    def get_all_sessions(self, limit: int = 100) -> List[Session]:
        """Get all sessions"""
        db_session = self.Session()
        try:
            return db_session.query(Session).order_by(Session.created_at.desc()).limit(limit).all()
        finally:
            db_session.close()
            
    def update_session(self, session_id: int, **kwargs):
        """Update session attributes"""
        db_session = self.Session()
        try:
            session = db_session.query(Session).filter_by(id=session_id).first()
            if session:
                for key, value in kwargs.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                db_session.commit()
                logger.info(f"Updated session {session_id}")
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error updating session: {e}")
            raise
        finally:
            db_session.close()
            
    def delete_session(self, session_id: int):
        """Delete a session"""
        db_session = self.Session()
        try:
            session = db_session.query(Session).filter_by(id=session_id).first()
            if session:
                db_session.delete(session)
                db_session.commit()
                logger.info(f"Deleted session {session_id}")
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error deleting session: {e}")
            raise
        finally:
            db_session.close()
            
    def add_packet(self, session_id: int, packet_info: Dict[str, Any]):
        """Add packet to session"""
        db_session = self.Session()
        try:
            packet = Packet(
                session_id=session_id,
                timestamp=packet_info.get('timestamp', datetime.now()),
                protocol=packet_info.get('protocol'),
                src_ip=packet_info.get('src_ip'),
                dst_ip=packet_info.get('dst_ip'),
                src_port=packet_info.get('src_port'),
                dst_port=packet_info.get('dst_port'),
                size=packet_info.get('size'),
                flags=packet_info.get('flags'),
                info=packet_info.get('info')
            )
            
            db_session.add(packet)
            
            # Update session counters
            session = db_session.query(Session).filter_by(id=session_id).first()
            if session:
                session.total_packets += 1
                session.total_bytes += packet_info.get('size', 0)
                
            db_session.commit()
            
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error adding packet: {e}")
        finally:
            db_session.close()
            
    def get_packets(self, session_id: int, limit: int = 1000, offset: int = 0) -> List[Packet]:
        """Get packets for a session"""
        db_session = self.Session()
        try:
            return db_session.query(Packet).filter_by(session_id=session_id)\
                .order_by(Packet.timestamp.desc()).limit(limit).offset(offset).all()
        finally:
            db_session.close()
            
    def update_statistics(self, session_id: int, stats: Dict[str, Any]):
        """Update session statistics"""
        db_session = self.Session()
        try:
            session_stats = db_session.query(SessionStatistics).filter_by(session_id=session_id).first()
            if session_stats:
                # Update protocol counts
                protocol_dist = stats.get('protocols', {}).get('packets', {})
                session_stats.tcp_packets = protocol_dist.get('TCP', 0)
                session_stats.udp_packets = protocol_dist.get('UDP', 0)
                session_stats.icmp_packets = protocol_dist.get('ICMP', 0)
                session_stats.dns_packets = protocol_dist.get('DNS', 0)
                session_stats.http_packets = protocol_dist.get('HTTP', 0)
                session_stats.https_packets = protocol_dist.get('HTTPS', 0)
                
                # Update rates
                current = stats.get('current', {})
                session_stats.avg_pps = stats.get('average', {}).get('pps', 0)
                session_stats.avg_bps = stats.get('average', {}).get('bps', 0)
                
                # Store top IPs and ports as JSON
                session_stats.top_src_ips = json.dumps(stats.get('top_ips', [])[:10])
                session_stats.top_ports = json.dumps(stats.get('top_ports', [])[:10])
                
                db_session.commit()
                
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error updating statistics: {e}")
        finally:
            db_session.close()
            
    def add_anomaly(self, session_id: int, anomaly: Dict[str, Any]):
        """Add anomaly to database"""
        db_session = self.Session()
        try:
            anomaly_record = Anomaly(
                session_id=session_id,
                timestamp=anomaly.get('timestamp', datetime.now()),
                type=anomaly.get('type'),
                severity=anomaly.get('severity'),
                src_ip=anomaly.get('src_ip'),
                dst_ip=anomaly.get('dst_ip'),
                description=anomaly.get('description'),
                details=json.dumps(anomaly)
            )
            
            db_session.add(anomaly_record)
            db_session.commit()
            
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error adding anomaly: {e}")
        finally:
            db_session.close()
            
    def get_anomalies(self, session_id: int = None, severity: str = None, 
                     limit: int = 100) -> List[Anomaly]:
        """Get anomalies"""
        db_session = self.Session()
        try:
            query = db_session.query(Anomaly)
            
            if session_id:
                query = query.filter_by(session_id=session_id)
                
            if severity:
                query = query.filter_by(severity=severity)
                
            return query.order_by(Anomaly.timestamp.desc()).limit(limit).all()
            
        finally:
            db_session.close()
            
    def save_filter_preset(self, name: str, filter_config: Dict[str, Any], 
                          description: str = None):
        """Save filter preset"""
        db_session = self.Session()
        try:
            preset = db_session.query(FilterPreset).filter_by(name=name).first()
            
            if preset:
                preset.filter_config = json.dumps(filter_config)
                preset.description = description
            else:
                preset = FilterPreset(
                    name=name,
                    description=description,
                    filter_config=json.dumps(filter_config)
                )
                db_session.add(preset)
                
            db_session.commit()
            logger.info(f"Saved filter preset: {name}")
            
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error saving filter preset: {e}")
            raise
        finally:
            db_session.close()
            
    def get_filter_presets(self) -> List[FilterPreset]:
        """Get all filter presets"""
        db_session = self.Session()
        try:
            return db_session.query(FilterPreset).all()
        finally:
            db_session.close()
            
    def delete_filter_preset(self, name: str):
        """Delete filter preset"""
        db_session = self.Session()
        try:
            preset = db_session.query(FilterPreset).filter_by(name=name).first()
            if preset:
                db_session.delete(preset)
                db_session.commit()
                logger.info(f"Deleted filter preset: {name}")
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error deleting filter preset: {e}")
            raise
        finally:
            db_session.close()
            
    def export_pcap(self, session_id: int, output_path: str):
        """Export session to PCAP file"""
        from scapy.all import wrpcap
        
        db_session = self.Session()
        try:
            packets = db_session.query(Packet).filter_by(session_id=session_id).all()
            
            # Convert to scapy packets
            scapy_packets = []
            for pkt in packets:
                if hasattr(pkt, 'raw_packet'):
                    scapy_packets.append(pkt.raw_packet)
                    
            if scapy_packets:
                wrpcap(output_path, scapy_packets)
                logger.info(f"Exported {len(scapy_packets)} packets to {output_path}")
            else:
                logger.warning("No packets to export")
                
        except Exception as e:
            logger.error(f"Error exporting PCAP: {e}")
            raise
        finally:
            db_session.close()
            
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        db_session = self.Session()
        try:
            config = db_session.query(Configuration).filter_by(key=key).first()
            if config:
                try:
                    return json.loads(config.value)
                except:
                    return config.value
            return default
        finally:
            db_session.close()
            
    def set_config(self, key: str, value: Any, description: str = None):
        """Set configuration value"""
        db_session = self.Session()
        try:
            config = db_session.query(Configuration).filter_by(key=key).first()
            
            value_str = json.dumps(value) if not isinstance(value, str) else value
            
            if config:
                config.value = value_str
                config.description = description
                config.updated_at = datetime.now()
            else:
                config = Configuration(
                    key=key,
                    value=value_str,
                    description=description
                )
                db_session.add(config)
                
            db_session.commit()
            
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error setting config: {e}")
            raise
        finally:
            db_session.close()
            
    def close(self):
        """Close database connection"""
        self.Session.remove()
        self.engine.dispose()
        logger.info("Session manager closed")
