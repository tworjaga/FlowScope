"""
Database Models
SQLAlchemy models for session storage
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class Session(Base):
    """Capture session model"""
    __tablename__ = 'sessions'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    start_time = Column(DateTime, default=datetime.now)
    end_time = Column(DateTime)
    interface = Column(String(100))
    filter_expression = Column(String(500))
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.now)
    
    # Relationships
    packets = relationship("Packet", back_populates="session", cascade="all, delete-orphan")
    statistics = relationship("SessionStatistics", back_populates="session", uselist=False)
    
    def __repr__(self):
        return f"<Session(id={self.id}, name='{self.name}', packets={self.total_packets})>"


class Packet(Base):
    """Packet model"""
    __tablename__ = 'packets'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('sessions.id'), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    protocol = Column(String(50))
    src_ip = Column(String(45))  # IPv6 support
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    size = Column(Integer)
    flags = Column(String(100))
    info = Column(Text)
    
    # Relationships
    session = relationship("Session", back_populates="packets")
    
    def __repr__(self):
        return f"<Packet(id={self.id}, protocol='{self.protocol}', {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port})>"


class SessionStatistics(Base):
    """Session statistics model"""
    __tablename__ = 'session_statistics'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('sessions.id'), nullable=False, unique=True)
    
    # Protocol distribution
    tcp_packets = Column(Integer, default=0)
    udp_packets = Column(Integer, default=0)
    icmp_packets = Column(Integer, default=0)
    dns_packets = Column(Integer, default=0)
    http_packets = Column(Integer, default=0)
    https_packets = Column(Integer, default=0)
    other_packets = Column(Integer, default=0)
    
    # Rates
    avg_pps = Column(Float, default=0.0)
    avg_bps = Column(Float, default=0.0)
    peak_pps = Column(Float, default=0.0)
    peak_bps = Column(Float, default=0.0)
    
    # Top IPs (stored as JSON string)
    top_src_ips = Column(Text)
    top_dst_ips = Column(Text)
    
    # Top ports (stored as JSON string)
    top_ports = Column(Text)
    
    # Anomalies
    anomaly_count = Column(Integer, default=0)
    
    # Relationships
    session = relationship("Session", back_populates="statistics")
    
    def __repr__(self):
        return f"<SessionStatistics(session_id={self.session_id}, total_packets={self.tcp_packets + self.udp_packets + self.icmp_packets})>"


class FilterPreset(Base):
    """Filter preset model"""
    __tablename__ = 'filter_presets'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    filter_config = Column(Text, nullable=False)  # JSON string
    created_at = Column(DateTime, default=datetime.now)
    last_used = Column(DateTime)
    
    def __repr__(self):
        return f"<FilterPreset(id={self.id}, name='{self.name}')>"


class Anomaly(Base):
    """Anomaly detection log"""
    __tablename__ = 'anomalies'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('sessions.id'))
    timestamp = Column(DateTime, default=datetime.now)
    type = Column(String(100), nullable=False)
    severity = Column(String(20))  # info, low, medium, high, critical
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    description = Column(Text)
    details = Column(Text)  # JSON string with additional details
    resolved = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<Anomaly(id={self.id}, type='{self.type}', severity='{self.severity}')>"


class Configuration(Base):
    """Application configuration"""
    __tablename__ = 'configuration'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(255), nullable=False, unique=True)
    value = Column(Text)
    description = Column(Text)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    def __repr__(self):
        return f"<Configuration(key='{self.key}', value='{self.value}')>"
