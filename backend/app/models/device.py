# backend/app/models/device.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, JSON, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

# Association tables
device_groups = Table('device_groups', Base.metadata,
    Column('device_id', Integer, ForeignKey('devices.id')),
    Column('group_id', Integer, ForeignKey('groups.id'))
)

class Device(Base):
    __tablename__ = 'devices'
    
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True)
    ip_address = Column(String(45), nullable=False, unique=True)
    hostname = Column(String(255))
    serial_number = Column(String(100))
    model = Column(String(100))
    vendor = Column(String(50))
    os_version = Column(String(100))
    location = Column(String(255))
    
    # Status and health
    status = Column(String(20), default='unknown')  # online, offline, unreachable
    health_score = Column(Float, default=0.0)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Credentials
    credential_set_id = Column(Integer, ForeignKey('credential_sets.id'))
    
    # Monitoring
    monitoring_enabled = Column(Boolean, default=True)
    collection_interval = Column(Integer, default=300)  # seconds
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(100))
    
    # Relationships
    groups = relationship("Group", secondary=device_groups, back_populates="devices")
    metrics = relationship("DeviceMetric", back_populates="device")
    configurations = relationship("Configuration", back_populates="device")
    alerts = relationship("Alert", back_populates="device")
    health_checks = relationship("HealthCheck", back_populates="device")

class Group(Base):
    __tablename__ = 'groups'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    parent_id = Column(Integer, ForeignKey('groups.id'))
    
    # Relationships
    devices = relationship("Device", secondary=device_groups, back_populates="groups")
    children = relationship("Group", remote_side=[id])

class DeviceMetric(Base):
    __tablename__ = 'device_metrics'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('devices.id'), nullable=False)
    metric_type = Column(String(50), nullable=False)  # cpu, memory, interface, etc.
    metric_name = Column(String(100), nullable=False)
    value = Column(Float, nullable=False)
    unit = Column(String(20))
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Additional metadata
    interface_name = Column(String(50))  # for interface metrics
    metadata = Column(JSON)
    
    # Relationships
    device = relationship("Device", back_populates="metrics")

class Configuration(Base):
    __tablename__ = 'configurations'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('devices.id'), nullable=False)
    config_type = Column(String(50), nullable=False)  # running, startup, etc.
    content = Column(Text, nullable=False)
    hash = Column(String(64))  # SHA256 hash for change detection
    
    # Timestamps
    collected_at = Column(DateTime, default=datetime.utcnow)
    
    # Change tracking
    change_id = Column(String(36))
    parent_config_id = Column(Integer, ForeignKey('configurations.id'))
    
    # Relationships
    device = relationship("Device", back_populates="configurations")
    changes = relationship("ConfigurationChange", back_populates="configuration")

class ConfigurationChange(Base):
    __tablename__ = 'configuration_changes'
    
    id = Column(Integer, primary_key=True)
    configuration_id = Column(Integer, ForeignKey('configurations.id'), nullable=False)
    change_type = Column(String(20), nullable=False)  # added, removed, modified
    line_number = Column(Integer)
    old_content = Column(Text)
    new_content = Column(Text)
    impact_level = Column(String(10))  # low, medium, high, critical
    
    # Analysis
    auto_analysis = Column(JSON)  # AI-generated analysis
    rollback_suggestion = Column(Text)
    
    # Relationships
    configuration = relationship("Configuration", back_populates="changes")

class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('devices.id'), nullable=False)
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)  # info, warning, error, critical
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Status
    status = Column(String(20), default='active')  # active, acknowledged, resolved
    acknowledged_by = Column(String(100))
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    # Correlation
    correlation_id = Column(String(36))
    root_cause_id = Column(Integer, ForeignKey('alerts.id'))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    device = relationship("Device", back_populates="alerts")

class HealthCheck(Base):
    __tablename__ = 'health_checks'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('devices.id'), nullable=False)
    check_type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)  # healthy, warning, critical
    score = Column(Float, nullable=False)
    details = Column(JSON)
    
    # Predictions
    predicted_failure_time = Column(DateTime)
    failure_probability = Column(Float)
    
    # Timestamps
    checked_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship("Device", back_populates="health_checks")

class NetworkTopology(Base):
    __tablename__ = 'network_topology'
    
    id = Column(Integer, primary_key=True)
    source_device_id = Column(Integer, ForeignKey('devices.id'), nullable=False)
    destination_device_id = Column(Integer, ForeignKey('devices.id'), nullable=False)
    connection_type = Column(String(50))  # cdp, lldp, manual
    source_interface = Column(String(100))
    destination_interface = Column(String(100))
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Link properties
    bandwidth = Column(Float)
    latency = Column(Float)
    utilization = Column(Float)
    
    # Relationships
    source_device = relationship("Device", foreign_keys=[source_device_id])
    destination_device = relationship("Device", foreign_keys=[destination_device_id])