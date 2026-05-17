from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum

from .database import Base


# Enums
class UserRole(str, enum.Enum):
    admin = "admin"
    security_engineer = "security_engineer"
    operator = "operator"


class NodeType(str, enum.Enum):
    router = "router"
    switch = "switch"
    base_station = "base_station"
    server = "server"
    firewall = "firewall"
    gateway = "gateway"


class NodeStatus(str, enum.Enum):
    active = "active"
    warning = "warning"
    offline = "offline"


class Protocol(str, enum.Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    OTHER = "OTHER"


class EventType(str, enum.Enum):
    auth_failed = "auth_failed"
    port_scan = "port_scan"
    traffic_spike = "traffic_spike"
    unauthorized_access = "unauthorized_access"
    config_change = "config_change"
    connection_drop = "connection_drop"
    suspicious_ip = "suspicious_ip"
    other = "other"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RiskLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    new = "new"
    in_progress = "in_progress"
    resolved = "resolved"
    false_positive = "false_positive"


class RuleCategory(str, enum.Enum):
    authentication = "authentication"
    network_scan = "network_scan"
    traffic_anomaly = "traffic_anomaly"
    unauthorized_access = "unauthorized_access"
    availability = "availability"
    configuration = "configuration"



class IncidentStatus(str, enum.Enum):
    new = "new"
    in_progress = "in_progress"
    resolved = "resolved"
    rejected = "rejected"


class AccessLevel(str, enum.Enum):
    read = "read"
    write = "write"
    manage = "manage"


class AuditAction(str, enum.Enum):
    create = "create"
    update = "update"
    delete = "delete"
    login = "login"
    grant_access = "grant_access"
    update_access = "update_access"
    revoke_access = "revoke_access"
    run_analysis = "run_analysis"
    create_alert = "create_alert"
    update_alert = "update_alert"
    import_dataset = "import_dataset"
    export_dataset = "export_dataset"
    create_incident_from_alert = "create_incident_from_alert"


class EntityType(str, enum.Enum):
    users = "users"
    network_nodes = "network_nodes"
    network_events = "network_events"
    detection_rules = "detection_rules"
    incidents = "incidents"
    correlation_alerts = "correlation_alerts"


# Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    created_events = relationship("NetworkEvent", back_populates="creator", foreign_keys="NetworkEvent.created_by")
    created_incidents = relationship("Incident", back_populates="creator", foreign_keys="Incident.created_by")
    assigned_incidents = relationship("Incident", back_populates="assignee", foreign_keys="Incident.assigned_to")
    audit_logs = relationship("AuditLog", back_populates="user")


class NetworkNode(Base):
    __tablename__ = "network_nodes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    node_type = Column(SQLEnum(NodeType), nullable=False)
    ip_address = Column(String(45), nullable=False)
    location = Column(String(200))
    status = Column(SQLEnum(NodeStatus), default=NodeStatus.active)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    events = relationship("NetworkEvent", back_populates="node")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    event_type = Column(SQLEnum(EventType), nullable=False)
    severity_threshold = Column(SQLEnum(Severity), nullable=False)
    risk_weight = Column(Integer, default=0, nullable=False)
    time_window_minutes = Column(Integer, default=10, nullable=False)
    threshold_count = Column(Integer, default=1, nullable=False)
    rule_category = Column(String(50), default=RuleCategory.configuration.value, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    events = relationship("NetworkEvent", back_populates="rule")



class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(Integer, ForeignKey("network_nodes.id"), nullable=False)
    rule_id = Column(Integer, ForeignKey("detection_rules.id"), nullable=True)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    protocol = Column(SQLEnum(Protocol), nullable=False)
    event_type = Column(SQLEnum(EventType), nullable=False)
    event_message = Column(Text, nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False)
    is_suspicious = Column(Boolean, nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(20), default=RiskLevel.low.value, nullable=False)
    detection_reason = Column(Text, default="", nullable=False)
    analyzed_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    node = relationship("NetworkNode", back_populates="events")
    rule = relationship("DetectionRule", back_populates="events")
    creator = relationship("User", back_populates="created_events", foreign_keys=[created_by])
    incidents = relationship("Incident", back_populates="event")
    alert_links = relationship("CorrelationAlertEvent", back_populates="event", cascade="all, delete-orphan")
    correlation_alerts = relationship(
        "CorrelationAlert",
        secondary="correlation_alert_events",
        back_populates="events",
        viewonly=True,
    )


class CorrelationAlert(Base):
    __tablename__ = "correlation_alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    status = Column(String(30), default=AlertStatus.new.value, nullable=False)
    source_ip = Column(String(45), nullable=True, index=True)
    node_id = Column(Integer, ForeignKey("network_nodes.id"), nullable=True)
    event_count = Column(Integer, default=0, nullable=False)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    node = relationship("NetworkNode")
    event_links = relationship("CorrelationAlertEvent", back_populates="alert", cascade="all, delete-orphan")
    events = relationship(
        "NetworkEvent",
        secondary="correlation_alert_events",
        back_populates="correlation_alerts",
        viewonly=True,
    )
    incidents = relationship("Incident", back_populates="correlation_alert")


class CorrelationAlertEvent(Base):
    __tablename__ = "correlation_alert_events"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("correlation_alerts.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("network_events.id"), nullable=False)

    alert = relationship("CorrelationAlert", back_populates="event_links")
    event = relationship("NetworkEvent", back_populates="alert_links")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.new)
    severity = Column(SQLEnum(Severity), nullable=False)
    event_id = Column(Integer, ForeignKey("network_events.id"), nullable=False)
    correlation_alert_id = Column(Integer, ForeignKey("correlation_alerts.id"), nullable=True, index=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    event = relationship("NetworkEvent", back_populates="incidents")
    correlation_alert = relationship("CorrelationAlert", back_populates="incidents")
    assignee = relationship("User", back_populates="assigned_incidents", foreign_keys=[assigned_to])
    creator = relationship("User", back_populates="created_incidents", foreign_keys=[created_by])
    access_grants = relationship("IncidentAccess", back_populates="incident", cascade="all, delete-orphan")


class IncidentAccess(Base):
    __tablename__ = "incident_access"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    access_level = Column(SQLEnum(AccessLevel), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="access_grants")
    user = relationship("User", foreign_keys=[user_id])
    granter = relationship("User", foreign_keys=[granted_by])


class EventAccess(Base):
    __tablename__ = "event_access"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("network_events.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    access_level = Column(SQLEnum(AccessLevel), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    event = relationship("NetworkEvent", foreign_keys=[event_id])
    user = relationship("User", foreign_keys=[user_id])
    granter = relationship("User", foreign_keys=[granted_by])


class NodeAccess(Base):
    __tablename__ = "node_access"

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(Integer, ForeignKey("network_nodes.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    access_level = Column(SQLEnum(AccessLevel), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    node = relationship("NetworkNode", foreign_keys=[node_id])
    user = relationship("User", foreign_keys=[user_id])
    granter = relationship("User", foreign_keys=[granted_by])


class RuleAccess(Base):
    __tablename__ = "rule_access"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    access_level = Column(SQLEnum(AccessLevel), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    rule = relationship("DetectionRule", foreign_keys=[rule_id])
    user = relationship("User", foreign_keys=[user_id])
    granter = relationship("User", foreign_keys=[granted_by])


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(SQLEnum(AuditAction), nullable=False)
    entity_type = Column(SQLEnum(EntityType), nullable=True)
    entity_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="audit_logs")


# Helper function for suspicious event detection
def is_event_suspicious(severity: Severity, event_type: EventType) -> bool:
    """
    Determine if an event is suspicious based on severity and event type.
    
    Returns True if ANY of the following conditions are met:
    - severity is 'high' or 'critical'
    - event_type is one of: 'auth_failed', 'port_scan', 'traffic_spike', 
      'unauthorized_access', 'suspicious_ip'
    """
    suspicious_severities = [Severity.high, Severity.critical]
    suspicious_event_types = [
        EventType.auth_failed,
        EventType.port_scan,
        EventType.traffic_spike,
        EventType.unauthorized_access,
        EventType.suspicious_ip
    ]
    
    return (severity in suspicious_severities) or (event_type in suspicious_event_types)
