from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional, List, Any
from datetime import datetime


# User Schemas
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


# Network Node Schemas
class NetworkNodeCreate(BaseModel):
    name: str
    node_type: str
    ip_address: str
    location: Optional[str] = None
    status: str = "active"


class NetworkNodeUpdate(BaseModel):
    name: Optional[str] = None
    node_type: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    status: Optional[str] = None


class NetworkNodeResponse(BaseModel):
    id: int
    name: str
    node_type: str
    ip_address: str
    location: Optional[str]
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)



# Detection Rule Schemas
class DetectionRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    event_type: str
    severity_threshold: str
    risk_weight: int = 0
    time_window_minutes: int = 10
    threshold_count: int = 1
    rule_category: str = "configuration"
    is_active: bool = True


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    event_type: Optional[str] = None
    severity_threshold: Optional[str] = None
    risk_weight: Optional[int] = None
    time_window_minutes: Optional[int] = None
    threshold_count: Optional[int] = None
    rule_category: Optional[str] = None
    is_active: Optional[bool] = None


class DetectionRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    event_type: str
    severity_threshold: str
    risk_weight: int
    time_window_minutes: int
    threshold_count: int
    rule_category: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentSummaryResponse(BaseModel):
    id: int
    title: str
    status: str
    severity: str
    event_id: int
    correlation_alert_id: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CorrelationAlertSummaryResponse(BaseModel):
    id: int
    title: str
    risk_score: int
    risk_level: str
    status: str
    source_ip: Optional[str]
    node_id: Optional[int]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Network Event Schemas
class NetworkEventCreate(BaseModel):
    node_id: int
    rule_id: Optional[int] = None
    source_ip: str
    destination_ip: str
    protocol: str
    event_type: str
    event_message: str
    severity: str


class NetworkEventUpdate(BaseModel):
    node_id: Optional[int] = None
    rule_id: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    event_type: Optional[str] = None
    event_message: Optional[str] = None
    severity: Optional[str] = None


class NetworkEventResponse(BaseModel):
    id: int
    node_id: int
    rule_id: Optional[int]
    source_ip: str
    destination_ip: str
    protocol: str
    event_type: str
    event_message: str
    severity: str
    is_suspicious: bool
    risk_score: int
    risk_level: str
    detection_reason: str
    analyzed_at: Optional[datetime]
    created_by: int
    created_at: datetime
    node: Optional[NetworkNodeResponse] = None
    rule: Optional[DetectionRuleResponse] = None
    correlation_alerts: List[CorrelationAlertSummaryResponse] = []
    incidents: List[IncidentSummaryResponse] = []

    model_config = ConfigDict(from_attributes=True)


class CorrelationAlertResponse(CorrelationAlertSummaryResponse):
    description: str
    node: Optional[NetworkNodeResponse] = None

    model_config = ConfigDict(from_attributes=True)


class CorrelationAlertDetailResponse(CorrelationAlertResponse):
    events: List[NetworkEventResponse] = []
    incidents: List[IncidentSummaryResponse] = []

    model_config = ConfigDict(from_attributes=True)


class CorrelationAlertUpdate(BaseModel):
    status: str


class AnalysisRunResponse(BaseModel):
    analyzed_events: int
    alerts_created: int
    alerts_updated: int



# Incident Schemas
class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str
    event_id: int
    assigned_to: Optional[int] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[int] = None


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    status: str
    severity: str
    event_id: int
    correlation_alert_id: Optional[int] = None
    assigned_to: Optional[int]
    created_by: int
    created_at: datetime
    updated_at: datetime
    event: Optional[NetworkEventResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Incident Access Schemas
class IncidentAccessCreate(BaseModel):
    user_id: int
    access_level: str


class IncidentAccessUpdate(BaseModel):
    access_level: str


class IncidentAccessResponse(BaseModel):
    id: int
    incident_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Event Access Schemas
class EventAccessCreate(BaseModel):
    user_id: int
    access_level: str


class EventAccessUpdate(BaseModel):
    access_level: str


class EventAccessResponse(BaseModel):
    id: int
    event_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Node Access Schemas
class NodeAccessCreate(BaseModel):
    user_id: int
    access_level: str


class NodeAccessUpdate(BaseModel):
    access_level: str


class NodeAccessResponse(BaseModel):
    id: int
    node_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Rule Access Schemas
class RuleAccessCreate(BaseModel):
    user_id: int
    access_level: str


class RuleAccessUpdate(BaseModel):
    access_level: str


class RuleAccessResponse(BaseModel):
    id: int
    rule_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Audit Log Schemas
class AuditLogResponse(BaseModel):
    id: int
    user_id: int
    action: str
    entity_type: Optional[str]
    entity_id: Optional[int]
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Pagination Schema
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    limit: int
