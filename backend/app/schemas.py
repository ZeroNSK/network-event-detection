from datetime import datetime
from ipaddress import ip_address
from typing import Optional, List, Any

from pydantic import BaseModel, EmailStr, ConfigDict, Field, field_validator

from .models import (
    AccessLevel,
    AlertStatus,
    EventType,
    IncidentStatus,
    NodeStatus,
    NodeType,
    Protocol,
    RuleCategory,
    Severity,
    UserRole,
)


def _enum_values(enum_class) -> set[str]:
    return {item.value for item in enum_class}


def _validate_enum(value: str | None, allowed_values: set[str], field_name: str) -> str | None:
    if value is None:
        return None
    normalized = value.value if hasattr(value, "value") else str(value).strip()
    if normalized not in allowed_values:
        allowed = ", ".join(sorted(allowed_values))
        raise ValueError(f"{field_name} должен быть одним из: {allowed}")
    return normalized


def _validate_ip(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    try:
        ip_address(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} должен быть корректным IPv4 или IPv6 адресом") from exc
    return normalized


NODE_TYPE_VALUES = _enum_values(NodeType)
NODE_STATUS_VALUES = _enum_values(NodeStatus)
PROTOCOL_VALUES = _enum_values(Protocol)
EVENT_TYPE_VALUES = _enum_values(EventType)
SEVERITY_VALUES = _enum_values(Severity)
ALERT_STATUS_VALUES = _enum_values(AlertStatus)
INCIDENT_STATUS_VALUES = _enum_values(IncidentStatus)
ACCESS_LEVEL_VALUES = _enum_values(AccessLevel)
RULE_CATEGORY_VALUES = _enum_values(RuleCategory)
USER_ROLE_VALUES = _enum_values(UserRole)
DANGEROUS_TEXT_MARKERS = (
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "<iframe",
    "</iframe",
)


def _validate_safe_text(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    normalized = str(value)
    lowered = normalized.lower()
    if any(marker in lowered for marker in DANGEROUS_TEXT_MARKERS):
        raise ValueError(f"{field_name} содержит потенциально опасный HTML/JavaScript")
    return normalized


# Схемы пользователей
class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, value: str) -> str:
        if any(char.isspace() for char in value):
            raise ValueError("Пароль не должен содержать пробельные символы")
        if not any(char.isalpha() for char in value):
            raise ValueError("Пароль должен содержать хотя бы одну букву")
        if not any(char.isdigit() for char in value):
            raise ValueError("Пароль должен содержать хотя бы одну цифру")
        return value


class UserLogin(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=256)


class LoginLockoutStatus(BaseModel):
    locked: bool
    retry_after_seconds: int
    failed_attempts: int
    attempts_remaining: int


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str | None) -> str | None:
        return _validate_enum(value, USER_ROLE_VALUES, "role")


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


# Схемы сетевых узлов
class NetworkNodeCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    node_type: str
    ip_address: str
    location: Optional[str] = Field(default=None, max_length=200)
    status: str = "active"

    @field_validator("node_type")
    @classmethod
    def validate_node_type(cls, value: str) -> str:
        return _validate_enum(value, NODE_TYPE_VALUES, "node_type")

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        return _validate_enum(value, NODE_STATUS_VALUES, "status")

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        return _validate_ip(value, "ip_address")

    @field_validator("name", "location")
    @classmethod
    def validate_safe_text_fields(cls, value: str | None) -> str | None:
        return _validate_safe_text(value, "поле узла")


class NetworkNodeUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    node_type: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = Field(default=None, max_length=200)
    status: Optional[str] = None

    @field_validator("node_type")
    @classmethod
    def validate_node_type(cls, value: str | None) -> str | None:
        return _validate_enum(value, NODE_TYPE_VALUES, "node_type")

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        return _validate_enum(value, NODE_STATUS_VALUES, "status")

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        return _validate_ip(value, "ip_address")

    @field_validator("name", "location")
    @classmethod
    def validate_safe_text_fields(cls, value: str | None) -> str | None:
        return _validate_safe_text(value, "поле узла")


class NetworkNodeResponse(BaseModel):
    id: int
    name: str
    node_type: str
    ip_address: str
    location: Optional[str]
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)



# Схемы правил обнаружения
class DetectionRuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    event_type: str
    severity_threshold: str
    risk_weight: int = Field(default=0, ge=0, le=100)
    time_window_minutes: int = Field(default=10, ge=1, le=1440)
    threshold_count: int = Field(default=1, ge=1, le=1000)
    rule_category: str = "configuration"
    is_active: bool = True

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        return _validate_enum(value, EVENT_TYPE_VALUES, "event_type")

    @field_validator("severity_threshold")
    @classmethod
    def validate_severity_threshold(cls, value: str) -> str:
        return _validate_enum(value, SEVERITY_VALUES, "severity_threshold")

    @field_validator("rule_category")
    @classmethod
    def validate_rule_category(cls, value: str) -> str:
        return _validate_enum(value, RULE_CATEGORY_VALUES, "rule_category")

    @field_validator("name", "description")
    @classmethod
    def validate_safe_text_fields(cls, value: str | None) -> str | None:
        return _validate_safe_text(value, "поле правила")


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    event_type: Optional[str] = None
    severity_threshold: Optional[str] = None
    risk_weight: Optional[int] = Field(default=None, ge=0, le=100)
    time_window_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    threshold_count: Optional[int] = Field(default=None, ge=1, le=1000)
    rule_category: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str | None) -> str | None:
        return _validate_enum(value, EVENT_TYPE_VALUES, "event_type")

    @field_validator("severity_threshold")
    @classmethod
    def validate_severity_threshold(cls, value: str | None) -> str | None:
        return _validate_enum(value, SEVERITY_VALUES, "severity_threshold")

    @field_validator("rule_category")
    @classmethod
    def validate_rule_category(cls, value: str | None) -> str | None:
        return _validate_enum(value, RULE_CATEGORY_VALUES, "rule_category")

    @field_validator("name", "description")
    @classmethod
    def validate_safe_text_fields(cls, value: str | None) -> str | None:
        return _validate_safe_text(value, "поле правила")


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


# Схемы сетевых событий
class NetworkEventCreate(BaseModel):
    node_id: int = Field(gt=0)
    rule_id: Optional[int] = Field(default=None, gt=0)
    source_ip: str
    destination_ip: str
    protocol: str
    event_type: str
    event_message: str = Field(min_length=1, max_length=4000)
    severity: str

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        return _validate_ip(value, "source_ip")

    @field_validator("destination_ip")
    @classmethod
    def validate_destination_ip(cls, value: str) -> str:
        return _validate_ip(value, "destination_ip")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str) -> str:
        return _validate_enum(value, PROTOCOL_VALUES, "protocol")

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        return _validate_enum(value, EVENT_TYPE_VALUES, "event_type")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        return _validate_enum(value, SEVERITY_VALUES, "severity")

    @field_validator("event_message")
    @classmethod
    def validate_safe_event_message(cls, value: str) -> str:
        return _validate_safe_text(value, "event_message")


class NetworkEventUpdate(BaseModel):
    node_id: Optional[int] = Field(default=None, gt=0)
    rule_id: Optional[int] = Field(default=None, gt=0)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    event_type: Optional[str] = None
    event_message: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    severity: Optional[str] = None

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        return _validate_ip(value, "source_ip")

    @field_validator("destination_ip")
    @classmethod
    def validate_destination_ip(cls, value: str | None) -> str | None:
        return _validate_ip(value, "destination_ip")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str | None) -> str | None:
        return _validate_enum(value, PROTOCOL_VALUES, "protocol")

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str | None) -> str | None:
        return _validate_enum(value, EVENT_TYPE_VALUES, "event_type")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str | None) -> str | None:
        return _validate_enum(value, SEVERITY_VALUES, "severity")

    @field_validator("event_message")
    @classmethod
    def validate_safe_event_message(cls, value: str | None) -> str | None:
        return _validate_safe_text(value, "event_message")


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

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        return _validate_enum(value, ALERT_STATUS_VALUES, "status")


class AnalysisRunResponse(BaseModel):
    analyzed_events: int
    alerts_created: int
    alerts_updated: int



# Схемы инцидентов
class IncidentCreate(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    severity: str
    event_id: int = Field(gt=0)
    assigned_to: Optional[int] = Field(default=None, gt=0)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        return _validate_enum(value, SEVERITY_VALUES, "severity")

    @field_validator("title", "description")
    @classmethod
    def validate_safe_text_fields(cls, value: str) -> str:
        return _validate_safe_text(value, "поле инцидента")


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=2, max_length=200)
    description: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[int] = Field(default=None, gt=0)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        return _validate_enum(value, INCIDENT_STATUS_VALUES, "status")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str | None) -> str | None:
        return _validate_enum(value, SEVERITY_VALUES, "severity")

    @field_validator("title", "description")
    @classmethod
    def validate_safe_text_fields(cls, value: str | None) -> str | None:
        return _validate_safe_text(value, "поле инцидента")


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


# Схемы доступа к инцидентам
class IncidentAccessCreate(BaseModel):
    user_id: int = Field(gt=0)
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class IncidentAccessUpdate(BaseModel):
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class IncidentAccessResponse(BaseModel):
    id: int
    incident_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Схемы доступа к событиям
class EventAccessCreate(BaseModel):
    user_id: int = Field(gt=0)
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class EventAccessUpdate(BaseModel):
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class EventAccessResponse(BaseModel):
    id: int
    event_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Схемы доступа к узлам
class NodeAccessCreate(BaseModel):
    user_id: int = Field(gt=0)
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class NodeAccessUpdate(BaseModel):
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class NodeAccessResponse(BaseModel):
    id: int
    node_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Схемы доступа к правилам
class RuleAccessCreate(BaseModel):
    user_id: int = Field(gt=0)
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class RuleAccessUpdate(BaseModel):
    access_level: str

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        return _validate_enum(value, ACCESS_LEVEL_VALUES, "access_level")


class RuleAccessResponse(BaseModel):
    id: int
    rule_id: int
    user_id: int
    access_level: str
    granted_by: int
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Схемы журнала аудита
class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    entity_type: Optional[str]
    entity_id: Optional[int]
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


# Схема журнала неудачных попыток входа
class LoginAttemptLogResponse(BaseModel):
    id: int
    username: str
    ip_address: str
    user_agent: Optional[str]
    reason: str
    attempt_number: int
    locked_until: Optional[datetime]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Схема пагинации
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    limit: int
