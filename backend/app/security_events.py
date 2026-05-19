from fastapi import Request
from sqlalchemy.orm import Session

from .analysis import analyze_and_correlate_event
from .models import (
    AuditAction,
    AuditLog,
    EntityType,
    EventType,
    LoginAttemptLog,
    NetworkEvent,
    NetworkNode,
    NodeStatus,
    NodeType,
    Protocol,
    Severity,
    User,
    UserRole,
)


AUTH_MONITOR_NODE_NAME = "AUTH-API-01"


def get_request_source_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    return request.client.host if request.client else "0.0.0.0"


def _get_auth_monitor_node(db: Session) -> NetworkNode:
    node = db.query(NetworkNode).filter(NetworkNode.name == AUTH_MONITOR_NODE_NAME).first()
    if node:
        return node

    node = NetworkNode(
        name=AUTH_MONITOR_NODE_NAME,
        node_type=NodeType.server,
        ip_address="127.0.0.1",
        location="Сервис аутентификации приложения",
        status=NodeStatus.active,
    )
    db.add(node)
    db.flush()
    return node


def _get_event_creator(db: Session, username: str) -> User | None:
    user = db.query(User).filter(User.username == username).first()
    if user:
        return user

    admin = db.query(User).filter(User.role == UserRole.admin).order_by(User.id.asc()).first()
    if admin:
        return admin

    return db.query(User).order_by(User.id.asc()).first()


def record_failed_login_attempt(
    db: Session,
    username: str,
    request: Request,
    *,
    reason: str = "invalid_credentials",
    attempt_number: int = 1,
    locked_until=None,
) -> NetworkEvent | None:
    source_ip = get_request_source_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500]

    # 1. Всегда пишем в login_attempt_logs — независимо от того, есть ли пользователь в БД
    attempt_log = LoginAttemptLog(
        username=username.strip() or "<empty>",
        ip_address=source_ip,
        user_agent=user_agent,
        reason=reason,
        attempt_number=attempt_number,
        locked_until=locked_until,
    )
    db.add(attempt_log)
    db.flush()

    # 2. Пишем NetworkEvent + AuditLog (требует хотя бы одного пользователя в системе)
    known_user = db.query(User).filter(User.username == username).first()
    event_creator = known_user or _get_event_creator(db, username)
    if not event_creator:
        return None

    node = _get_auth_monitor_node(db)
    attempted_user = username.strip() or "<empty>"

    reason_label = {
        "invalid_credentials": "неверные учётные данные",
        "account_locked": "аккаунт временно заблокирован",
        "account_disabled": "аккаунт отключен администратором",
    }.get(reason, reason)

    event = NetworkEvent(
        node_id=node.id,
        source_ip=source_ip,
        destination_ip=node.ip_address,
        protocol=Protocol.HTTPS if request.url.scheme == "https" else Protocol.HTTP,
        event_type=EventType.auth_failed,
        event_message=(
            f"Неуспешная попытка входа №{attempt_number} для пользователя '{attempted_user}'. "
            f"Причина: {reason_label}. Источник: {source_ip}."
        ),
        severity=Severity.high,
        is_suspicious=False,
        created_by=event_creator.id,
    )
    db.add(event)
    db.flush()
    analyze_and_correlate_event(db, event, user_id=event_creator.id)

    db.add(
        AuditLog(
            user_id=known_user.id if known_user else None,
            action=AuditAction.failed_login,
            entity_type=EntityType.network_events,
            entity_id=event.id,
        )
    )
    return event
