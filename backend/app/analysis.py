from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy.orm import Session

from .models import (
    AlertStatus,
    AuditAction,
    AuditLog,
    CorrelationAlert,
    CorrelationAlertEvent,
    DetectionRule,
    EntityType,
    EventType,
    NetworkEvent,
    NetworkNode,
    Severity,
)


SEVERITY_WEIGHTS = {
    "low": 10,
    "medium": 25,
    "high": 50,
    "critical": 70,
}

EVENT_TYPE_WEIGHTS = {
    "auth_failed": 20,
    "port_scan": 35,
    "traffic_spike": 30,
    "unauthorized_access": 45,
    "suspicious_ip": 40,
    "config_change": 20,
    "connection_drop": 10,
}

EVENT_TYPE_LABELS = {
    "auth_failed": "ошибка аутентификации",
    "port_scan": "сканирование портов",
    "traffic_spike": "всплеск трафика",
    "unauthorized_access": "несанкционированный доступ",
    "suspicious_ip": "подозрительный IP",
    "config_change": "изменение конфигурации",
    "connection_drop": "потеря соединения",
    "other": "другое событие",
}

PROTOCOL_WEIGHTS = {
    "SSH": 10,
    "TCP": 5,
    "UDP": 10,
    "OTHER": 5,
}

NODE_TYPE_WEIGHTS = {
    "firewall": 15,
    "gateway": 15,
    "server": 10,
    "router": 10,
    "base_station": 5,
}

NODE_TYPE_LABELS = {
    "firewall": "межсетевой экран",
    "gateway": "шлюз",
    "server": "сервер",
    "router": "маршрутизатор",
    "base_station": "базовая станция",
    "switch": "коммутатор",
}

RISK_LABELS = {
    "low": "низкий",
    "medium": "средний",
    "high": "высокий",
    "critical": "критический",
}


def enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def is_external_ip(ip_address: str | None) -> bool:
    if not ip_address:
        return False
    return (
        ip_address.startswith("185.")
        or ip_address.startswith("198.51.100.")
        or ip_address.startswith("203.0.113.")
    )


def risk_level_for_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def calculate_event_risk(db: Session, event: NetworkEvent, node: NetworkNode | None = None) -> dict:
    node = node or event.node or db.query(NetworkNode).filter(NetworkNode.id == event.node_id).first()
    severity = enum_value(event.severity)
    event_type = enum_value(event.event_type)
    protocol = enum_value(event.protocol)
    node_type = enum_value(node.node_type) if node else ""

    score = 0
    reasons: list[str] = []

    severity_weight = SEVERITY_WEIGHTS.get(severity, 0)
    if severity_weight:
        score += severity_weight
        reasons.append(f"{RISK_LABELS.get(severity, severity)} уровень критичности")

    event_type_weight = EVENT_TYPE_WEIGHTS.get(event_type, 0)
    if event_type_weight:
        score += event_type_weight
        reasons.append(f"тип события: {EVENT_TYPE_LABELS.get(event_type, event_type)}")

    protocol_weight = PROTOCOL_WEIGHTS.get(protocol, 5)
    score += protocol_weight
    reasons.append(f"протокол {protocol}")

    if is_external_ip(event.source_ip):
        score += 20
        reasons.append("внешний IP-источник")

    node_type_weight = NODE_TYPE_WEIGHTS.get(node_type, 0)
    if node_type_weight:
        score += node_type_weight
        reasons.append(f"целевой узел: {NODE_TYPE_LABELS.get(node_type, node_type)}")

    matching_rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.is_active.is_(True), DetectionRule.event_type == event_type)
        .all()
    )
    rule_weight = sum(rule.risk_weight or 0 for rule in matching_rules)
    if rule_weight:
        score += rule_weight
        rule_names = ", ".join(rule.name for rule in matching_rules if rule.risk_weight)
        reasons.append(f"активные правила обнаружения: {rule_names}")

    score = min(score, 100)
    risk_level = risk_level_for_score(score)
    is_suspicious = score >= 50
    if is_suspicious:
        reason = "Событие признано подозрительным: " + ", ".join(reasons) + "."
    else:
        reason = "Событие имеет низкий уровень риска: " + ", ".join(reasons) + "."

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "is_suspicious": is_suspicious,
        "detection_reason": reason,
        "analyzed_at": datetime.utcnow(),
    }


def analyze_event(db: Session, event: NetworkEvent) -> NetworkEvent:
    result = calculate_event_risk(db, event)
    event.risk_score = result["risk_score"]
    event.risk_level = result["risk_level"]
    event.is_suspicious = result["is_suspicious"]
    event.detection_reason = result["detection_reason"]
    event.analyzed_at = result["analyzed_at"]
    return event


def log_action(
    db: Session,
    user_id: int | None,
    action: AuditAction,
    entity_type: EntityType | None = None,
    entity_id: int | None = None,
) -> None:
    if not user_id:
        return
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
        )
    )


def _event_time(event: NetworkEvent) -> datetime:
    return event.created_at or datetime.utcnow()


def _events_window(db: Session, event: NetworkEvent, minutes: int = 10) -> list[NetworkEvent]:
    last_seen = _event_time(event)
    first_seen = last_seen - timedelta(minutes=minutes)
    return (
        db.query(NetworkEvent)
        .filter(
            NetworkEvent.source_ip == event.source_ip,
            NetworkEvent.created_at >= first_seen,
            NetworkEvent.created_at <= last_seen,
        )
        .order_by(NetworkEvent.created_at.asc(), NetworkEvent.id.asc())
        .all()
    )


def _create_or_update_alert(
    db: Session,
    *,
    title: str,
    description: str,
    risk_score: int,
    risk_level: str,
    source_ip: str | None,
    node_id: int | None,
    events: Iterable[NetworkEvent],
    user_id: int | None = None,
) -> tuple[CorrelationAlert, bool]:
    event_list = list(events)
    if not event_list:
        raise ValueError("Для корреляционного оповещения требуется хотя бы одно событие")

    first_seen = min(_event_time(event) for event in event_list)
    last_seen = max(_event_time(event) for event in event_list)

    alert = (
        db.query(CorrelationAlert)
        .filter(
            CorrelationAlert.title == title,
            CorrelationAlert.source_ip == source_ip,
            CorrelationAlert.node_id == node_id,
            CorrelationAlert.status.in_([AlertStatus.new.value, AlertStatus.in_progress.value]),
        )
        .first()
    )
    created = alert is None
    if created:
        alert = CorrelationAlert(
            title=title,
            description=description,
            risk_score=risk_score,
            risk_level=risk_level,
            status=AlertStatus.new.value,
            source_ip=source_ip,
            node_id=node_id,
            event_count=len(event_list),
            first_seen=first_seen,
            last_seen=last_seen,
        )
        db.add(alert)
        db.flush()
        log_action(db, user_id, AuditAction.create_alert, EntityType.correlation_alerts, alert.id)
    else:
        alert.description = description
        alert.risk_score = risk_score
        alert.risk_level = risk_level
        alert.event_count = max(alert.event_count or 0, len(event_list))
        alert.first_seen = min(alert.first_seen, first_seen)
        alert.last_seen = max(alert.last_seen, last_seen)

    existing_event_ids = {
        link.event_id
        for link in db.query(CorrelationAlertEvent).filter(CorrelationAlertEvent.alert_id == alert.id).all()
    }
    for event in event_list:
        if event.id not in existing_event_ids:
            db.add(CorrelationAlertEvent(alert_id=alert.id, event_id=event.id))

    return alert, created


def correlate_event(db: Session, event: NetworkEvent, user_id: int | None = None) -> dict:
    created = 0
    updated = 0
    window_events = _events_window(db, event, minutes=10)
    event_type = enum_value(event.event_type)
    node = event.node or db.query(NetworkNode).filter(NetworkNode.id == event.node_id).first()
    node_type = enum_value(node.node_type) if node else ""

    auth_events = [item for item in window_events if enum_value(item.event_type) == EventType.auth_failed.value]
    if len(auth_events) >= 5:
        _, was_created = _create_or_update_alert(
            db,
            title="Множественные ошибки аутентификации",
            description="С одного IP-адреса зафиксировано несколько неуспешных попыток аутентификации за короткий период.",
            risk_score=75,
            risk_level="high",
            source_ip=event.source_ip,
            node_id=event.node_id,
            events=auth_events,
            user_id=user_id,
        )
        created += int(was_created)
        updated += int(not was_created)

    port_scan_events = [
        item for item in window_events if enum_value(item.event_type) == EventType.port_scan.value
    ]
    distinct_destinations = {item.destination_ip for item in window_events}
    if len(port_scan_events) >= 3 or (event_type == EventType.port_scan.value and len(distinct_destinations) >= 3):
        relevant_events = port_scan_events if len(port_scan_events) >= 3 else window_events
        _, was_created = _create_or_update_alert(
            db,
            title="Признаки сканирования сетевой инфраструктуры",
            description="С одного IP-адреса выявлены признаки сканирования портов или обращений к нескольким адресам назначения за короткий период.",
            risk_score=80,
            risk_level="critical",
            source_ip=event.source_ip,
            node_id=event.node_id,
            events=relevant_events,
            user_id=user_id,
        )
        created += int(was_created)
        updated += int(not was_created)

    if event_type == EventType.traffic_spike.value and node_type in {"firewall", "gateway", "router"}:
        _, was_created = _create_or_update_alert(
            db,
            title="Аномальный рост трафика на критическом сетевом узле",
            description="На критическом сетевом узле зафиксирован резкий рост трафика, требующий проверки устойчивости и источников нагрузки.",
            risk_score=70,
            risk_level="high",
            source_ip=event.source_ip,
            node_id=event.node_id,
            events=[event],
            user_id=user_id,
        )
        created += int(was_created)
        updated += int(not was_created)

    critical_node = node_type in {"server", "firewall", "gateway"} or (
        node and "NMS" in node.name.upper()
    )
    suspicious_access_type = event_type in {
        EventType.unauthorized_access.value,
        EventType.suspicious_ip.value,
    }
    if is_external_ip(event.source_ip) and critical_node and suspicious_access_type:
        _, was_created = _create_or_update_alert(
            db,
            title="Подозрительный внешний доступ к критическому узлу",
            description="Внешний источник обращается к критическому узлу сети связи с признаками несанкционированного или подозрительного доступа.",
            risk_score=85,
            risk_level="critical",
            source_ip=event.source_ip,
            node_id=event.node_id,
            events=[event],
            user_id=user_id,
        )
        created += int(was_created)
        updated += int(not was_created)

    return {"alerts_created": created, "alerts_updated": updated}


def analyze_and_correlate_event(db: Session, event: NetworkEvent, user_id: int | None = None) -> dict:
    analyze_event(db, event)
    db.flush()
    return correlate_event(db, event, user_id=user_id)


def run_full_analysis(db: Session, user_id: int | None = None) -> dict:
    analyzed_events = 0
    alerts_created = 0
    alerts_updated = 0

    events = db.query(NetworkEvent).order_by(NetworkEvent.created_at.asc(), NetworkEvent.id.asc()).all()
    for event in events:
        analyze_event(db, event)
        db.flush()
        result = correlate_event(db, event, user_id=user_id)
        analyzed_events += 1
        alerts_created += result["alerts_created"]
        alerts_updated += result["alerts_updated"]

    log_action(db, user_id, AuditAction.run_analysis)
    return {
        "analyzed_events": analyzed_events,
        "alerts_created": alerts_created,
        "alerts_updated": alerts_updated,
    }


def group_counts(items: Iterable[str | None], limit: int = 10) -> list[dict]:
    counters: dict[str, int] = defaultdict(int)
    for item in items:
        if item:
            counters[item] += 1
    return [
        {"value": value, "count": count}
        for value, count in sorted(counters.items(), key=lambda pair: pair[1], reverse=True)[:limit]
    ]
