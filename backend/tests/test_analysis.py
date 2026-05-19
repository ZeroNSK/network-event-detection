from datetime import datetime

import pytest

from app.models import (
    AlertStatus,
    CorrelationAlert,
    CorrelationAlertEvent,
    NetworkNode,
    NodeStatus,
    NodeType,
)


@pytest.fixture
def analysis_node(db):
    node = NetworkNode(
        name="EDGE-FW-TEST",
        node_type=NodeType.firewall,
        ip_address="172.16.0.10",
        location="Тестовый периметр",
        status=NodeStatus.active,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


def create_event(client, token, node, **overrides):
    payload = {
        "node_id": node.id,
        "rule_id": None,
        "source_ip": "185.10.10.10",
        "destination_ip": node.ip_address,
        "protocol": "TCP",
        "event_type": "port_scan",
        "event_message": "Тестовое сетевое событие",
        "severity": "high",
    }
    payload.update(overrides)
    return client.post("/api/events", headers={"Authorization": f"Bearer {token}"}, json=payload)


def test_risk_score_risk_level_and_suspicious_flag(client, admin_user, admin_token, analysis_node):
    response = create_event(client, admin_token, analysis_node)

    assert response.status_code == 201
    data = response.json()
    assert data["risk_score"] == 100
    assert data["risk_level"] == "critical"
    assert data["is_suspicious"] is True
    assert "Событие признано подозрительным" in data["detection_reason"]
    assert data["analyzed_at"] is not None


def test_medium_risk_level_for_non_suspicious_event(client, admin_user, admin_token, db):
    node = NetworkNode(
        name="LTE-eNB-TEST",
        node_type=NodeType.base_station,
        ip_address="10.10.22.10",
        location="Тестовая радиоплощадка",
        status=NodeStatus.active,
    )
    db.add(node)
    db.commit()
    db.refresh(node)

    response = create_event(
        client,
        admin_token,
        node,
        source_ip="10.10.22.10",
        protocol="OTHER",
        event_type="connection_drop",
        severity="low",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["risk_score"] == 30
    assert data["risk_level"] == "medium"
    assert data["is_suspicious"] is False


def test_correlation_alert_created_for_multiple_auth_failures(client, admin_user, admin_token, analysis_node):
    for index in range(5):
        response = create_event(
            client,
            admin_token,
            analysis_node,
            source_ip="203.0.113.15",
            event_type="auth_failed",
            event_message=f"Ошибка аутентификации {index}",
            severity="medium",
        )
        assert response.status_code == 201

    response = client.get(
        "/api/analysis/alerts",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"source_ip": "203.0.113.15"},
    )

    assert response.status_code == 200
    titles = [item["title"] for item in response.json()["items"]]
    assert "Множественные ошибки аутентификации" in titles


def test_correlation_alert_created_for_port_scan(client, admin_user, admin_token, analysis_node):
    for index in range(3):
        response = create_event(
            client,
            admin_token,
            analysis_node,
            source_ip="198.51.100.77",
            destination_ip=f"172.16.0.{index + 1}",
            event_type="port_scan",
            event_message=f"Сканирование портов {index}",
        )
        assert response.status_code == 201

    response = client.get(
        "/api/analysis/alerts",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"source_ip": "198.51.100.77"},
    )

    assert response.status_code == 200
    titles = [item["title"] for item in response.json()["items"]]
    assert "Признаки сканирования сетевой инфраструктуры" in titles


def test_incident_created_from_alert_only_once(client, admin_user, admin_token, analysis_node, db):
    event_response = create_event(
        client,
        admin_token,
        analysis_node,
        source_ip="203.0.113.200",
        event_type="unauthorized_access",
        event_message="Несанкционированный внешний доступ",
    )
    event_id = event_response.json()["id"]
    alert = db.query(CorrelationAlert).filter(
        CorrelationAlert.title == "Подозрительный внешний доступ к критическому узлу"
    ).first()
    assert alert is not None

    if not alert.events:
        db.add(CorrelationAlertEvent(alert_id=alert.id, event_id=event_id))
        db.commit()

    first = client.post(
        f"/api/analysis/alerts/{alert.id}/create-incident",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    second = client.post(
        f"/api/analysis/alerts/{alert.id}/create-incident",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert db.query(CorrelationAlert).filter(CorrelationAlert.id == alert.id).first().incidents


def test_operator_cannot_delete_alert(client, operator_user, operator_token, db):
    alert = CorrelationAlert(
        title="Тестовое оповещение",
        description="Описание тестового оповещения",
        risk_score=75,
        risk_level="high",
        status=AlertStatus.new.value,
        source_ip="203.0.113.10",
        node_id=None,
        event_count=0,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    response = client.delete(
        f"/api/analysis/alerts/{alert.id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )

    assert response.status_code == 403


def test_security_engineer_can_run_analysis(client, security_engineer_user, engineer_token, analysis_node):
    response = create_event(
        client,
        engineer_token,
        analysis_node,
        source_ip="10.0.0.10",
        event_type="connection_drop",
        severity="low",
    )
    assert response.status_code == 201

    response = client.post(
        "/api/analysis/run",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )

    assert response.status_code == 200
    assert response.json()["analyzed_events"] >= 1


def test_csv_import_creates_network_events(client, security_engineer_user, engineer_token, db):
    csv_content = (
        "timestamp,node_name,source_ip,destination_ip,protocol,event_type,event_message,severity\n"
        "2026-05-17T10:00:00,AUTH-RADIUS-CSV,203.0.113.91,10.10.5.5,UDP,auth_failed,Ошибка аутентификации из CSV,high\n"
    )

    response = client.post(
        "/api/dataset/import",
        headers={"Authorization": f"Bearer {engineer_token}"},
        files={"file": ("events.csv", csv_content, "text/csv")},
    )

    assert response.status_code == 200
    assert response.json()["imported"] == 1
    assert response.json()["events"][0]["event_type"] == "auth_failed"
