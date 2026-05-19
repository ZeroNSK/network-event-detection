"""
Тесты endpoints сетевых событий.
Requirements: 16.4, 16.5
"""
import pytest
from app.models import AccessLevel, EventAccess, NetworkEvent, NetworkNode, NodeType, NodeStatus, DetectionRule, EventType, Protocol, Severity


@pytest.fixture
def network_node(db):
    """Создает сетевой узел для тестов."""
    node = NetworkNode(
        name="Test-Node",
        node_type=NodeType.router,
        ip_address="10.0.0.1",
        location="Тестовая локация",
        status=NodeStatus.active
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@pytest.fixture
def detection_rule(db):
    """Создает правило обнаружения для тестов."""
    rule = DetectionRule(
        name="Тестовое правило",
        description="Описание тестового правила",
        event_type=EventType.auth_failed,
        severity_threshold=Severity.high,
        is_active=True
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def test_create_event_with_token(client, admin_user, admin_token, network_node, detection_rule):
    """
    Проверяет, что создание сетевого события с действительным токеном возвращает 201.
    Requirements: 16.4
    """
    response = client.post(
        "/api/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "node_id": network_node.id,
            "rule_id": detection_rule.id,
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "event_type": "auth_failed",
            "event_message": "Failed authentication attempt",
            "severity": "high"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["source_ip"] == "192.168.1.100"
    assert data["destination_ip"] == "10.0.0.1"
    assert data["severity"] == "high"
    assert data["is_suspicious"] is True  # high severity should be suspicious
    assert data["created_by"] == admin_user.id


def test_event_critical_severity_is_suspicious(client, admin_user, admin_token, network_node):
    """
    Проверяет, что сетевое событие с критичностью critical получает is_suspicious=true.
    Requirements: 16.5
    """
    response = client.post(
        "/api/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "node_id": network_node.id,
            "rule_id": None,
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "event_type": "other",
            "event_message": "Critical event",
            "severity": "critical"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["severity"] == "critical"
    assert data["is_suspicious"] is True


def test_event_low_severity_not_suspicious(client, admin_user, admin_token, network_node):
    """
    Проверяет, что событие low с неподозрительным типом не становится подозрительным.
    """
    response = client.post(
        "/api/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "node_id": network_node.id,
            "rule_id": None,
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "event_type": "other",
            "event_message": "Normal event",
            "severity": "low"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["severity"] == "low"
    assert data["is_suspicious"] is False


def test_event_suspicious_event_type(client, admin_user, admin_token, network_node):
    """
    Проверяет, что подозрительные типы событий становятся подозрительными при риске 50+.
    """
    suspicious_types = ["auth_failed", "port_scan", "traffic_spike", "unauthorized_access", "suspicious_ip"]
    
    for event_type in suspicious_types:
        response = client.post(
            "/api/events",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "node_id": network_node.id,
                "rule_id": None,
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "event_type": event_type,
                "event_message": f"Event of type {event_type}",
                "severity": "high"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["risk_score"] >= 50
        assert data["is_suspicious"] is True, f"Event type {event_type} should be suspicious"


def test_create_event_rejects_invalid_ip(client, admin_user, admin_token, network_node):
    """
    Проверяет, что событие с некорректным IP-адресом не проходит валидацию.
    """
    response = client.post(
        "/api/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "node_id": network_node.id,
            "rule_id": None,
            "source_ip": "not-an-ip",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "event_type": "auth_failed",
            "event_message": "Invalid source IP",
            "severity": "high",
        },
    )

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert response.json()["message"] == "Ошибка валидации входных данных"


def test_create_event_rejects_invalid_enum_value(client, admin_user, admin_token, network_node):
    """
    Проверяет, что произвольное значение protocol/event_type отклоняется схемой.
    """
    response = client.post(
        "/api/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "node_id": network_node.id,
            "rule_id": None,
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "FTP",
            "event_type": "malware",
            "event_message": "Invalid enum values",
            "severity": "high",
        },
    )

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_operator_sees_only_own_events(client, admin_user, operator_user, operator_token, admin_token, network_node, db):
    """
    Проверяет, что оператор видит только свои события.
    """
    admin_event = NetworkEvent(
        node_id=network_node.id,
        rule_id=None,
        source_ip="192.168.10.10",
        destination_ip="10.0.0.1",
        protocol=Protocol.TCP,
        event_type=EventType.auth_failed,
        event_message="Admin event",
        severity=Severity.high,
        is_suspicious=True,
        created_by=admin_user.id,
    )
    operator_event = NetworkEvent(
        node_id=network_node.id,
        rule_id=None,
        source_ip="192.168.10.11",
        destination_ip="10.0.0.1",
        protocol=Protocol.TCP,
        event_type=EventType.auth_failed,
        event_message="Operator event",
        severity=Severity.high,
        is_suspicious=True,
        created_by=operator_user.id,
    )
    db.add_all([admin_event, operator_event])
    db.commit()
    db.refresh(admin_event)
    db.refresh(operator_event)

    response = client.get("/api/events?limit=100", headers={"Authorization": f"Bearer {operator_token}"})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["id"] == operator_event.id

    forbidden = client.get(f"/api/events/{admin_event.id}", headers={"Authorization": f"Bearer {operator_token}"})
    assert forbidden.status_code == 403

    admin_response = client.get("/api/events?limit=100", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_response.status_code == 200
    assert admin_response.json()["total"] == 2


def test_operator_can_read_event_with_explicit_access(client, admin_user, operator_user, operator_token, network_node, db):
    """
    Проверяет, что явная выдача доступа позволяет оператору читать чужое событие.
    """
    event = NetworkEvent(
        node_id=network_node.id,
        rule_id=None,
        source_ip="192.168.20.10",
        destination_ip="10.0.0.1",
        protocol=Protocol.TCP,
        event_type=EventType.auth_failed,
        event_message="Shared event",
        severity=Severity.high,
        is_suspicious=True,
        created_by=admin_user.id,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    db.add(
        EventAccess(
            event_id=event.id,
            user_id=operator_user.id,
            access_level=AccessLevel.read,
            granted_by=admin_user.id,
        )
    )
    db.commit()

    response = client.get(f"/api/events/{event.id}", headers={"Authorization": f"Bearer {operator_token}"})

    assert response.status_code == 200
    assert response.json()["id"] == event.id
