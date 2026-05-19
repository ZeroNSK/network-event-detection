"""
ИБ-тесты некорректного и потенциально опасного ввода.
"""

from app.models import NetworkEvent, NetworkNode, NodeStatus, NodeType, EventType, Protocol, Severity


def test_sql_injection_payload_does_not_bypass_login(client, admin_user):
    """
    Проверяет, что SQLi-подобный логин не проходит аутентификацию.
    """
    response = client.post(
        "/api/auth/login",
        json={
            "username": "' OR '1'='1",
            "password": "anything",
        },
    )

    assert response.status_code == 401


def test_sql_injection_payload_in_filter_is_treated_as_plain_text(client, admin_user, admin_token, db):
    """
    Проверяет, что SQLi-подобный фильтр не расширяет выборку событий.
    """
    node = NetworkNode(
        name="SQLI-TEST-NODE",
        node_type=NodeType.router,
        ip_address="10.0.0.50",
        status=NodeStatus.active,
    )
    db.add(node)
    db.commit()
    db.refresh(node)

    event = NetworkEvent(
        node_id=node.id,
        source_ip="192.168.50.10",
        destination_ip="10.0.0.50",
        protocol=Protocol.TCP,
        event_type=EventType.auth_failed,
        event_message="Normal event",
        severity=Severity.high,
        is_suspicious=True,
        created_by=admin_user.id,
    )
    db.add(event)
    db.commit()

    response = client.get(
        "/api/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"source_ip": "192.168.50.10' OR '1'='1"},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_xss_payload_in_event_message_is_rejected(client, admin_user, admin_token, db):
    """
    Проверяет, что активный HTML/JavaScript в событии отклоняется.
    """
    node = NetworkNode(
        name="XSS-TEST-NODE",
        node_type=NodeType.router,
        ip_address="10.0.0.60",
        status=NodeStatus.active,
    )
    db.add(node)
    db.commit()
    db.refresh(node)

    response = client.post(
        "/api/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "node_id": node.id,
            "source_ip": "192.168.60.10",
            "destination_ip": "10.0.0.60",
            "protocol": "TCP",
            "event_type": "auth_failed",
            "event_message": "<script>alert(1)</script>",
            "severity": "high",
        },
    )

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_xss_payload_in_incident_description_is_rejected(client, admin_user, admin_token, db):
    """
    Проверяет, что XSS-подобное описание инцидента не принимается.
    """
    node = NetworkNode(
        name="XSS-INCIDENT-NODE",
        node_type=NodeType.router,
        ip_address="10.0.0.70",
        status=NodeStatus.active,
    )
    db.add(node)
    db.commit()
    db.refresh(node)

    event = NetworkEvent(
        node_id=node.id,
        source_ip="192.168.70.10",
        destination_ip="10.0.0.70",
        protocol=Protocol.TCP,
        event_type=EventType.auth_failed,
        event_message="Event for incident",
        severity=Severity.high,
        is_suspicious=True,
        created_by=admin_user.id,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    response = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "XSS Incident",
            "description": "<img src=x onerror=alert(1)>",
            "severity": "high",
            "event_id": event.id,
        },
    )

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"
