"""
Тесты endpoints инцидентов.
Requirements: 16.6, 16.7, 16.8
"""
import pytest
from app.models import AccessLevel, IncidentAccess, NetworkNode, NodeType, NodeStatus, NetworkEvent, EventType, Severity, Protocol


class FakeSMTP:
    instances = []
    messages = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.login_args = None
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def starttls(self):
        self.started_tls = True

    def login(self, username, password):
        self.login_args = (username, password)

    def send_message(self, message):
        self.__class__.messages.append(message)


@pytest.fixture
def suspicious_event(db, admin_user):
    """Создает подозрительное сетевое событие для тестов."""
    # Сначала создаем узел.
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
    
    # Создаем подозрительное событие.
    event = NetworkEvent(
        node_id=node.id,
        rule_id=None,
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        protocol=Protocol.TCP,
        event_type=EventType.auth_failed,
        event_message="Failed authentication attempt",
        severity=Severity.high,
        is_suspicious=True,
        created_by=admin_user.id
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def test_create_incident_from_suspicious_event(client, admin_user, admin_token, suspicious_event):
    """
    Проверяет, что создание инцидента из подозрительного события возвращает 201.
    Requirements: 16.8
    """
    response = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Тестовый инцидент",
            "description": "Описание тестового инцидента",
            "severity": "high",
            "event_id": suspicious_event.id,
            "assigned_to": admin_user.id
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Тестовый инцидент"
    assert data["description"] == "Описание тестового инцидента"
    assert data["severity"] == "high"
    assert data["event_id"] == suspicious_event.id
    assert data["status"] == "new"
    assert data["created_by"] == admin_user.id


def test_create_dangerous_incident_sends_email(
    client,
    admin_user,
    admin_token,
    suspicious_event,
    monkeypatch
):
    """Проверяет, что инцидент высокой критичности отправляет SMTP-уведомление."""
    FakeSMTP.instances = []
    FakeSMTP.messages = []
    monkeypatch.setenv("SMTP_HOST", "smtp.test.local")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("SMTP_USERNAME", "smtp-user")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-pass")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "alerts@test.local")
    monkeypatch.setenv("SMTP_TO_EMAILS", "security@test.local")
    monkeypatch.setattr("app.email_notifications.smtplib.SMTP", FakeSMTP)

    response = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Опасный инцидент",
            "description": "Требует немедленного внимания",
            "severity": "high",
            "event_id": suspicious_event.id,
            "assigned_to": admin_user.id
        }
    )

    assert response.status_code == 201
    assert len(FakeSMTP.messages) == 1
    assert FakeSMTP.instances[0].host == "smtp.test.local"
    assert FakeSMTP.instances[0].port == 2525
    assert FakeSMTP.instances[0].started_tls is True
    assert FakeSMTP.instances[0].login_args == ("smtp-user", "smtp-pass")

    message = FakeSMTP.messages[0]
    assert message["From"] == "alerts@test.local"
    assert message["To"] == "security@test.local"
    assert "Опасный инцидент" in message["Subject"]
    assert "Опасный инцидент" in message.get_content()
    assert "Критичность: high" in message.get_content()


def test_create_non_dangerous_incident_does_not_send_email(
    client,
    admin_user,
    admin_token,
    suspicious_event,
    monkeypatch
):
    """Проверяет, что инцидент средней критичности не отправляет письмо."""
    FakeSMTP.instances = []
    FakeSMTP.messages = []
    monkeypatch.setenv("SMTP_HOST", "smtp.test.local")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "alerts@test.local")
    monkeypatch.setenv("SMTP_TO_EMAILS", "security@test.local")
    monkeypatch.setattr("app.email_notifications.smtplib.SMTP", FakeSMTP)

    response = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Medium Incident",
            "description": "Письмо не ожидается",
            "severity": "medium",
            "event_id": suspicious_event.id,
            "assigned_to": admin_user.id
        }
    )

    assert response.status_code == 201
    assert FakeSMTP.instances == []
    assert FakeSMTP.messages == []


def test_operator_cannot_delete_event(client, operator_user, operator_token, suspicious_event):
    """
    Проверяет, что оператор получает 403 при попытке удалить сетевое событие.
    Requirements: 16.6
    """
    response = client.delete(
        f"/api/events/{suspicious_event.id}",
        headers={"Authorization": f"Bearer {operator_token}"}
    )
    
    assert response.status_code == 403


def test_admin_can_delete_event(client, admin_user, admin_token, suspicious_event, db):
    """
    Проверяет, что администратор может удалить сетевое событие.
    Requirements: 16.7
    """
    event_id = suspicious_event.id
    
    response = client.delete(
        f"/api/events/{event_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 204
    
    # Проверяем, что событие удалено.
    deleted_event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    assert deleted_event is None


def test_operator_sees_only_own_incidents(client, operator_user, operator_token, admin_user, admin_token, suspicious_event, db):
    """
    Проверяет, что оператор видит только свои инциденты.
    """
    # Создаем инцидент от имени оператора.
    from app.models import Incident, IncidentStatus
    operator_incident = Incident(
        title="Инцидент оператора",
        description="Создан оператором",
        status=IncidentStatus.new,
        severity=Severity.high,
        event_id=suspicious_event.id,
        created_by=operator_user.id
    )
    db.add(operator_incident)
    
    # Создаем инцидент от имени администратора.
    admin_incident = Incident(
        title="Инцидент администратора",
        description="Создан администратором",
        status=IncidentStatus.new,
        severity=Severity.high,
        event_id=suspicious_event.id,
        created_by=admin_user.id
    )
    db.add(admin_incident)
    db.commit()
    
    # Оператор должен видеть только свой инцидент.
    response = client.get(
        "/api/incidents",
        headers={"Authorization": f"Bearer {operator_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Инцидент оператора"
    
    # Администратор должен видеть все инциденты.
    response = client.get(
        "/api/incidents",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2


def test_operator_sees_shared_incident(client, operator_user, operator_token, admin_user, suspicious_event, db):
    """
    Проверяет, что оператор видит инцидент после явной выдачи доступа.
    """
    from app.models import Incident, IncidentStatus

    incident = Incident(
        title="Инцидент с доступом",
        description="Доступ выдан оператору",
        status=IncidentStatus.new,
        severity=Severity.high,
        event_id=suspicious_event.id,
        created_by=admin_user.id,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    db.add(
        IncidentAccess(
            incident_id=incident.id,
            user_id=operator_user.id,
            access_level=AccessLevel.read,
            granted_by=admin_user.id,
        )
    )
    db.commit()

    response = client.get(
        f"/api/incidents/{incident.id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == incident.id


def test_get_incident_returns_full_event_payload(client, admin_user, admin_token, suspicious_event, db):
    """
    Проверяет, что получение одного инцидента возвращает данные формата IncidentResponse.
    This guards against response validation errors on nested event fields.
    """
    from app.models import Incident, IncidentStatus

    incident = Incident(
        title="Detailed Incident",
        description="Incident for detail page",
        status=IncidentStatus.new,
        severity=Severity.high,
        event_id=suspicious_event.id,
        assigned_to=admin_user.id,
        created_by=admin_user.id
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    response = client.get(
        f"/api/incidents/{incident.id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == incident.id
    assert data["event"]["id"] == suspicious_event.id
    assert data["event"]["destination_ip"] == suspicious_event.destination_ip
    assert data["event"]["event_message"] == suspicious_event.event_message
    assert data["event"]["protocol"] == suspicious_event.protocol.value
