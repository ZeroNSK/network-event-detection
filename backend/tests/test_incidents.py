"""
Tests for incidents endpoints.
Requirements: 16.6, 16.7, 16.8
"""
import pytest
from app.models import NetworkNode, NodeType, NodeStatus, NetworkEvent, EventType, Severity, Protocol


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
    """Create a suspicious network event for testing."""
    # Create a node first
    node = NetworkNode(
        name="Test-Node",
        node_type=NodeType.router,
        ip_address="10.0.0.1",
        location="Test Location",
        status=NodeStatus.active
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    
    # Create a suspicious event
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
    Test creating an incident from a suspicious event returns 201.
    Requirements: 16.8
    """
    response = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Test Incident",
            "description": "Test incident description",
            "severity": "high",
            "event_id": suspicious_event.id,
            "assigned_to": admin_user.id
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Test Incident"
    assert data["description"] == "Test incident description"
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
    """Test that creating a high-severity incident sends an SMTP notification."""
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
            "title": "Dangerous Incident",
            "description": "Requires immediate attention",
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
    assert "Dangerous incident" in message["Subject"]
    assert "Dangerous Incident" in message.get_content()
    assert "Severity: high" in message.get_content()


def test_create_non_dangerous_incident_does_not_send_email(
    client,
    admin_user,
    admin_token,
    suspicious_event,
    monkeypatch
):
    """Test that creating a medium-severity incident does not send an email."""
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
            "description": "No email expected",
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
    Test that an operator attempting to delete a network event returns 403.
    Requirements: 16.6
    """
    response = client.delete(
        f"/api/events/{suspicious_event.id}",
        headers={"Authorization": f"Bearer {operator_token}"}
    )
    
    assert response.status_code == 403


def test_admin_can_delete_event(client, admin_user, admin_token, suspicious_event, db):
    """
    Test that an admin can successfully delete a network event.
    Requirements: 16.7
    """
    event_id = suspicious_event.id
    
    response = client.delete(
        f"/api/events/{event_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 204
    
    # Verify event is deleted
    deleted_event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    assert deleted_event is None


def test_operator_sees_only_own_incidents(client, operator_user, operator_token, admin_user, admin_token, suspicious_event, db):
    """
    Test that an operator sees only their own incidents.
    """
    # Create incident as operator
    from app.models import Incident, IncidentStatus
    operator_incident = Incident(
        title="Operator Incident",
        description="Created by operator",
        status=IncidentStatus.new,
        severity=Severity.high,
        event_id=suspicious_event.id,
        created_by=operator_user.id
    )
    db.add(operator_incident)
    
    # Create incident as admin
    admin_incident = Incident(
        title="Admin Incident",
        description="Created by admin",
        status=IncidentStatus.new,
        severity=Severity.high,
        event_id=suspicious_event.id,
        created_by=admin_user.id
    )
    db.add(admin_incident)
    db.commit()
    
    # Operator should see only their incident
    response = client.get(
        "/api/incidents",
        headers={"Authorization": f"Bearer {operator_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Operator Incident"
    
    # Admin should see all incidents
    response = client.get(
        "/api/incidents",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2


def test_get_incident_returns_full_event_payload(client, admin_user, admin_token, suspicious_event, db):
    """
    Test that getting a single incident returns a payload matching IncidentResponse.
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
