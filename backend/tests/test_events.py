"""
Tests for network events endpoints.
Requirements: 16.4, 16.5
"""
import pytest
from app.models import NetworkNode, NodeType, NodeStatus, DetectionRule, EventType, Severity


@pytest.fixture
def network_node(db):
    """Create a network node for testing."""
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
    return node


@pytest.fixture
def detection_rule(db):
    """Create a detection rule for testing."""
    rule = DetectionRule(
        name="Test Rule",
        description="Test rule description",
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
    Test creating a network event with valid token returns 201.
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
    Test that a network event with severity 'critical' has is_suspicious set to true.
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
    Test that a network event with severity 'low' and non-suspicious event_type is not suspicious.
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
    Test that suspicious event types become suspicious once the computed risk reaches 50+.
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
