"""
Tests for network nodes endpoints.
Requirements: 16.9, 16.10
"""
import pytest


def test_operator_cannot_create_node(client, operator_user, operator_token):
    """
    Test that an operator attempting to create a network node returns 403.
    Requirements: 16.9
    """
    response = client.post(
        "/api/nodes",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={
            "name": "Test-Node",
            "node_type": "router",
            "ip_address": "10.0.0.1",
            "location": "Test Location",
            "status": "active"
        }
    )
    
    assert response.status_code == 403
    assert "detail" in response.json()


def test_admin_can_create_node(client, admin_user, admin_token):
    """
    Test that an admin can successfully create a network node.
    Requirements: 16.10
    """
    response = client.post(
        "/api/nodes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Test-Node",
            "node_type": "router",
            "ip_address": "10.0.0.1",
            "location": "Test Location",
            "status": "active"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test-Node"
    assert data["node_type"] == "router"
    assert data["ip_address"] == "10.0.0.1"
    assert data["status"] == "active"


def test_security_engineer_cannot_delete_node(client, admin_user, admin_token, security_engineer_user, engineer_token, db):
    """
    Test that a security engineer cannot delete a network node.
    """
    # First create a node as admin
    from app.models import NetworkNode, NodeType, NodeStatus
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
    
    # Try to delete as security engineer
    response = client.delete(
        f"/api/nodes/{node.id}",
        headers={"Authorization": f"Bearer {engineer_token}"}
    )
    
    assert response.status_code == 403


def test_admin_can_delete_node(client, admin_user, admin_token, db):
    """
    Test that an admin can successfully delete a network node.
    """
    # First create a node
    from app.models import NetworkNode, NodeType, NodeStatus
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
    node_id = node.id
    
    # Delete as admin
    response = client.delete(
        f"/api/nodes/{node_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 204
    
    # Verify node is deleted
    deleted_node = db.query(NetworkNode).filter(NetworkNode.id == node_id).first()
    assert deleted_node is None
