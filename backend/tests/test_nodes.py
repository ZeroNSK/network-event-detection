"""
Тесты endpoints сетевых узлов.
Requirements: 16.9, 16.10
"""
import pytest


def test_operator_cannot_create_node(client, operator_user, operator_token):
    """
    Проверяет, что оператор получает 403 при попытке создать сетевой узел.
    Requirements: 16.9
    """
    response = client.post(
        "/api/nodes",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={
            "name": "Test-Node",
            "node_type": "router",
            "ip_address": "10.0.0.1",
            "location": "Тестовая локация",
            "status": "active"
        }
    )
    
    assert response.status_code == 403
    assert "detail" in response.json()


def test_admin_can_create_node(client, admin_user, admin_token):
    """
    Проверяет, что администратор может создать сетевой узел.
    Requirements: 16.10
    """
    response = client.post(
        "/api/nodes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Test-Node",
            "node_type": "router",
            "ip_address": "10.0.0.1",
            "location": "Тестовая локация",
            "status": "active"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test-Node"
    assert data["node_type"] == "router"
    assert data["ip_address"] == "10.0.0.1"
    assert data["status"] == "active"


def test_create_node_rejects_invalid_ip_and_type(client, admin_user, admin_token):
    """
    Проверяет валидацию типа узла и IP-адреса.
    """
    response = client.post(
        "/api/nodes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Bad-Node",
            "node_type": "satellite",
            "ip_address": "999.999.999.999",
            "location": "Тестовая локация",
            "status": "active",
        },
    )

    assert response.status_code == 422


def test_security_engineer_cannot_delete_node(client, admin_user, admin_token, security_engineer_user, engineer_token, db):
    """
    Проверяет, что инженер ИБ не может удалить сетевой узел.
    """
    # Сначала создаем узел от имени администратора.
    from app.models import NetworkNode, NodeType, NodeStatus
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
    
    # Пытаемся удалить узел от имени инженера ИБ.
    response = client.delete(
        f"/api/nodes/{node.id}",
        headers={"Authorization": f"Bearer {engineer_token}"}
    )
    
    assert response.status_code == 403


def test_admin_can_delete_node(client, admin_user, admin_token, db):
    """
    Проверяет, что администратор может удалить сетевой узел.
    """
    # Сначала создаем узел.
    from app.models import NetworkNode, NodeType, NodeStatus
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
    node_id = node.id
    
    # Удаляем от имени администратора.
    response = client.delete(
        f"/api/nodes/{node_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 204
    
    # Проверяем, что узел удален.
    deleted_node = db.query(NetworkNode).filter(NetworkNode.id == node_id).first()
    assert deleted_node is None
