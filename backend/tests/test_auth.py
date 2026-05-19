"""
Тесты endpoints аутентификации.
Requirements: 16.1, 16.2, 16.3
"""
import pytest
from app.models import (
    AuditAction,
    AuditLog,
    CorrelationAlert,
    EntityType,
    EventType,
    NetworkEvent,
    User,
    UserRole,
)
from app.auth import hash_password


def test_register_user(client, db):
    """
    Проверяет, что регистрация создает новую учетную запись пользователя.
    Requirements: 16.1
    """
    response = client.post(
        "/api/auth/register",
        json={
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "password123"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "newuser@test.com"
    assert data["role"] == "operator"  # Default role
    assert "id" in data
    assert "created_at" in data
    
    # Проверяем, что пользователь создан в базе данных.
    user = db.query(User).filter(User.username == "newuser").first()
    assert user is not None
    assert user.email == "newuser@test.com"


@pytest.mark.parametrize(
    "password",
    [
        "short1",
        "passwordonly",
        "12345678",
        "password 123",
    ],
)
def test_register_rejects_weak_password(client, password):
    """
    Проверяет, что регистрация отклоняет слабые пароли.
    """
    response = client.post(
        "/api/auth/register",
        json={
            "username": f"user_{password.replace(' ', '_')[:10]}",
            "email": f"{password.replace(' ', '_')}@test.com",
            "password": password,
        },
    )

    assert response.status_code == 422


def test_login_returns_jwt(client, admin_user):
    """
    Проверяет, что вход пользователя возвращает действительный JWT-токен.
    Requirements: 16.2
    """
    response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "admin123"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"


def test_login_invalid_credentials(client, admin_user):
    """
    Проверяет, что вход с неверными данными возвращает 401.
    """
    response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "wrongpassword"
        }
    )
    
    assert response.status_code == 401
    assert response.json()["code"] == "HTTP_401"
    assert response.json()["message"] == "Неверное имя пользователя или пароль"
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["message"] == "Неверное имя пользователя или пароль"
    assert detail["attempts_remaining"] == 4


def test_login_lockout_after_five_failed_attempts(client, admin_user):
    """
    Проверяет блокировку входа после пяти неверных паролей.
    """
    for attempt in range(4):
        response = client.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "wrongpassword",
            },
        )
        assert response.status_code == 401
        assert response.json()["detail"]["attempts_remaining"] == 4 - attempt

    response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "wrongpassword",
        },
    )
    assert response.status_code == 429
    assert response.json()["detail"]["retry_after_seconds"] == 30
    assert response.headers.get("retry-after") == "30"

    blocked_response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "admin123",
        },
    )
    assert blocked_response.status_code == 429

    status_response = client.get("/api/auth/login-lockout", params={"username": "admin"})
    assert status_response.status_code == 200
    assert status_response.json()["locked"] is True
    assert status_response.json()["retry_after_seconds"] >= 1


def test_login_invalid_credentials_creates_security_event_and_audit_log(client, admin_user, db):
    """
    Проверяет, что неуспешный вход фиксируется как сетевое событие и запись аудита.
    """
    response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "wrongpassword"
        },
        headers={"x-forwarded-for": "198.51.100.77"}
    )

    assert response.status_code == 401

    event = db.query(NetworkEvent).filter(NetworkEvent.event_type == EventType.auth_failed).first()
    assert event is not None
    assert event.source_ip == "198.51.100.77"
    assert event.risk_score >= 50
    assert event.is_suspicious is True
    assert "wrongpassword" not in event.event_message

    audit_log = db.query(AuditLog).filter(AuditLog.action == AuditAction.failed_login).first()
    assert audit_log is not None
    assert audit_log.user_id == admin_user.id
    assert audit_log.entity_type == EntityType.network_events
    assert audit_log.entity_id == event.id


def test_multiple_invalid_logins_create_correlation_alert(client, admin_user, db):
    """
    Проверяет, что серия неуспешных входов с одного IP создает корреляционное оповещение.
    """
    for index in range(5):
        response = client.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "wrongpassword"
            },
            headers={"x-forwarded-for": "198.51.100.88"}
        )
        if index < 4:
            assert response.status_code == 401
        else:
            assert response.status_code == 429

    alert = (
        db.query(CorrelationAlert)
        .filter(CorrelationAlert.title == "Множественные ошибки аутентификации")
        .first()
    )
    assert alert is not None
    assert alert.source_ip == "198.51.100.88"
    assert alert.event_count >= 5


def test_access_protected_endpoint_without_token(client):
    """
    Проверяет доступ к защищенному endpoint без токена.
    Requirements: 16.3
    """
    response = client.get("/api/auth/me")
    
    assert response.status_code == 401  # FastAPI HTTPBearer возвращает 401 при отсутствии токена.


def test_access_protected_endpoint_with_valid_token(client, admin_user, admin_token):
    """
    Проверяет успешный доступ к защищенному endpoint с действительным токеном.
    """
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "admin"
    assert data["role"] == "admin"


def test_get_users_returns_paginated_list(client, admin_user, operator_user, admin_token):
    """
    Проверяет, что аутентифицированный пользователь может получить список пользователей для форм назначения и доступа.
    """
    response = client.get(
        "/api/auth/users?limit=100",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 2
    usernames = [item["username"] for item in data["items"]]
    assert "admin" in usernames
    assert "operator" in usernames


def test_admin_can_update_user_role_and_status(client, admin_user, operator_user, admin_token, db):
    """
    Проверяет, что администратор может менять роль и активность пользователя.
    """
    response = client.put(
        f"/api/auth/users/{operator_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "role": "security_engineer",
            "is_active": False,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "security_engineer"
    assert data["is_active"] is False

    db.refresh(operator_user)
    assert operator_user.role == UserRole.security_engineer
    assert operator_user.is_active is False


def test_operator_cannot_update_user(client, admin_user, operator_user, operator_token):
    """
    Проверяет, что оператор не может управлять учетными записями.
    """
    response = client.put(
        f"/api/auth/users/{admin_user.id}",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={"role": "operator"},
    )

    assert response.status_code == 403


def test_admin_cannot_deactivate_self(client, admin_user, admin_token):
    """
    Проверяет защиту от отключения собственной учетной записи администратора.
    """
    response = client.delete(
        f"/api/auth/users/{admin_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 400


def test_inactive_user_cannot_login(client, operator_user, db):
    """
    Проверяет, что отключенная учетная запись не может войти в систему.
    """
    operator_user.is_active = False
    db.commit()

    response = client.post(
        "/api/auth/login",
        json={
            "username": "operator",
            "password": "operator123",
        },
    )

    assert response.status_code == 403


def test_access_protected_endpoint_with_invalid_token(client):
    """
    Проверяет доступ к защищенному endpoint с недействительным токеном.
    """
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer invalid_token"}
    )
    
    assert response.status_code == 401
