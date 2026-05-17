"""
Tests for authentication endpoints.
Requirements: 16.1, 16.2, 16.3
"""
import pytest
from app.models import User, UserRole
from app.auth import hash_password


def test_register_user(client, db):
    """
    Test user registration creates a new user account.
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
    
    # Verify user exists in database
    user = db.query(User).filter(User.username == "newuser").first()
    assert user is not None
    assert user.email == "newuser@test.com"


def test_login_returns_jwt(client, admin_user):
    """
    Test user login returns a valid JWT token.
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
    Test login with invalid credentials returns 401.
    """
    response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "wrongpassword"
        }
    )
    
    assert response.status_code == 401
    assert "detail" in response.json()


def test_access_protected_endpoint_without_token(client):
    """
    Test accessing a protected endpoint without a token returns 401.
    Requirements: 16.3
    """
    response = client.get("/api/auth/me")
    
    assert response.status_code == 403  # FastAPI HTTPBearer returns 403 for missing token


def test_access_protected_endpoint_with_valid_token(client, admin_user, admin_token):
    """
    Test accessing a protected endpoint with a valid token succeeds.
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
    Test authenticated user can retrieve users list for assignment/access forms.
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


def test_access_protected_endpoint_with_invalid_token(client):
    """
    Test accessing a protected endpoint with an invalid token returns 401.
    """
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer invalid_token"}
    )
    
    assert response.status_code == 401
