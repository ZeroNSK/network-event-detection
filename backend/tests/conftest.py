import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models import User
from app.auth import hash_password


@pytest.fixture(autouse=True)
def disable_smtp_notifications(monkeypatch):
    """Не дает тестам использовать реальные SMTP-настройки окружения."""
    smtp_env_names = [
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "SMTP_FROM_EMAIL",
        "SMTP_TO_EMAILS",
        "SMTP_USE_TLS",
        "SMTP_USE_SSL",
        "SMTP_TIMEOUT",
    ]
    for name in smtp_env_names:
        monkeypatch.delenv(name, raising=False)


# Создаем SQLite-базу в памяти для тестов.
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Создает свежую базу данных для каждого теста."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """Создает тестовый клиент с подменой зависимости базы данных."""
    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        test_client.close()
        app.dependency_overrides.clear()


@pytest.fixture
def admin_user(db):
    """Создает администратора для тестов."""
    from app.models import UserRole
    user = User(
        username="admin",
        email="admin@test.com",
        hashed_password=hash_password("admin123"),
        role=UserRole.admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def operator_user(db):
    """Создает оператора для тестов."""
    from app.models import UserRole
    user = User(
        username="operator",
        email="operator@test.com",
        hashed_password=hash_password("operator123"),
        role=UserRole.operator
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def security_engineer_user(db):
    """Создает инженера ИБ для тестов."""
    from app.models import UserRole
    user = User(
        username="engineer",
        email="engineer@test.com",
        hashed_password=hash_password("engineer123"),
        role=UserRole.security_engineer
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_token(client, admin_user):
    """Получает JWT-токен администратора."""
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin123"}
    )
    return response.json()["access_token"]


@pytest.fixture
def operator_token(client, operator_user):
    """Получает JWT-токен оператора."""
    response = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator123"}
    )
    return response.json()["access_token"]


@pytest.fixture
def engineer_token(client, security_engineer_user):
    """Получает JWT-токен инженера ИБ."""
    response = client.post(
        "/api/auth/login",
        json={"username": "engineer", "password": "engineer123"}
    )
    return response.json()["access_token"]
