import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Получаем URL базы данных из переменной окружения.
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/network_security")

# Создаем подключение SQLAlchemy.
engine = create_engine(DATABASE_URL)

# Создаем фабрику сессий SessionLocal.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Создаем базовый класс для моделей.
Base = declarative_base()

# Зависимость для получения сессии базы данных.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
