FROM python:3.11-slim

WORKDIR /app

# Устанавливаем системные зависимости.
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Копируем список зависимостей и устанавливаем Python-пакеты.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения.
COPY . .

# Открываем порт.
EXPOSE 8000

# Запускаем приложение.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
