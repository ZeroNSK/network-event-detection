# Backup, восстановление и сопровождение

## Какие данные копируются

Резервному копированию подлежит база PostgreSQL `network_security`, включая:

- пользователей и роли;
- сетевые узлы;
- события;
- правила обнаружения;
- correlation alerts;
- инциденты;
- журналы действий;
- журналы неудачных входов;
- таблицы доступа.

Не копируются в репозиторий: JWT-секрет, SMTP-пароли, реальные production `.env`.

## Где хранятся данные

В Docker Compose данные PostgreSQL хранятся в volume `postgres_data`.

## Рекомендуемый регламент backup

| Среда | Частота | Хранение |
|---|---|---|
| Учебный стенд | Перед защитой и после крупных изменений | Локальный `.sql` файл вне репозитория |
| Тестовая эксплуатация | 1 раз в сутки | Закрытый каталог/сетевое хранилище |
| Production | 1 раз в сутки + перед релизом | Защищенное хранилище с ротацией |

## Создание резервной копии

```bash
docker compose exec db pg_dump -U postgres network_security > backups/network_security_$(date +%Y%m%d_%H%M%S).sql
```

Каталог `backups/` должен быть вне публичного репозитория или добавлен в `.gitignore`.

## Восстановление

```bash
docker compose down
docker compose up -d db
docker compose exec -T db psql -U postgres -d network_security < backups/network_security_YYYYMMDD_HHMMSS.sql
docker compose up -d backend frontend
```

## Обновление приложения

1. Получить новую версию кода.
2. Проверить `.env` и секреты.
3. Создать backup базы.
4. Запустить тесты backend.
5. Собрать frontend.
6. Выполнить `docker compose up --build`.
7. Проверить `/health`, `/docs`, вход тестового пользователя.

## Мониторинг

Минимальные проверки:

- контейнер БД проходит `pg_isready`;
- backend отвечает на `/health`;
- frontend доступен на `http://localhost:3001`;
- в `audit_logs` появляются входы, изменения и удаления;
- в `login_attempt_logs` фиксируются неудачные входы.

Команды:

```bash
docker compose ps
docker compose logs backend
docker compose logs db
curl -I http://localhost:8000/health
```

## Восстановление после сбоя

1. Проверить состояние контейнеров.
2. Посмотреть backend/db logs.
3. Если повреждена БД, остановить сервисы и восстановить последний backup.
4. Запустить `docker compose up --build`.
5. Проверить вход, dashboard и создание тестового события.

## Масштабирование

Для роста нагрузки:

- вынести PostgreSQL на отдельный сервер;
- добавить регулярные Alembic migrations;
- добавить Redis/Kafka для потоковой обработки событий;
- вынести frontend в статический hosting;
- настроить централизованные логи и метрики.
