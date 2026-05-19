# Система обнаружения подозрительной активности в сети связи

Веб-приложение для хранения, анализа и корреляции сетевых событий в инфраструктуре оператора связи. Проект расширяет лабораторную работу до уровня РГР по теме: «Разработка системы обнаружения подозрительной активности в сети связи на основе анализа сетевых событий».

## Назначение системы

Система помогает инженеру безопасности фиксировать события от сетевых узлов, автоматически рассчитывать риск каждого события, находить группы связанных событий и создавать инциденты безопасности. Приложение включает FastAPI backend, React + Vite frontend, PostgreSQL, JWT-аутентификацию, RBAC, Swagger и Docker Compose.

## Связь с темой РГР

РГР требует не только CRUD для сетевых событий, но и модель анализа. В проект добавлены:

- расчет `risk_score` и `risk_level` для каждого `network_event`;
- текстовое объяснение `detection_reason`;
- корреляционные правила для серий событий;
- таблицы `correlation_alerts` и `correlation_alert_events`;
- создание `incident` из correlation alert;
- аналитика, timeline, топ IP-источников и распределение риска;
- импорт и экспорт dataset через CSV;
- реалистичный seed-набор для сети связи.

## Модель анализа сетевых событий

При создании или изменении `network_event` backend автоматически пересчитывает:

- `risk_score`: число от 0 до 100;
- `risk_level`: `low`, `medium`, `high`, `critical`;
- `is_suspicious`: `true`, если `risk_score >= 50`;
- `detection_reason`: русскоязычное объяснение;
- `analyzed_at`: время анализа.

Активные `detection_rules`, совпадающие по `event_type`, добавляют к риску свой `risk_weight`.

## Расчет risk_score

Базовая формула складывает веса признаков и ограничивает итог максимумом 100.

| Признак | Вес |
|---|---:|
| `severity=low` | +10 |
| `severity=medium` | +25 |
| `severity=high` | +50 |
| `severity=critical` | +70 |
| `event_type=auth_failed` | +20 |
| `event_type=port_scan` | +35 |
| `event_type=traffic_spike` | +30 |
| `event_type=unauthorized_access` | +45 |
| `event_type=suspicious_ip` | +40 |
| `event_type=config_change` | +20 |
| `event_type=connection_drop` | +10 |
| `protocol=SSH` | +10 |
| `protocol=TCP` | +5 |
| `protocol=UDP` | +10 |
| `protocol=OTHER` или другой | +5 |
| внешний `source_ip` из `185.x.x.x`, `198.51.100.x`, `203.0.113.x` | +20 |
| `node_type=firewall` или `gateway` | +15 |
| `node_type=server` или `router` | +10 |
| `node_type=base_station` | +5 |

Уровни риска:

- `0-24`: `low`;
- `25-49`: `medium`;
- `50-74`: `high`;
- `75-100`: `critical`.

## Правила корреляции

Корреляция запускается при создании события и вручную через `POST /api/analysis/run`.

| Правило | Условие | Alert |
|---|---|---|
| Multiple auth failures | 5 и более `auth_failed` с одного `source_ip` за 10 минут | «Множественные ошибки аутентификации», risk 75, level `high` |
| Port scan | 3 и более `port_scan` с одного `source_ip` за 10 минут или обращения к разным `destination_ip` | «Признаки сканирования сетевой инфраструктуры», risk 80, level `critical` |
| Traffic spike on critical node | `traffic_spike` на `firewall`, `gateway`, `router` | «Аномальный рост трафика на критическом сетевом узле», risk 70, level `high` |
| Suspicious external access | внешний IP обращается к `server`, `firewall`, `gateway` или NMS с `unauthorized_access`/`suspicious_ip` | «Подозрительный внешний доступ к критическому узлу», risk 85, level `critical` |

## Dataset и импорт CSV

Импорт выполняется через `POST /api/dataset/import`. CSV должен содержать поля:

```csv
timestamp,node_name,source_ip,destination_ip,protocol,event_type,event_message,severity
2026-05-17T10:00:00,AUTH-RADIUS-01,203.0.113.91,10.10.5.5,UDP,auth_failed,Неуспешная RADIUS-аутентификация,high
```

Если узел из `node_name` отсутствует, он создается автоматически с `node_type=server`.

Экспорт:

- `GET /api/dataset/export/events`;
- `GET /api/dataset/export/incidents`;
- `GET /api/dataset/sample`.

## Аналитика

Backend предоставляет:

- `GET /api/analytics/summary`;
- `GET /api/analytics/timeline`;
- `GET /api/analytics/top-sources`;
- `GET /api/analytics/risk-distribution`.

Summary возвращает `total_events`, `suspicious_events`, `total_incidents`, `active_incidents`, `critical_events`, `critical_alerts`, `average_risk_score`, события и alerts за 24 часа, топ источников, топ типов событий, топ узлов и распределение риска.

## Примеры реалистичных событий

Seed-данные моделируют сеть связи:

- RADIUS auth failures на `AUTH-RADIUS-01`;
- PPPoE session failures на `BRAS-MSK-01`;
- SIP flood на `IMS-SBC-01`;
- port scan на `EDGE-FW-01` и `CORE-RTR-02`;
- DNS anomaly на `DNS-REC-01`;
- traffic spike на BRAS/EPC/firewall/router;
- unauthorized access к `NMS-SRV-01`;
- configuration change на `BSC-CTRL-07`;
- LTE base station connection drop на `LTE-eNB-2217`;
- suspicious external IP access к критическим узлам.

Минимальный seed-набор:

- 10 `network_nodes`;
- 10 `detection_rules`;
- 50 `network_events`;
- 15 `incidents`;
- 10+ `correlation_alerts`.

## Роли пользователей

| Роль | Возможности |
|---|---|
| `admin` | Полный доступ, удаление alert, управление правилами, dataset, аналитика, журнал |
| `security_engineer` | Запуск анализа, просмотр аналитики, работа с alert, создание incident из alert, импорт dataset |
| `operator` | Dashboard, создание `network_events`, просмотр summary-аналитики, без удаления и без управления правилами |

Тестовые пользователи:

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | `admin` |
| `engineer` | `engineer123` | `security_engineer` |
| `operator` | `operator123` | `operator` |

## API endpoints

Существующие CRUD endpoints сохранены:

- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`;
- `/api/nodes`;
- `/api/events`;
- `/api/rules`;
- `/api/incidents`;
- `/api/logs`;
- endpoints управления доступом к events/nodes/rules/incidents.

Новые endpoints РГР:

- `POST /api/analysis/run`;
- `GET /api/analysis/alerts`;
- `GET /api/analysis/alerts/{alert_id}`;
- `PUT /api/analysis/alerts/{alert_id}`;
- `DELETE /api/analysis/alerts/{alert_id}`;
- `POST /api/analysis/alerts/{alert_id}/create-incident`;
- `GET /api/analytics/summary`;
- `GET /api/analytics/timeline`;
- `GET /api/analytics/top-sources`;
- `GET /api/analytics/risk-distribution`;
- `POST /api/dataset/import`;
- `GET /api/dataset/export/events`;
- `GET /api/dataset/export/incidents`;
- `GET /api/dataset/sample`.

Swagger доступен по адресу `http://localhost:8000/docs`.

## Документация РГР

- `docs/technical_specification.md` - техническое задание по структуре РГР;
- `docs/interface_mockup.md` - макет и структура экранов;
- `docs/user_scenarios.md` - пользовательские сценарии по ролям;
- `docs/api_access_matrix.md` - API, методы и роли доступа;
- `docs/backup_and_maintenance.md` - backup, восстановление и сопровождение;
- `docs/test_results.md` - результаты функционального и ИБ-тестирования.

## Запуск через Docker

Перед запуском задайте секрет JWT в корневом `.env` или в переменной окружения:

```bash
printf "SECRET_KEY=%s\n" "$(openssl rand -hex 32)" > .env
```

```bash
docker compose up --build
```

Адреса:

- Frontend: `http://localhost:3001`;
- Backend API: `http://localhost:8000`;
- Swagger: `http://localhost:8000/docs`;
- PostgreSQL с хоста: `localhost:5433`.

Для чистого перезапуска с удалением данных:

```bash
docker compose down -v
docker compose up --build
```

## Проверка работы

1. Откройте `http://localhost:3001`.
2. Войдите как `engineer` / `engineer123`.
3. Перейдите в `Анализ` и нажмите `Запустить анализ`.
4. Откройте `Correlation alerts` и проверьте созданные alert.
5. Откройте любой alert и нажмите `Создать инцидент`.
6. Перейдите в `Инциденты` и убедитесь, что incident появился.
7. Откройте `Аналитика` и проверьте карточки, распределение риска и timeline.
8. Откройте `Dataset`, скачайте пример CSV, импортируйте его и проверьте последние события.

## Frontend-страницы

- `/dashboard`: средний риск, critical alerts, распределение риска, топ источников и типов событий;
- `/events`: новые колонки `risk_score`, `risk_level`, `detection_reason`, `analyzed_at` и фильтры риска;
- `/events/:id`: расчет риска, причины обнаружения, связанные alerts и incidents;
- `/analysis`: ручной запуск анализа;
- `/analysis/alerts`: таблица correlation alerts;
- `/analysis/alerts/:id`: карточка alert, события, статус и создание incident;
- `/analytics`: сводка, риск, топы, динамика по времени;
- `/dataset`: импорт CSV, пример CSV, экспорт событий и инцидентов.

## Тесты

Backend:

```bash
/private/tmp/lab4-rgr-venv311/bin/pytest backend/tests -q
```

Frontend:

```bash
cd frontend
npm install
npm run build
```

Проверено: backend tests проходят (`52 passed`), frontend production build собирается.
Дополнительно проверено: `npm audit --audit-level=moderate` возвращает `0 vulnerabilities`, Python dependency audit не находит уязвимостей в зависимостях приложения.
