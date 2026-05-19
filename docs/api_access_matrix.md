# API и роли доступа

Swagger доступен по адресу `http://localhost:8000/docs`.

## Аутентификация

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| POST | `/api/auth/register` | Регистрация | Открытый |
| POST | `/api/auth/login` | Вход и JWT | Открытый |
| GET | `/api/auth/login-lockout` | Статус блокировки входа | Открытый |
| GET | `/api/auth/me` | Текущий пользователь | Авторизованный |
| GET | `/api/auth/users` | Список пользователей | `admin`, `security_engineer` |
| PUT | `/api/auth/users/{id}` | Роль/email/status | `admin` |
| DELETE | `/api/auth/users/{id}` | Отключить пользователя | `admin` |

## События

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| GET | `/api/events` | Список событий | `admin`, `security_engineer`: все; `operator`: свои и выданные |
| GET | `/api/events/{id}` | Карточка события | По праву чтения |
| POST | `/api/events` | Создать событие | Авторизованный |
| PUT | `/api/events/{id}` | Изменить событие | `admin`, `security_engineer` |
| DELETE | `/api/events/{id}` | Удалить событие | `admin` |

## Инциденты

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| GET | `/api/incidents` | Список инцидентов | `admin`, `security_engineer`: все; `operator`: свои/назначенные/выданные |
| GET | `/api/incidents/{id}` | Карточка инцидента | По праву чтения |
| POST | `/api/incidents` | Создать инцидент | Авторизованный с доступом к событию |
| PUT | `/api/incidents/{id}` | Изменить инцидент | `admin`, `security_engineer` |
| DELETE | `/api/incidents/{id}` | Удалить инцидент | `admin` |

## Узлы

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| GET | `/api/nodes` | Список узлов | Авторизованный |
| GET | `/api/nodes/{id}` | Карточка узла | Авторизованный |
| POST | `/api/nodes` | Создать узел | `admin` |
| PUT | `/api/nodes/{id}` | Изменить узел | `admin` |
| DELETE | `/api/nodes/{id}` | Удалить узел | `admin` |

Узлы считаются справочником инфраструктуры. Изменение справочника доступно только администратору.

## Правила

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| GET | `/api/rules` | Список правил | Авторизованный |
| GET | `/api/rules/{id}` | Карточка правила | Авторизованный |
| POST | `/api/rules` | Создать правило | `admin` |
| PUT | `/api/rules/{id}` | Изменить правило | `admin` |
| DELETE | `/api/rules/{id}` | Удалить правило | `admin` |

Правила доступны на чтение как справочник классификации событий, управление доступно только администратору.

## Анализ и alerts

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| POST | `/api/analysis/run` | Запуск анализа | `admin`, `security_engineer` |
| GET | `/api/analysis/alerts` | Список alerts | `admin`, `security_engineer` |
| GET | `/api/analysis/alerts/{id}` | Карточка alert | `admin`, `security_engineer` |
| PUT | `/api/analysis/alerts/{id}` | Статус alert | `admin`, `security_engineer` |
| DELETE | `/api/analysis/alerts/{id}` | Удалить alert | `admin` |
| POST | `/api/analysis/alerts/{id}/create-incident` | Создать incident | `admin`, `security_engineer` |

## Dataset и аналитика

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| POST | `/api/dataset/import` | Импорт CSV | `admin`, `security_engineer` |
| GET | `/api/dataset/export/events` | Экспорт событий | `admin`, `security_engineer` |
| GET | `/api/dataset/export/incidents` | Экспорт инцидентов | `admin`, `security_engineer` |
| GET | `/api/dataset/sample` | Пример CSV | Авторизованный |
| GET | `/api/analytics/summary` | Сводка | Авторизованный, с учетом доступных данных |
| GET | `/api/analytics/timeline` | Динамика | Авторизованный, с учетом доступных данных |
| GET | `/api/analytics/top-sources` | Топ источников | Авторизованный, с учетом доступных данных |
| GET | `/api/analytics/risk-distribution` | Риски | Авторизованный, с учетом доступных данных |

## Журналы

| Метод | Endpoint | Назначение | Доступ |
|---|---|---|---|
| GET | `/api/logs` | Audit log | `admin`, `security_engineer` |
| GET | `/api/logs/login-attempts` | Неудачные входы | `admin`, `security_engineer` |
