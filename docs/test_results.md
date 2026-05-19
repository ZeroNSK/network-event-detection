# Результаты тестирования

Дата актуализации: 2026-05-19.

## Команды проверки

Backend:

```bash
/private/tmp/lab4-rgr-venv311/bin/pytest backend/tests -q
```

Frontend:

```bash
cd frontend
npm run build
```

Аудит зависимостей:

```bash
cd frontend
npm audit --audit-level=moderate
/private/tmp/lab4-rgr-venv311/bin/pip-audit --local --cache-dir /private/tmp/pip-audit-cache --ignore-vuln CVE-2025-8869 --ignore-vuln CVE-2026-1703 --ignore-vuln CVE-2026-3219 --ignore-vuln CVE-2026-6357
```

## Итог

| Направление | Результат |
|---|---|
| Backend tests | `52 passed` |
| Frontend build | `vite build` успешно, Vite `8.0.13` |
| Frontend dependency audit | `found 0 vulnerabilities` |
| Python dependency audit | `No known vulnerabilities found`, уязвимости `pip` проигнорированы как часть временного venv, а не зависимость приложения |

## Проверенные сценарии

| Сценарий | Проверка | Статус |
|---|---|---|
| Регистрация | Создание `operator`, возврат без пароля | Пройдено |
| Password policy | Слабые пароли отклоняются | Пройдено |
| Вход | Возврат JWT | Пройдено |
| Неверный вход | 401, журналирование, security event | Пройдено |
| Lockout | 5 неудачных попыток дают 429 | Пройдено |
| Защищенный endpoint без токена | Доступ запрещен | Пройдено |
| Создание события | Риск рассчитывается автоматически | Пройдено |
| Валидация события | Некорректный IP/enum отклоняется | Пройдено |
| Корреляция auth_failed | Создается alert | Пройдено |
| Корреляция port_scan | Создается alert | Пройдено |
| Incident from alert | Повторный incident не дублируется | Пройдено |
| Operator delete alert | 403 | Пройдено |
| Security engineer run analysis | 200 | Пройдено |
| CSV import | Создаются события | Пройдено |
| Admin create/delete node | 201/204 | Пройдено |
| Operator create/delete node | 403 | Пройдено |
| SMTP notification | Для dangerous incident отправляется письмо | Пройдено |
| Access control events | Operator видит свои/выданные события | Пройдено |
| Access control incidents | Operator видит свои/назначенные/выданные инциденты | Пройдено |
| Admin user management | Смена роли и отключение учетной записи | Пройдено |
| Disabled user login | 403 | Пройдено |
| SQL injection login | Не обходит вход | Пройдено |
| SQL injection filter | Не расширяет выборку | Пройдено |
| XSS event message | Отклоняется | Пройдено |
| XSS incident description | Отклоняется | Пройдено |

## Остаточные замечания

Тесты проходят с предупреждениями о `datetime.utcnow()`, `sqlalchemy.ext.declarative.declarative_base()` и deprecated alias `HTTP_422_UNPROCESSABLE_ENTITY` в Starlette. Они не ломают работу, но в дальнейшем можно перейти на timezone-aware `datetime.now(datetime.UTC)`, `sqlalchemy.orm.declarative_base` и актуальный код статуса `HTTP_422_UNPROCESSABLE_CONTENT`.
