from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .models import LoginAttemptLog

MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 30


def _normalize_username(username: str) -> str:
    return username.strip()


def _get_active_lock_until(db: Session, username: str, now: datetime) -> datetime | None:
    latest_lock = (
        db.query(LoginAttemptLog)
        .filter(
            LoginAttemptLog.username == username,
            LoginAttemptLog.locked_until.isnot(None),
        )
        .order_by(LoginAttemptLog.locked_until.desc())
        .first()
    )
    if latest_lock and latest_lock.locked_until and latest_lock.locked_until > now:
        return latest_lock.locked_until
    return None


def _series_start_after_lock(db: Session, username: str, now: datetime) -> datetime | None:
    latest_lock = (
        db.query(LoginAttemptLog)
        .filter(
            LoginAttemptLog.username == username,
            LoginAttemptLog.locked_until.isnot(None),
        )
        .order_by(LoginAttemptLog.created_at.desc())
        .first()
    )
    if not latest_lock or not latest_lock.locked_until:
        return None
    if latest_lock.locked_until > now:
        return None
    return latest_lock.locked_until


def count_failed_attempts_in_series(db: Session, username: str) -> int:
    normalized = _normalize_username(username)
    if not normalized:
        return 0

    now = datetime.utcnow()
    if _get_active_lock_until(db, normalized, now):
        return MAX_FAILED_LOGIN_ATTEMPTS

    query = db.query(LoginAttemptLog).filter(
        LoginAttemptLog.username == normalized,
        LoginAttemptLog.reason.in_(["invalid_credentials", "account_locked"]),
    )
    series_start = _series_start_after_lock(db, normalized, now)
    if series_start:
        query = query.filter(LoginAttemptLog.created_at >= series_start)

    return query.count()


def get_login_lockout_state(db: Session, username: str) -> dict:
    normalized = _normalize_username(username)
    if not normalized:
        return {
            "locked": False,
            "retry_after_seconds": 0,
            "failed_attempts": 0,
            "attempts_remaining": MAX_FAILED_LOGIN_ATTEMPTS,
        }

    now = datetime.utcnow()
    active_lock_until = _get_active_lock_until(db, normalized, now)
    failed_attempts = count_failed_attempts_in_series(db, normalized)

    if active_lock_until:
        retry_after_seconds = max(1, int((active_lock_until - now).total_seconds()) + 1)
        return {
            "locked": True,
            "retry_after_seconds": retry_after_seconds,
            "failed_attempts": failed_attempts,
            "attempts_remaining": 0,
        }

    return {
        "locked": False,
        "retry_after_seconds": 0,
        "failed_attempts": failed_attempts,
        "attempts_remaining": max(0, MAX_FAILED_LOGIN_ATTEMPTS - failed_attempts),
    }


def _lockout_http_exception(retry_after_seconds: int, message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "message": message,
            "retry_after_seconds": retry_after_seconds,
        },
        headers={"Retry-After": str(retry_after_seconds)},
    )


def ensure_login_not_locked(db: Session, username: str) -> None:
    state = get_login_lockout_state(db, username)
    if state["locked"]:
        raise _lockout_http_exception(
            state["retry_after_seconds"],
            f"Слишком много неудачных попыток. Повторите через {state['retry_after_seconds']} с.",
        )


def raise_failed_login_error(
    *,
    locked: bool,
    retry_after_seconds: int,
    attempts_remaining: int,
) -> None:
    if locked:
        raise _lockout_http_exception(
            retry_after_seconds,
            f"Превышено число попыток входа. Повторите через {retry_after_seconds} с.",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "message": "Неверное имя пользователя или пароль",
            "attempts_remaining": attempts_remaining,
        },
    )


def next_failed_login_metadata(db: Session, username: str) -> tuple[int, datetime | None, bool]:
    normalized = _normalize_username(username)
    now = datetime.utcnow()
    attempt_number = count_failed_attempts_in_series(db, normalized) + 1
    locked_until = None
    locked = False

    if attempt_number >= MAX_FAILED_LOGIN_ATTEMPTS:
        locked_until = now + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
        locked = True

    return attempt_number, locked_until, locked
