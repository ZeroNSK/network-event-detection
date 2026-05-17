from __future__ import annotations

import logging
import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage


logger = logging.getLogger(__name__)

DANGEROUS_INCIDENT_SEVERITIES = {"high", "critical"}


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _split_emails(value: str | None) -> tuple[str, ...]:
    cleaned = _clean(value)
    if not cleaned:
        return ()
    return tuple(email.strip() for email in cleaned.split(",") if email.strip())


def _env_bool(name: str, default: bool) -> bool:
    value = _clean(os.getenv(name))
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = _clean(os.getenv(name))
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning("Invalid %s value %r, using %s", name, value, default)
        return default


def _env_float(name: str, default: float) -> float:
    value = _clean(os.getenv(name))
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        logger.warning("Invalid %s value %r, using %s", name, value, default)
        return default


def _severity_value(severity: object) -> str:
    value = getattr(severity, "value", severity)
    return str(value).lower()


def is_dangerous_incident(severity: object) -> bool:
    return _severity_value(severity) in DANGEROUS_INCIDENT_SEVERITIES


@dataclass(frozen=True)
class SmtpSettings:
    host: str | None
    port: int
    username: str | None
    password: str | None
    sender: str | None
    recipients: tuple[str, ...]
    use_tls: bool
    use_ssl: bool
    timeout: float

    @classmethod
    def from_env(cls) -> "SmtpSettings":
        use_ssl = _env_bool("SMTP_USE_SSL", False)
        default_port = 465 if use_ssl else 587
        username = _clean(os.getenv("SMTP_USERNAME"))

        return cls(
            host=_clean(os.getenv("SMTP_HOST")),
            port=_env_int("SMTP_PORT", default_port),
            username=username,
            password=_clean(os.getenv("SMTP_PASSWORD")),
            sender=_clean(os.getenv("SMTP_FROM_EMAIL")) or username,
            recipients=_split_emails(os.getenv("SMTP_TO_EMAILS")),
            use_tls=_env_bool("SMTP_USE_TLS", not use_ssl),
            use_ssl=use_ssl,
            timeout=_env_float("SMTP_TIMEOUT", 10.0),
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.sender and self.recipients)


def _build_incident_body(incident: object) -> str:
    event = getattr(incident, "event", None)
    lines = [
        "Dangerous incident was created in the network monitoring system.",
        "",
        f"Incident ID: {getattr(incident, 'id', '-')}",
        f"Title: {getattr(incident, 'title', '-')}",
        f"Severity: {_severity_value(getattr(incident, 'severity', '-'))}",
        f"Status: {_severity_value(getattr(incident, 'status', '-'))}",
        f"Description: {getattr(incident, 'description', '-')}",
        f"Created by user ID: {getattr(incident, 'created_by', '-')}",
        f"Assigned to user ID: {getattr(incident, 'assigned_to', '-') or 'not assigned'}",
        f"Created at: {getattr(incident, 'created_at', '-')}",
    ]

    if event is not None:
        lines.extend(
            [
                "",
                "Related event:",
                f"Event ID: {getattr(event, 'id', '-')}",
                f"Event type: {_severity_value(getattr(event, 'event_type', '-'))}",
                f"Source IP: {getattr(event, 'source_ip', '-')}",
                f"Destination IP: {getattr(event, 'destination_ip', '-')}",
                f"Protocol: {_severity_value(getattr(event, 'protocol', '-'))}",
                f"Event message: {getattr(event, 'event_message', '-')}",
            ]
        )

    return "\n".join(lines)


def _build_incident_message(incident: object, settings: SmtpSettings) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = (
        f"[Network Security] Dangerous incident #{getattr(incident, 'id', '-')}: "
        f"{getattr(incident, 'title', '-')}"
    )
    message["From"] = settings.sender
    message["To"] = ", ".join(settings.recipients)
    message.set_content(_build_incident_body(incident))
    return message


def _send_message(message: EmailMessage, settings: SmtpSettings) -> None:
    smtp_class = smtplib.SMTP_SSL if settings.use_ssl else smtplib.SMTP

    with smtp_class(settings.host, settings.port, timeout=settings.timeout) as server:
        if settings.use_tls and not settings.use_ssl:
            server.starttls()
        if settings.username and settings.password:
            server.login(settings.username, settings.password)
        server.send_message(message)


def notify_dangerous_incident_created(incident: object) -> bool:
    if not is_dangerous_incident(getattr(incident, "severity", None)):
        return False

    settings = SmtpSettings.from_env()
    if not settings.is_configured:
        logger.info("Dangerous incident email skipped: SMTP is not configured")
        return False

    message = _build_incident_message(incident, settings)
    try:
        _send_message(message, settings)
    except Exception:
        logger.exception(
            "Failed to send dangerous incident email for incident %s",
            getattr(incident, "id", "-"),
        )
        return False

    logger.info(
        "Dangerous incident email sent for incident %s",
        getattr(incident, "id", "-"),
    )
    return True
