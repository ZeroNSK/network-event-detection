from sqlalchemy import or_
from sqlalchemy.orm import Session

from .models import EventAccess, Incident, IncidentAccess, NetworkEvent


SECURITY_ROLES = {"admin", "security_engineer"}
READ_ACCESS_LEVELS = {"read", "write", "manage"}


def has_global_security_read(current_user: dict) -> bool:
    return current_user["role"] in SECURITY_ROLES


def readable_events_query(db: Session, current_user: dict):
    query = db.query(NetworkEvent)
    if has_global_security_read(current_user):
        return query

    user_id = current_user["user_id"]
    shared_event_ids = (
        db.query(EventAccess.event_id)
        .filter(
            EventAccess.user_id == user_id,
            EventAccess.access_level.in_(READ_ACCESS_LEVELS),
        )
    )
    return query.filter(
        or_(
            NetworkEvent.created_by == user_id,
            NetworkEvent.id.in_(shared_event_ids),
        )
    )


def can_read_event(db: Session, event: NetworkEvent, current_user: dict) -> bool:
    if has_global_security_read(current_user):
        return True
    user_id = current_user["user_id"]
    if event.created_by == user_id:
        return True
    return (
        db.query(EventAccess)
        .filter(
            EventAccess.event_id == event.id,
            EventAccess.user_id == user_id,
            EventAccess.access_level.in_(READ_ACCESS_LEVELS),
        )
        .first()
        is not None
    )


def readable_incidents_query(db: Session, current_user: dict):
    query = db.query(Incident)
    if has_global_security_read(current_user):
        return query

    user_id = current_user["user_id"]
    shared_incident_ids = (
        db.query(IncidentAccess.incident_id)
        .filter(
            IncidentAccess.user_id == user_id,
            IncidentAccess.access_level.in_(READ_ACCESS_LEVELS),
        )
    )
    return query.filter(
        or_(
            Incident.created_by == user_id,
            Incident.assigned_to == user_id,
            Incident.id.in_(shared_incident_ids),
        )
    )


def can_read_incident(db: Session, incident: Incident, current_user: dict) -> bool:
    if has_global_security_read(current_user):
        return True
    user_id = current_user["user_id"]
    if incident.created_by == user_id or incident.assigned_to == user_id:
        return True
    return (
        db.query(IncidentAccess)
        .filter(
            IncidentAccess.incident_id == incident.id,
            IncidentAccess.user_id == user_id,
            IncidentAccess.access_level.in_(READ_ACCESS_LEVELS),
        )
        .first()
        is not None
    )
