from sqlalchemy import inspect, text

from .database import engine


def _column_names(table_name: str) -> set[str]:
    inspector = inspect(engine)
    if not inspector.has_table(table_name):
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _execute(statement: str) -> None:
    with engine.begin() as connection:
        connection.execute(text(statement))


def _add_column_if_missing(table_name: str, column_name: str, ddl: str) -> None:
    if column_name not in _column_names(table_name):
        _execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")


def _upgrade_postgres_enums() -> None:
    if engine.dialect.name != "postgresql":
        return

    audit_actions = [
        "run_analysis",
        "create_alert",
        "update_alert",
        "import_dataset",
        "export_dataset",
        "create_incident_from_alert",
    ]
    entity_types = ["correlation_alerts"]

    for value in audit_actions:
        _execute(f"ALTER TYPE auditaction ADD VALUE IF NOT EXISTS '{value}'")
    for value in entity_types:
        _execute(f"ALTER TYPE entitytype ADD VALUE IF NOT EXISTS '{value}'")


def _upgrade_postgres_constraints() -> None:
    if engine.dialect.name != "postgresql":
        return

    _execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'fk_incidents_correlation_alert_id'
            ) THEN
                ALTER TABLE incidents
                ADD CONSTRAINT fk_incidents_correlation_alert_id
                FOREIGN KEY (correlation_alert_id)
                REFERENCES correlation_alerts(id);
            END IF;
        END $$;
        """
    )


def ensure_runtime_schema() -> None:
    """Small startup schema upgrade for projects without Alembic migrations."""
    _upgrade_postgres_enums()

    _add_column_if_missing(
        "network_events",
        "risk_score",
        "risk_score INTEGER NOT NULL DEFAULT 0",
    )
    _add_column_if_missing(
        "network_events",
        "risk_level",
        "risk_level VARCHAR(20) NOT NULL DEFAULT 'low'",
    )
    _add_column_if_missing(
        "network_events",
        "detection_reason",
        "detection_reason TEXT NOT NULL DEFAULT ''",
    )
    _add_column_if_missing(
        "network_events",
        "analyzed_at",
        "analyzed_at TIMESTAMP NULL",
    )

    _add_column_if_missing(
        "detection_rules",
        "risk_weight",
        "risk_weight INTEGER NOT NULL DEFAULT 0",
    )
    _add_column_if_missing(
        "detection_rules",
        "time_window_minutes",
        "time_window_minutes INTEGER NOT NULL DEFAULT 10",
    )
    _add_column_if_missing(
        "detection_rules",
        "threshold_count",
        "threshold_count INTEGER NOT NULL DEFAULT 1",
    )
    _add_column_if_missing(
        "detection_rules",
        "rule_category",
        "rule_category VARCHAR(50) NOT NULL DEFAULT 'configuration'",
    )

    _add_column_if_missing(
        "incidents",
        "correlation_alert_id",
        "correlation_alert_id INTEGER NULL",
    )
    _upgrade_postgres_constraints()
