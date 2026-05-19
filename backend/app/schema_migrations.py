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
        "failed_login",
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

    _execute("ALTER TABLE audit_logs ALTER COLUMN user_id DROP NOT NULL")

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
        "users",
        "is_active",
        "is_active BOOLEAN NOT NULL DEFAULT TRUE",
    )

    # Создаём таблицу login_attempt_logs если её нет
    _execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempt_logs (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            user_agent VARCHAR(500),
            reason VARCHAR(100) NOT NULL,
            attempt_number INTEGER NOT NULL DEFAULT 1,
            locked_until TIMESTAMP NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    # Индексы для быстрого поиска
    _execute(
        "CREATE INDEX IF NOT EXISTS ix_login_attempt_logs_username ON login_attempt_logs (username)"
    )
    _execute(
        "CREATE INDEX IF NOT EXISTS ix_login_attempt_logs_ip_address ON login_attempt_logs (ip_address)"
    )
    _execute(
        "CREATE INDEX IF NOT EXISTS ix_login_attempt_logs_created_at ON login_attempt_logs (created_at)"
    )

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
