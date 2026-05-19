"""
Тесты валидации правил обнаружения.
"""


def test_create_rule_rejects_invalid_thresholds(client, admin_user, admin_token):
    """
    Проверяет, что небезопасные числовые параметры правила отклоняются схемой.
    """
    response = client.post(
        "/api/rules",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Bad rule",
            "description": "Invalid rule limits",
            "event_type": "auth_failed",
            "severity_threshold": "high",
            "risk_weight": 500,
            "time_window_minutes": 0,
            "threshold_count": 0,
            "rule_category": "authentication",
            "is_active": True,
        },
    )

    assert response.status_code == 422
