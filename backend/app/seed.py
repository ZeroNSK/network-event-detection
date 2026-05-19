from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import (
    AccessLevel,
    CorrelationAlert,
    DetectionRule,
    EventType,
    Incident,
    IncidentAccess,
    IncidentStatus,
    NetworkEvent,
    NetworkNode,
    NodeStatus,
    NodeType,
    Protocol,
    Severity,
    User,
    UserRole,
)
from .analysis import analyze_event, run_full_analysis
from .auth import hash_password


def _ensure_user(db: Session, user_data: dict) -> User:
    is_active = user_data.get("is_active", True)
    user = db.query(User).filter(User.username == user_data["username"]).first()
    if user:
        changed = False
        if user.email != user_data["email"]:
            user.email = user_data["email"]
            changed = True
        if user.role != user_data["role"]:
            user.role = user_data["role"]
            changed = True
        if user.is_active != is_active:
            user.is_active = is_active
            changed = True
        if changed:
            db.flush()
        return user

    user = User(
        username=user_data["username"],
        email=user_data["email"],
        hashed_password=hash_password(user_data["password"]),
        role=user_data["role"],
        is_active=is_active,
    )
    db.add(user)
    db.flush()
    return user


def _ensure_node(db: Session, node_data: dict) -> NetworkNode:
    node = db.query(NetworkNode).filter(NetworkNode.name == node_data["name"]).first()
    if not node:
        node = NetworkNode(**node_data)
        db.add(node)
        db.flush()
        return node

    for field, value in node_data.items():
        setattr(node, field, value)
    db.flush()
    return node


def _ensure_rule(db: Session, rule_data: dict) -> DetectionRule:
    aliases = rule_data.get("aliases", [])
    rule_names = [rule_data["name"], *aliases]
    rule_payload = {key: value for key, value in rule_data.items() if key != "aliases"}
    rule = db.query(DetectionRule).filter(DetectionRule.name.in_(rule_names)).first()
    if not rule:
        rule = DetectionRule(**rule_payload)
        db.add(rule)
        db.flush()
        return rule

    for field, value in rule_payload.items():
        setattr(rule, field, value)
    db.flush()
    return rule


def _ensure_event(db: Session, event_data: dict) -> NetworkEvent:
    event = db.query(NetworkEvent).filter(
        NetworkEvent.node_id == event_data["node_id"],
        NetworkEvent.source_ip == event_data["source_ip"],
        NetworkEvent.destination_ip == event_data["destination_ip"],
        NetworkEvent.event_message == event_data["event_message"],
    ).first()

    event_payload = dict(event_data)
    event_payload.setdefault("is_suspicious", False)

    if not event:
        event = NetworkEvent(**event_payload)
        db.add(event)
        db.flush()
        analyze_event(db, event)
        db.flush()
        return event

    for field, value in event_payload.items():
        setattr(event, field, value)
    db.flush()
    analyze_event(db, event)
    db.flush()
    return event


def _ensure_incident(db: Session, incident_data: dict) -> Incident:
    incident = db.query(Incident).filter(Incident.title == incident_data["title"]).first()
    if not incident:
        incident = Incident(**incident_data)
        db.add(incident)
        db.flush()
        return incident

    for field, value in incident_data.items():
        setattr(incident, field, value)
    db.flush()
    return incident


def _ensure_incident_access(db: Session, access_data: dict) -> IncidentAccess:
    access = db.query(IncidentAccess).filter(
        IncidentAccess.incident_id == access_data["incident_id"],
        IncidentAccess.user_id == access_data["user_id"],
    ).first()
    if not access:
        access = IncidentAccess(**access_data)
        db.add(access)
        db.flush()
        return access

    access.access_level = access_data["access_level"]
    access.granted_by = access_data["granted_by"]
    db.flush()
    return access


def seed_database():
    """Заполняет базу реалистичными демонстрационными данными сети связи."""
    db = SessionLocal()

    try:
        print("Проверка демонстрационных данных сети связи...")

        users_data = [
            {
                "username": "admin",
                "email": "admin@telecom.local",
                "password": "admin123",
                "role": UserRole.admin,
            },
            {
                "username": "engineer",
                "email": "engineer@telecom.local",
                "password": "engineer123",
                "role": UserRole.security_engineer,
            },
            {
                "username": "operator",
                "email": "operator@telecom.local",
                "password": "operator123",
                "role": UserRole.operator,
            },
            {
                "username": "soc_lead",
                "email": "soc_lead@telecom.local",
                "password": "soclead123",
                "role": UserRole.security_engineer,
            },
            {
                "username": "noc_shift",
                "email": "noc_shift@telecom.local",
                "password": "nocshift123",
                "role": UserRole.operator,
            },
            {
                "username": "voip_ops",
                "email": "voip_ops@telecom.local",
                "password": "voipops123",
                "role": UserRole.security_engineer,
            },
        ]
        users = {user["username"]: _ensure_user(db, user) for user in users_data}
        db.commit()
        print(f"Пользователей доступно: {db.query(User).count()}")

        nodes_data = [
            {
                "name": "BRAS-MSK-01",
                "node_type": NodeType.server,
                "ip_address": "10.10.1.10",
                "location": "Москва, М9, BRAS-сегмент",
                "status": NodeStatus.warning,
            },
            {
                "name": "EPC-GW-NSK-01",
                "node_type": NodeType.gateway,
                "ip_address": "10.10.2.20",
                "location": "Новосибирск, ядро EPC",
                "status": NodeStatus.active,
            },
            {
                "name": "IMS-SBC-01",
                "node_type": NodeType.server,
                "ip_address": "10.10.3.30",
                "location": "Москва, пограничный VoIP-кластер",
                "status": NodeStatus.warning,
            },
            {
                "name": "BSC-CTRL-07",
                "node_type": NodeType.base_station,
                "ip_address": "172.16.7.17",
                "location": "Омск, контроллер базовых станций",
                "status": NodeStatus.active,
            },
            {
                "name": "LTE-eNB-2217",
                "node_type": NodeType.base_station,
                "ip_address": "10.10.22.17",
                "location": "Новосибирск, площадка LTE-2217",
                "status": NodeStatus.offline,
            },
            {
                "name": "CORE-RTR-02",
                "node_type": NodeType.router,
                "ip_address": "10.10.0.2",
                "location": "Москва, магистральное ядро IP/MPLS",
                "status": NodeStatus.active,
            },
            {
                "name": "EDGE-FW-01",
                "node_type": NodeType.firewall,
                "ip_address": "172.16.0.1",
                "location": "Москва, периметр сети управления",
                "status": NodeStatus.warning,
            },
            {
                "name": "AUTH-RADIUS-01",
                "node_type": NodeType.server,
                "ip_address": "10.10.5.5",
                "location": "Москва, AAA-сервисы",
                "status": NodeStatus.active,
            },
            {
                "name": "DNS-REC-01",
                "node_type": NodeType.server,
                "ip_address": "10.10.6.53",
                "location": "Новосибирск, ферма рекурсивных DNS-серверов",
                "status": NodeStatus.active,
            },
            {
                "name": "NMS-SRV-01",
                "node_type": NodeType.server,
                "ip_address": "172.16.10.10",
                "location": "Москва, система управления сетью",
                "status": NodeStatus.active,
            },
            {
                "name": "MGMT-SW-01",
                "node_type": NodeType.switch,
                "ip_address": "172.16.10.2",
                "location": "Москва, коммутатор сети управления",
                "status": NodeStatus.active,
            },
            {
                "name": "CGNAT-GW-01",
                "node_type": NodeType.gateway,
                "ip_address": "10.10.8.1",
                "location": "Новосибирск, CGNAT-шлюз",
                "status": NodeStatus.warning,
            },
            {
                "name": "DHCP-SRV-01",
                "node_type": NodeType.server,
                "ip_address": "10.10.9.67",
                "location": "Москва, сервисы DHCP-аренды",
                "status": NodeStatus.active,
            },
            {
                "name": "AGG-RTR-NSK-03",
                "node_type": NodeType.router,
                "ip_address": "10.10.0.33",
                "location": "Новосибирск, агрегационный IP/MPLS узел",
                "status": NodeStatus.active,
            },
            {
                "name": "LTE-eNB-2388",
                "node_type": NodeType.base_station,
                "ip_address": "10.10.23.88",
                "location": "Бердск, площадка LTE-2388",
                "status": NodeStatus.warning,
            },
        ]
        nodes = {node["name"]: _ensure_node(db, node) for node in nodes_data}
        db.commit()
        print(f"Сетевых узлов доступно: {db.query(NetworkNode).count()}")

        rules_data = [
            {
                "name": "Серия ошибок RADIUS-аутентификации",
                "aliases": ["RADIUS Authentication Failure Burst"],
                "description": "Выявляет серию неуспешных RADIUS-аутентификаций абонентских сессий с одного источника.",
                "event_type": EventType.auth_failed,
                "severity_threshold": Severity.high,
                "risk_weight": 15,
                "time_window_minutes": 10,
                "threshold_count": 5,
                "rule_category": "authentication",
                "is_active": True,
            },
            {
                "name": "Сканирование портов пограничного маршрутизатора",
                "aliases": ["Edge Router Port Scan Sweep"],
                "description": "Фиксирует последовательное обращение к нескольким TCP-портам пограничного маршрутизатора.",
                "event_type": EventType.port_scan,
                "severity_threshold": Severity.high,
                "risk_weight": 20,
                "time_window_minutes": 10,
                "threshold_count": 3,
                "rule_category": "network_scan",
                "is_active": True,
            },
            {
                "name": "Всплеск SIP-трафика",
                "aliases": ["SIP Flood Traffic Spike"],
                "description": "Выявляет резкий рост UDP/SIP-трафика на SBC и VoIP-сервисах.",
                "event_type": EventType.traffic_spike,
                "severity_threshold": Severity.critical,
                "risk_weight": 20,
                "time_window_minutes": 5,
                "threshold_count": 3,
                "rule_category": "traffic_anomaly",
                "is_active": True,
            },
            {
                "name": "Несанкционированное изменение конфигурации BSC",
                "aliases": ["Unauthorized BSC Configuration Change"],
                "description": "Контролирует попытки изменения конфигурации контроллеров базовых станций без подтвержденной админ-сессии.",
                "event_type": EventType.config_change,
                "severity_threshold": Severity.critical,
                "risk_weight": 15,
                "time_window_minutes": 30,
                "threshold_count": 1,
                "rule_category": "configuration",
                "is_active": True,
            },
            {
                "name": "Потеря связи с базовой станцией",
                "aliases": ["Base Station Link Loss"],
                "description": "Определяет потерю связи с базовой станцией дольше 5 минут.",
                "event_type": EventType.connection_drop,
                "severity_threshold": Severity.medium,
                "risk_weight": 10,
                "time_window_minutes": 15,
                "threshold_count": 2,
                "rule_category": "availability",
                "is_active": True,
            },
            {
                "name": "Доступ к NMS из недоверенной сети",
                "aliases": ["Untrusted NMS Access Attempt"],
                "description": "Обнаруживает подключения к NMS из недоверенных административных подсетей.",
                "event_type": EventType.unauthorized_access,
                "severity_threshold": Severity.high,
                "risk_weight": 25,
                "time_window_minutes": 10,
                "threshold_count": 1,
                "rule_category": "unauthorized_access",
                "is_active": True,
            },
            {
                "name": "DNS-запросы к IOC-индикаторам",
                "aliases": ["DNS IOC Query Detection"],
                "description": "Ищет запросы к доменам, связанным с известными индикаторами компрометации.",
                "event_type": EventType.suspicious_ip,
                "severity_threshold": Severity.high,
                "risk_weight": 15,
                "time_window_minutes": 20,
                "threshold_count": 2,
                "rule_category": "unauthorized_access",
                "is_active": True,
            },
            {
                "name": "Аномальный профиль трафика EPC-шлюза",
                "aliases": ["EPC Gateway Abnormal Flow Profile"],
                "description": "Сигнализирует о нестандартном профиле соединений на шлюзе пакетного ядра.",
                "event_type": EventType.other,
                "severity_threshold": Severity.critical,
                "risk_weight": 10,
                "time_window_minutes": 15,
                "threshold_count": 4,
                "rule_category": "traffic_anomaly",
                "is_active": True,
            },
            {
                "name": "Массовые отказы PPPoE-сессий",
                "aliases": ["PPPoE Session Failure Storm"],
                "description": "Выявляет всплеск отказов PPPoE-сессий на BRAS и AAA-инфраструктуре.",
                "event_type": EventType.auth_failed,
                "severity_threshold": Severity.medium,
                "risk_weight": 10,
                "time_window_minutes": 10,
                "threshold_count": 5,
                "rule_category": "authentication",
                "is_active": True,
            },
            {
                "name": "Внешний IOC-доступ к критическому узлу",
                "aliases": ["Critical Node External IOC Access"],
                "description": "Повышает риск при обращении подозрительных внешних IP к NMS, межсетевому экрану, шлюзу или серверным узлам.",
                "event_type": EventType.suspicious_ip,
                "severity_threshold": Severity.high,
                "risk_weight": 20,
                "time_window_minutes": 10,
                "threshold_count": 1,
                "rule_category": "unauthorized_access",
                "is_active": True,
            },
            {
                "name": "Истощение таблицы соединений CGNAT",
                "aliases": ["CGNAT Flow Exhaustion"],
                "description": "Фиксирует аномальный рост числа трансляций и короткоживущих TCP-сессий на CGNAT-шлюзе.",
                "event_type": EventType.traffic_spike,
                "severity_threshold": Severity.high,
                "risk_weight": 15,
                "time_window_minutes": 5,
                "threshold_count": 3,
                "rule_category": "traffic_anomaly",
                "is_active": True,
            },
            {
                "name": "Подозрительные DHCP-запросы аренды",
                "aliases": ["DHCP Lease Abuse Pattern"],
                "description": "Выявляет подозрительные запросы аренды адресов и попытки истощения DHCP-пула.",
                "event_type": EventType.suspicious_ip,
                "severity_threshold": Severity.medium,
                "risk_weight": 12,
                "time_window_minutes": 10,
                "threshold_count": 4,
                "rule_category": "availability",
                "is_active": True,
            },
        ]
        rules = {rule["name"]: _ensure_rule(db, rule) for rule in rules_data}
        db.commit()
        print(f"Правил обнаружения доступно: {db.query(DetectionRule).count()}")

        events_data = [
            {
                "node_id": nodes["AUTH-RADIUS-01"].id,
                "rule_id": rules["Серия ошибок RADIUS-аутентификации"].id,
                "source_ip": "185.71.66.14",
                "destination_ip": "10.10.5.5",
                "protocol": Protocol.UDP,
                "event_type": EventType.auth_failed,
                "event_message": "Множественные неуспешные попытки RADIUS-аутентификации PPPoE-сессий с IP 185.71.66.14 на узле AUTH-RADIUS-01 в течение 3 минут.",
                "severity": Severity.high,
                "created_by": users["engineer"].id,
            },
            {
                "node_id": nodes["CORE-RTR-02"].id,
                "rule_id": rules["Сканирование портов пограничного маршрутизатора"].id,
                "source_ip": "203.0.113.77",
                "destination_ip": "10.10.0.2",
                "protocol": Protocol.TCP,
                "event_type": EventType.port_scan,
                "event_message": "Обнаружено последовательное обращение к TCP-портам 22, 23, 80 и 443 на CORE-RTR-02 с внешнего адреса 203.0.113.77.",
                "severity": Severity.high,
                "created_by": users["operator"].id,
            },
            {
                "node_id": nodes["IMS-SBC-01"].id,
                "rule_id": rules["Всплеск SIP-трафика"].id,
                "source_ip": "198.51.100.23",
                "destination_ip": "10.10.3.30",
                "protocol": Protocol.UDP,
                "event_type": EventType.traffic_spike,
                "event_message": "На IMS-SBC-01 зафиксирован резкий рост UDP-трафика на SIP-порт 5060, похожий на SIP-флуд.",
                "severity": Severity.critical,
                "created_by": users["voip_ops"].id,
            },
            {
                "node_id": nodes["BSC-CTRL-07"].id,
                "rule_id": rules["Несанкционированное изменение конфигурации BSC"].id,
                "source_ip": "172.16.7.250",
                "destination_ip": "172.16.7.17",
                "protocol": Protocol.SSH,
                "event_type": EventType.config_change,
                "event_message": "Попытка изменения конфигурации BSC-CTRL-07 без подтвержденной административной сессии из сети управления.",
                "severity": Severity.critical,
                "created_by": users["soc_lead"].id,
            },
            {
                "node_id": nodes["LTE-eNB-2217"].id,
                "rule_id": rules["Потеря связи с базовой станцией"].id,
                "source_ip": "10.10.22.17",
                "destination_ip": "10.10.0.2",
                "protocol": Protocol.ICMP,
                "event_type": EventType.connection_drop,
                "event_message": "Потеря связи с базовой станцией LTE-eNB-2217 более чем на 5 минут по транспортному каналу.",
                "severity": Severity.medium,
                "created_by": users["noc_shift"].id,
            },
            {
                "node_id": nodes["NMS-SRV-01"].id,
                "rule_id": rules["Доступ к NMS из недоверенной сети"].id,
                "source_ip": "185.19.204.55",
                "destination_ip": "172.16.10.10",
                "protocol": Protocol.HTTPS,
                "event_type": EventType.unauthorized_access,
                "event_message": "Зафиксирована попытка входа на NMS-SRV-01 с IP 185.19.204.55, отсутствующего в списке доверенных административных подсетей.",
                "severity": Severity.high,
                "created_by": users["engineer"].id,
            },
            {
                "node_id": nodes["BRAS-MSK-01"].id,
                "rule_id": rules["Серия ошибок RADIUS-аутентификации"].id,
                "source_ip": "10.10.100.44",
                "destination_ip": "10.10.1.10",
                "protocol": Protocol.TCP,
                "event_type": EventType.traffic_spike,
                "event_message": "Повышенное число ошибок авторизации PPPoE-сессий и рост количества переподключений на BRAS-MSK-01.",
                "severity": Severity.medium,
                "created_by": users["noc_shift"].id,
            },
            {
                "node_id": nodes["DNS-REC-01"].id,
                "rule_id": rules["DNS-запросы к IOC-индикаторам"].id,
                "source_ip": "192.168.44.19",
                "destination_ip": "10.10.6.53",
                "protocol": Protocol.UDP,
                "event_type": EventType.suspicious_ip,
                "event_message": "DNS-REC-01 обработал серию запросов к доменам из списка IOC, инициированных узлом 192.168.44.19.",
                "severity": Severity.high,
                "created_by": users["soc_lead"].id,
            },
            {
                "node_id": nodes["EDGE-FW-01"].id,
                "rule_id": rules["Доступ к NMS из недоверенной сети"].id,
                "source_ip": "198.51.100.88",
                "destination_ip": "172.16.0.1",
                "protocol": Protocol.HTTPS,
                "event_type": EventType.auth_failed,
                "event_message": "На EDGE-FW-01 повторяются неуспешные попытки входа в административный интерфейс из внешней сети 198.51.100.88.",
                "severity": Severity.high,
                "created_by": users["operator"].id,
            },
            {
                "node_id": nodes["EPC-GW-NSK-01"].id,
                "rule_id": rules["Аномальный профиль трафика EPC-шлюза"].id,
                "source_ip": "10.10.200.14",
                "destination_ip": "10.10.2.20",
                "protocol": Protocol.GTP if hasattr(Protocol, "GTP") else Protocol.OTHER,
                "event_type": EventType.other,
                "event_message": "На EPC-GW-NSK-01 обнаружена серия соединений с нестандартным профилем трафика и ростом сигнализации в сегменте пакетного ядра.",
                "severity": Severity.critical,
                "created_by": users["engineer"].id,
            },
            {
                "node_id": nodes["AUTH-RADIUS-01"].id,
                "rule_id": rules["Серия ошибок RADIUS-аутентификации"].id,
                "source_ip": "203.0.113.91",
                "destination_ip": "10.10.5.5",
                "protocol": Protocol.UDP,
                "event_type": EventType.auth_failed,
                "event_message": "Наблюдается всплеск Access-Reject для сессий xDSL-абонентов с источника 203.0.113.91 на AUTH-RADIUS-01.",
                "severity": Severity.high,
                "created_by": users["engineer"].id,
            },
            {
                "node_id": nodes["IMS-SBC-01"].id,
                "rule_id": rules["Всплеск SIP-трафика"].id,
                "source_ip": "185.203.116.9",
                "destination_ip": "10.10.3.30",
                "protocol": Protocol.UDP,
                "event_type": EventType.traffic_spike,
                "event_message": "На SBC замечен кратный рост INVITE/REGISTER запросов с IP 185.203.116.9, превышающий базовый профиль VoIP-трафика.",
                "severity": Severity.critical,
                "created_by": users["voip_ops"].id,
            },
            {
                "node_id": nodes["NMS-SRV-01"].id,
                "rule_id": rules["Доступ к NMS из недоверенной сети"].id,
                "source_ip": "172.16.99.40",
                "destination_ip": "172.16.10.10",
                "protocol": Protocol.SSH,
                "event_type": EventType.unauthorized_access,
                "event_message": "Попытка SSH-подключения к NMS-SRV-01 из сегмента управления 172.16.99.40, не включенного в список доверенных хостов.",
                "severity": Severity.medium,
                "created_by": users["soc_lead"].id,
            },
            {
                "node_id": nodes["CORE-RTR-02"].id,
                "rule_id": rules["Сканирование портов пограничного маршрутизатора"].id,
                "source_ip": "185.244.39.120",
                "destination_ip": "10.10.0.2",
                "protocol": Protocol.TCP,
                "event_type": EventType.port_scan,
                "event_message": "Повторная серия SYN-запросов к служебным портам маршрутизатора CORE-RTR-02 со стороны 185.244.39.120.",
                "severity": Severity.high,
                "created_by": users["operator"].id,
            },
            {
                "node_id": nodes["DNS-REC-01"].id,
                "rule_id": rules["DNS-запросы к IOC-индикаторам"].id,
                "source_ip": "10.10.55.24",
                "destination_ip": "10.10.6.53",
                "protocol": Protocol.UDP,
                "event_type": EventType.suspicious_ip,
                "event_message": "DNS-REC-01 получил множественные запросы к доменам, совпадающим с телеком-IOC, от внутреннего узла 10.10.55.24.",
                "severity": Severity.medium,
                "created_by": users["soc_lead"].id,
            },
            {
                "node_id": nodes["BRAS-MSK-01"].id,
                "rule_id": rules["Серия ошибок RADIUS-аутентификации"].id,
                "source_ip": "192.168.10.201",
                "destination_ip": "10.10.1.10",
                "protocol": Protocol.TCP,
                "event_type": EventType.auth_failed,
                "event_message": "На BRAS-MSK-01 зафиксирована серия ошибок аутентификации PPPoE-сессий абонентского концентратора 192.168.10.201.",
                "severity": Severity.medium,
                "created_by": users["noc_shift"].id,
            },
        ]
        base_time = datetime.utcnow() - timedelta(hours=3)

        def add_event(
            *,
            minutes: int,
            node_name: str,
            rule_name: str,
            source_ip: str,
            destination_ip: str,
            protocol: Protocol,
            event_type: EventType,
            event_message: str,
            severity: Severity,
            created_by: str,
        ) -> None:
            events_data.append(
                {
                    "node_id": nodes[node_name].id,
                    "rule_id": rules[rule_name].id,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "protocol": protocol,
                    "event_type": event_type,
                    "event_message": event_message,
                    "severity": severity,
                    "created_by": users[created_by].id,
                    "created_at": base_time + timedelta(minutes=minutes),
                }
            )

        for index in range(5):
            add_event(
                minutes=index,
                node_name="AUTH-RADIUS-01",
                rule_name="Серия ошибок RADIUS-аутентификации",
                source_ip="203.0.113.91",
                destination_ip="10.10.5.5",
                protocol=Protocol.UDP,
                event_type=EventType.auth_failed,
                event_message=f"Отказ RADIUS Access-Reject №{index + 1}: отказ PPPoE-аутентификации абонентской сессии с внешнего источника 203.0.113.91.",
                severity=Severity.high,
                created_by="engineer",
            )

        for index in range(5):
            add_event(
                minutes=12 + index,
                node_name="BRAS-MSK-01",
                rule_name="Массовые отказы PPPoE-сессий",
                source_ip="198.51.100.45",
                destination_ip="10.10.1.10",
                protocol=Protocol.TCP,
                event_type=EventType.auth_failed,
                event_message=f"Отказ PPPoE №{index + 1}: BRAS-MSK-01 отклонил сессию после некорректных учетных данных абонента.",
                severity=Severity.medium,
                created_by="noc_shift",
            )

        for index, destination in enumerate(["172.16.0.1", "172.16.0.2", "172.16.0.3", "172.16.0.4"]):
            add_event(
                minutes=30 + index,
                node_name="EDGE-FW-01",
                rule_name="Сканирование портов пограничного маршрутизатора",
                source_ip="198.51.100.77",
                destination_ip=destination,
                protocol=Protocol.TCP,
                event_type=EventType.port_scan,
                event_message=f"Сканирование периметра: источник 198.51.100.77 проверяет административный TCP-порт на адресе {destination}.",
                severity=Severity.high,
                created_by="operator",
            )

        for index, port in enumerate(["22", "23", "80"]):
            add_event(
                minutes=42 + index,
                node_name="CORE-RTR-02",
                rule_name="Сканирование портов пограничного маршрутизатора",
                source_ip="185.66.77.88",
                destination_ip="10.10.0.2",
                protocol=Protocol.TCP,
                event_type=EventType.port_scan,
                event_message=f"CORE-RTR-02 получил подозрительный SYN-запрос к порту {port} от 185.66.77.88.",
                severity=Severity.high,
                created_by="operator",
            )

        traffic_spike_cases = [
            ("EPC-GW-NSK-01", "10.10.200.14", "Рост GTP-C сигнализации на EPC-шлюзе выше базового профиля."),
            ("EDGE-FW-01", "185.203.116.9", "Резкий рост HTTPS-сессий к административной зоне межсетевого экрана."),
            ("CORE-RTR-02", "10.10.70.11", "Аномальный всплеск TCP-потоков на магистральном маршрутизаторе."),
            ("EPC-GW-NSK-01", "198.51.100.200", "Нестандартный всплеск входящих соединений к шлюзу пакетного ядра."),
            ("EDGE-FW-01", "203.0.113.120", "Кратковременная перегрузка таблицы состояний межсетевого экрана внешним источником."),
        ]
        for index, (node_name, source_ip, message) in enumerate(traffic_spike_cases):
            add_event(
                minutes=55 + index,
                node_name=node_name,
                rule_name="Всплеск SIP-трафика",
                source_ip=source_ip,
                destination_ip=nodes[node_name].ip_address,
                protocol=Protocol.UDP if index == 0 else Protocol.TCP,
                event_type=EventType.traffic_spike,
                event_message=message,
                severity=Severity.high if index < 3 else Severity.critical,
                created_by="soc_lead",
            )

        suspicious_access_cases = [
            ("NMS-SRV-01", "185.19.204.55", "Попытка доступа к NMS API с внешнего IP, отсутствующего в доверенных подсетях."),
            ("EDGE-FW-01", "203.0.113.120", "Внешний источник пробует получить доступ к консоли управления межсетевым экраном."),
            ("EPC-GW-NSK-01", "198.51.100.200", "Подозрительный внешний IP обращается к сервисному интерфейсу EPC-шлюзе."),
            ("NMS-SRV-01", "185.71.66.14", "Повторный запрос к административной панели NMS с адреса из внешнего диапазона."),
            ("IMS-SBC-01", "203.0.113.144", "Сигнализационный SIP-запрос от источника из списка подозрительных адресов."),
            ("DNS-REC-01", "198.51.100.88", "DNS-рекурсор получил запросы от внешнего источника с IOC-признаками."),
        ]
        for index, (node_name, source_ip, message) in enumerate(suspicious_access_cases):
            add_event(
                minutes=70 + index,
                node_name=node_name,
                rule_name="Внешний IOC-доступ к критическому узлу" if index >= 4 else "Доступ к NMS из недоверенной сети",
                source_ip=source_ip,
                destination_ip=nodes[node_name].ip_address,
                protocol=Protocol.HTTPS if index < 4 else Protocol.UDP,
                event_type=EventType.unauthorized_access if index < 4 else EventType.suspicious_ip,
                event_message=message,
                severity=Severity.high,
                created_by="engineer",
            )

        additional_operational_cases = [
            ("DNS-REC-01", "10.10.55.24", "DNS-запросы к IOC-индикаторам", Protocol.UDP, EventType.suspicious_ip, "Внутренний узел повторно запрашивает домены из списка IOC.", Severity.medium),
            ("LTE-eNB-2217", "10.10.22.17", "Потеря связи с базовой станцией", Protocol.ICMP, EventType.connection_drop, "LTE eNB потеряла транспортную связность после перепада питания на площадке.", Severity.medium),
            ("BSC-CTRL-07", "172.16.7.250", "Несанкционированное изменение конфигурации BSC", Protocol.SSH, EventType.config_change, "Планировщик конфигураций BSC получил изменение без заявки на работы.", Severity.critical),
            ("IMS-SBC-01", "185.203.116.9", "Всплеск SIP-трафика", Protocol.UDP, EventType.traffic_spike, "Повторный пик SIP REGISTER на SBC после короткого затишья.", Severity.critical),
            ("BRAS-MSK-01", "192.168.10.201", "Массовые отказы PPPoE-сессий", Protocol.TCP, EventType.auth_failed, "Абонентский концентратор генерирует серию PPPoE ошибок после смены профиля.", Severity.medium),
            ("AUTH-RADIUS-01", "185.71.66.14", "Серия ошибок RADIUS-аутентификации", Protocol.UDP, EventType.auth_failed, "Новая пачка Access-Request с некорректными учетными данными из внешнего диапазона.", Severity.high),
        ]
        for index, (node_name, source_ip, rule_name, protocol, event_type, message, severity) in enumerate(additional_operational_cases):
            add_event(
                minutes=90 + index,
                node_name=node_name,
                rule_name=rule_name,
                source_ip=source_ip,
                destination_ip=nodes[node_name].ip_address,
                protocol=protocol,
                event_type=event_type,
                event_message=message,
                severity=severity,
                created_by="soc_lead",
            )

        for batch in range(4):
            source_ip = f"185.90.{batch + 10}.44"
            for index in range(5):
                add_event(
                    minutes=110 + batch * 8 + index,
                    node_name="AUTH-RADIUS-01",
                    rule_name="Серия ошибок RADIUS-аутентификации",
                    source_ip=source_ip,
                    destination_ip="10.10.5.5",
                    protocol=Protocol.UDP,
                    event_type=EventType.auth_failed,
                    event_message=f"Массовая ошибка RADIUS №{index + 1}: источник {source_ip} генерирует Access-Reject для абонентских PPPoE-сессий.",
                    severity=Severity.high if index >= 3 else Severity.medium,
                    created_by="engineer",
                )

        for batch in range(5):
            source_ip = f"198.51.100.{210 + batch}"
            target_node = "EDGE-FW-01" if batch % 2 == 0 else "AGG-RTR-NSK-03"
            for index in range(3):
                add_event(
                    minutes=150 + batch * 6 + index,
                    node_name=target_node,
                    rule_name="Сканирование портов пограничного маршрутизатора",
                    source_ip=source_ip,
                    destination_ip=f"172.16.{batch}.{20 + index}",
                    protocol=Protocol.TCP,
                    event_type=EventType.port_scan,
                    event_message=f"Сканирование адресного пространства: {source_ip} проверяет служебные порты на назначение №{index + 1}.",
                    severity=Severity.high,
                    created_by="operator",
                )

        traffic_nodes = ["CGNAT-GW-01", "EPC-GW-NSK-01", "EDGE-FW-01", "CORE-RTR-02", "AGG-RTR-NSK-03"]
        for index in range(14):
            node_name = traffic_nodes[index % len(traffic_nodes)]
            add_event(
                minutes=190 + index,
                node_name=node_name,
                rule_name="Истощение таблицы соединений CGNAT" if node_name == "CGNAT-GW-01" else "Всплеск SIP-трафика",
                source_ip=f"203.0.113.{130 + index}",
                destination_ip=nodes[node_name].ip_address,
                protocol=Protocol.TCP if index % 2 else Protocol.UDP,
                event_type=EventType.traffic_spike,
                event_message=f"Аномальный рост трафика на {node_name}: превышен базовый профиль соединений в абонентском сегменте.",
                severity=Severity.high if index % 3 else Severity.critical,
                created_by="soc_lead",
            )

        access_nodes = ["NMS-SRV-01", "EDGE-FW-01", "EPC-GW-NSK-01", "IMS-SBC-01", "DHCP-SRV-01", "DNS-REC-01"]
        for index in range(18):
            node_name = access_nodes[index % len(access_nodes)]
            event_type = EventType.unauthorized_access if index % 2 == 0 else EventType.suspicious_ip
            rule_name = "Доступ к NMS из недоверенной сети" if event_type == EventType.unauthorized_access else "Внешний IOC-доступ к критическому узлу"
            if node_name == "DHCP-SRV-01":
                rule_name = "Подозрительные DHCP-запросы аренды"
                event_type = EventType.suspicious_ip
            add_event(
                minutes=220 + index,
                node_name=node_name,
                rule_name=rule_name,
                source_ip=f"185.177.{20 + index}.9",
                destination_ip=nodes[node_name].ip_address,
                protocol=Protocol.HTTPS if event_type == EventType.unauthorized_access else Protocol.UDP,
                event_type=event_type,
                event_message=f"Подозрительный внешний доступ к {node_name}: источник не входит в доверенные подсети управления.",
                severity=Severity.high,
                created_by="engineer" if index % 2 else "soc_lead",
            )

        radio_cases = [
            ("LTE-eNB-2217", "10.10.22.17"),
            ("LTE-eNB-2388", "10.10.23.88"),
        ]
        for index in range(12):
            node_name, source_ip = radio_cases[index % 2]
            add_event(
                minutes=250 + index,
                node_name=node_name,
                rule_name="Потеря связи с базовой станцией",
                source_ip=source_ip,
                destination_ip="10.10.0.2",
                protocol=Protocol.ICMP,
                event_type=EventType.connection_drop,
                event_message=f"Потеря связи с базовой станцией {node_name}: транспортный канал нестабилен более 5 минут.",
                severity=Severity.medium if index % 3 else Severity.high,
                created_by="noc_shift",
            )

        events = [_ensure_event(db, event) for event in events_data]
        db.commit()
        run_full_analysis(db)
        db.commit()
        print(f"Сетевых событий доступно: {db.query(NetworkEvent).count()}")
        print(f"Корреляционных оповещений доступно: {db.query(CorrelationAlert).count()}")

        incidents_data = [
            {
                "title": "Массовые ошибки RADIUS-аутентификации абонентов",
                "description": "На узле AUTH-RADIUS-01 зафиксировано большое количество неуспешных попыток аутентификации абонентских сессий с одного IP-адреса. Событие может указывать на подбор учетных данных или сбой в работе клиентского оборудования.",
                "status": IncidentStatus.new,
                "severity": Severity.high,
                "event_id": events[0].id,
                "assigned_to": users["engineer"].id,
                "created_by": users["operator"].id,
            },
            {
                "title": "Подозрение на SIP-флуд на IMS-SBC-01",
                "description": "На пограничном SBC обнаружен резкий рост UDP-пакетов, направленных на SIP-порт. Нагрузка превышает обычный уровень и может указывать на попытку отказа в обслуживании VoIP-сервисов.",
                "status": IncidentStatus.in_progress,
                "severity": Severity.critical,
                "event_id": events[2].id,
                "assigned_to": users["voip_ops"].id,
                "created_by": users["engineer"].id,
            },
            {
                "title": "Сканирование портов пограничного маршрутизатора CORE-RTR-02",
                "description": "С внешнего IP-адреса зафиксированы последовательные подключения к нескольким TCP-портам пограничного маршрутизатора. Активность соответствует признакам разведки сетевой инфраструктуры.",
                "status": IncidentStatus.new,
                "severity": Severity.high,
                "event_id": events[1].id,
                "assigned_to": users["soc_lead"].id,
                "created_by": users["operator"].id,
            },
            {
                "title": "Попытка несанкционированного изменения конфигурации BSC-CTRL-07",
                "description": "В журнале управления оборудованием обнаружена попытка изменения конфигурации контроллера базовых станций без подтвержденной административной сессии.",
                "status": IncidentStatus.new,
                "severity": Severity.critical,
                "event_id": events[3].id,
                "assigned_to": users["admin"].id,
                "created_by": users["soc_lead"].id,
            },
            {
                "title": "Недоступность базовой станции LTE-eNB-2217",
                "description": "Система мониторинга зафиксировала потерю связи с базовой станцией более чем на 5 минут. Требуется проверка канала связи и состояния оборудования.",
                "status": IncidentStatus.in_progress,
                "severity": Severity.medium,
                "event_id": events[4].id,
                "assigned_to": users["noc_shift"].id,
                "created_by": users["operator"].id,
            },
            {
                "title": "Подключение к NMS-SRV-01 с недоверенного IP",
                "description": "На сервер управления сетью выполнена попытка входа с IP-адреса, который не входит в список доверенных административных подсетей.",
                "status": IncidentStatus.new,
                "severity": Severity.high,
                "event_id": events[5].id,
                "assigned_to": users["engineer"].id,
                "created_by": users["soc_lead"].id,
            },
            {
                "title": "Аномальный DNS-трафик на DNS-REC-01",
                "description": "DNS-рекурсор обработал серию запросов к доменам, связанным с подозрительными индикаторами компрометации. Требуется проверка источника запросов.",
                "status": IncidentStatus.in_progress,
                "severity": Severity.high,
                "event_id": events[7].id,
                "assigned_to": users["soc_lead"].id,
                "created_by": users["engineer"].id,
            },
            {
                "title": "Резкий рост трафика на BRAS-MSK-01",
                "description": "На BRAS-узле зафиксирован рост числа PPPoE-сессий и объема входящего трафика выше среднего значения. Возможна аномальная активность или массовое переподключение абонентов.",
                "status": IncidentStatus.new,
                "severity": Severity.medium,
                "event_id": events[6].id,
                "assigned_to": users["noc_shift"].id,
                "created_by": users["operator"].id,
            },
            {
                "title": "Ошибки управления на EDGE-FW-01",
                "description": "На межсетевом экране обнаружены повторяющиеся неуспешные попытки входа в административный интерфейс. Источник запросов не относится к доверенной сети управления.",
                "status": IncidentStatus.resolved,
                "severity": Severity.high,
                "event_id": events[8].id,
                "assigned_to": users["admin"].id,
                "created_by": users["engineer"].id,
            },
            {
                "title": "Подозрительная активность на EPC-GW-NSK-01",
                "description": "На шлюзе пакетного ядра обнаружена серия соединений с нестандартным профилем трафика. Активность требует проверки на наличие компрометации сетевого сегмента.",
                "status": IncidentStatus.new,
                "severity": Severity.critical,
                "event_id": events[9].id,
                "assigned_to": users["engineer"].id,
                "created_by": users["soc_lead"].id,
            },
            {
                "title": "Серия PPPoE-отказов на BRAS-MSK-01",
                "description": "С одного внешнего источника зафиксирована серия отказов PPPoE-сессий. Возможна попытка подбора учетных данных или ошибочная массовая конфигурация клиентского оборудования.",
                "status": IncidentStatus.in_progress,
                "severity": Severity.high,
                "event_id": events[21].id,
                "assigned_to": users["noc_shift"].id,
                "created_by": users["engineer"].id,
            },
            {
                "title": "Разведка адресов периметра EDGE-FW-01",
                "description": "В течение короткого окна источник 198.51.100.77 обращался к нескольким адресам периметра, что соответствует признакам сканирования сетевой инфраструктуры.",
                "status": IncidentStatus.new,
                "severity": Severity.critical,
                "event_id": events[26].id,
                "assigned_to": users["soc_lead"].id,
                "created_by": users["operator"].id,
            },
            {
                "title": "Внешний доступ к сервисному интерфейсу EPC-шлюза",
                "description": "Критический шлюз пакетного ядра получил обращение с внешнего IP-адреса с признаками недоверенного доступа.",
                "status": IncidentStatus.new,
                "severity": Severity.critical,
                "event_id": events[39].id,
                "assigned_to": users["engineer"].id,
                "created_by": users["soc_lead"].id,
            },
            {
                "title": "Повторный пик SIP-регистраций на IMS-SBC-01",
                "description": "SBC получил повторный всплеск SIP REGISTER, который может повлиять на доступность VoIP-сервисов для абонентов.",
                "status": IncidentStatus.in_progress,
                "severity": Severity.critical,
                "event_id": events[47].id,
                "assigned_to": users["voip_ops"].id,
                "created_by": users["engineer"].id,
            },
            {
                "title": "Изменение конфигурации BSC без заявки",
                "description": "На контроллере базовых станций обнаружено изменение конфигурации без подтвержденной заявки на плановые работы.",
                "status": IncidentStatus.new,
                "severity": Severity.critical,
                "event_id": events[46].id,
                "assigned_to": users["admin"].id,
                "created_by": users["soc_lead"].id,
            },
        ]
        extra_incident_events = [
            event for event in events
            if (event.risk_score or 0) >= 70
        ][:25]
        for index, event in enumerate(extra_incident_events, start=1):
            node_name = event.node.name if event.node else f"узел #{event.node_id}"
            source_ip = event.source_ip
            incident_status = [
                IncidentStatus.new,
                IncidentStatus.in_progress,
                IncidentStatus.resolved,
            ][index % 3]
            assignee = [
                users["engineer"].id,
                users["soc_lead"].id,
                users["voip_ops"].id,
                users["noc_shift"].id,
            ][index % 4]
            risk_severity = Severity[event.risk_level] if event.risk_level in Severity.__members__ else event.severity
            incidents_data.append(
                {
                    "title": f"Корреляционная проверка №{index}: подозрительная активность на {node_name}",
                    "description": (
                        f"Событие от источника {source_ip} получило балл риска {event.risk_score}. "
                        f"Причина: {event.detection_reason}"
                    ),
                    "status": incident_status,
                    "severity": risk_severity,
                    "event_id": event.id,
                    "assigned_to": assignee,
                    "created_by": users["soc_lead"].id if index % 2 else users["engineer"].id,
                }
            )

        incidents = [_ensure_incident(db, incident) for incident in incidents_data]
        db.commit()
        print(f"Инцидентов доступно: {db.query(Incident).count()}")

        access_items = []
        for incident in incidents:
            access_items.append(
                {
                    "incident_id": incident.id,
                    "user_id": incident.created_by,
                    "access_level": AccessLevel.manage,
                    "granted_by": incident.created_by,
                }
            )
            if incident.assigned_to:
                access_items.append(
                    {
                        "incident_id": incident.id,
                        "user_id": incident.assigned_to,
                        "access_level": AccessLevel.write,
                        "granted_by": incident.created_by,
                    }
                )

        access_items.extend(
            [
                {
                    "incident_id": incidents[1].id,
                    "user_id": users["admin"].id,
                    "access_level": AccessLevel.manage,
                    "granted_by": users["engineer"].id,
                },
                {
                    "incident_id": incidents[2].id,
                    "user_id": users["operator"].id,
                    "access_level": AccessLevel.read,
                    "granted_by": users["soc_lead"].id,
                },
                {
                    "incident_id": incidents[6].id,
                    "user_id": users["voip_ops"].id,
                    "access_level": AccessLevel.read,
                    "granted_by": users["engineer"].id,
                },
            ]
        )

        for access_data in access_items:
            _ensure_incident_access(db, access_data)

        db.commit()
        print(f"Выданных доступов к инцидентам: {db.query(IncidentAccess).count()}")
        print("Демонстрационные данные сети связи готовы.")

    except Exception as e:
        print(f"Ошибка заполнения базы данных: {e}")
        db.rollback()
    finally:
        db.close()
