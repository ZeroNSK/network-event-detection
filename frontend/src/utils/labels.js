const fallback = (value) => value || '-'

export const severityLabels = {
  low: 'Низкий',
  medium: 'Средний',
  high: 'Высокий',
  critical: 'Критический'
}

export const riskLevelLabels = severityLabels

export const eventTypeLabels = {
  auth_failed: 'Ошибка аутентификации',
  port_scan: 'Сканирование портов',
  traffic_spike: 'Всплеск трафика',
  unauthorized_access: 'Несанкционированный доступ',
  suspicious_ip: 'Подозрительный IP',
  config_change: 'Изменение конфигурации',
  connection_drop: 'Потеря соединения',
  other: 'Другое событие'
}

export const nodeTypeLabels = {
  router: 'Маршрутизатор',
  switch: 'Коммутатор',
  base_station: 'Базовая станция',
  server: 'Сервер',
  firewall: 'Межсетевой экран',
  gateway: 'Шлюз'
}

export const nodeStatusLabels = {
  active: 'Активен',
  warning: 'Требует внимания',
  offline: 'Недоступен'
}

export const alertStatusLabels = {
  new: 'Новый',
  in_progress: 'В работе',
  resolved: 'Решен',
  false_positive: 'Ложное срабатывание'
}

export const incidentStatusLabels = {
  new: 'Новый',
  in_progress: 'В работе',
  resolved: 'Решен',
  rejected: 'Отклонен'
}

export const roleLabels = {
  admin: 'Администратор',
  security_engineer: 'Инженер ИБ',
  operator: 'Оператор'
}

export const ruleCategoryLabels = {
  authentication: 'Аутентификация',
  network_scan: 'Сканирование сети',
  traffic_anomaly: 'Аномалии трафика',
  unauthorized_access: 'Несанкционированный доступ',
  availability: 'Доступность',
  configuration: 'Конфигурация'
}

export const auditActionLabels = {
  create: 'Создание',
  update: 'Изменение',
  delete: 'Удаление',
  login: 'Вход',
  failed_login: 'Неуспешный вход',
  run_analysis: 'Запуск анализа',
  create_alert: 'Создание оповещения',
  update_alert: 'Изменение оповещения',
  import_dataset: 'Импорт dataset',
  export_dataset: 'Экспорт dataset',
  create_incident_from_alert: 'Инцидент из оповещения'
}

export const entityTypeLabels = {
  users: 'Пользователи',
  network_nodes: 'Сетевые узлы',
  network_events: 'Сетевые события',
  detection_rules: 'Правила обнаружения',
  incidents: 'Инциденты',
  audit_logs: 'Журнал действий',
  correlation_alerts: 'Корреляционные оповещения'
}

export const protocolLabels = {
  TCP: 'TCP',
  UDP: 'UDP',
  ICMP: 'ICMP',
  HTTP: 'HTTP',
  HTTPS: 'HTTPS',
  SSH: 'SSH',
  OTHER: 'Другой'
}

export const ruleNameLabels = {
  'RADIUS Authentication Failure Burst': 'Серия ошибок RADIUS-аутентификации',
  'Edge Router Port Scan Sweep': 'Сканирование портов пограничного маршрутизатора',
  'SIP Flood Traffic Spike': 'Всплеск SIP-трафика',
  'Unauthorized BSC Configuration Change': 'Несанкционированное изменение конфигурации BSC',
  'Base Station Link Loss': 'Потеря связи с базовой станцией',
  'Untrusted NMS Access Attempt': 'Попытка доступа к NMS из недоверенной сети',
  'DNS IOC Query Detection': 'DNS-запросы к IOC-индикаторам',
  'EPC Gateway Abnormal Flow Profile': 'Аномальный профиль трафика EPC-шлюза',
  'PPPoE Session Failure Storm': 'Массовые отказы PPPoE-сессий',
  'Critical Node External IOC Access': 'Внешний IOC-доступ к критическому узлу',
  'CGNAT Flow Exhaustion': 'Истощение таблицы соединений CGNAT',
  'DHCP Lease Abuse Pattern': 'Подозрительные DHCP-запросы аренды',
  'Серия ошибок RADIUS-аутентификации': 'Серия ошибок RADIUS-аутентификации',
  'Сканирование портов пограничного маршрутизатора': 'Сканирование портов пограничного маршрутизатора',
  'Всплеск SIP-трафика': 'Всплеск SIP-трафика',
  'Несанкционированное изменение конфигурации BSC': 'Несанкционированное изменение конфигурации BSC',
  'Потеря связи с базовой станцией': 'Потеря связи с базовой станцией',
  'Доступ к NMS из недоверенной сети': 'Попытка доступа к NMS из недоверенной сети',
  'DNS-запросы к IOC-индикаторам': 'DNS-запросы к IOC-индикаторам',
  'Аномальный профиль трафика EPC-шлюза': 'Аномальный профиль трафика EPC-шлюза',
  'Массовые отказы PPPoE-сессий': 'Массовые отказы PPPoE-сессий',
  'Внешний IOC-доступ к критическому узлу': 'Внешний IOC-доступ к критическому узлу',
  'Истощение таблицы соединений CGNAT': 'Истощение таблицы соединений CGNAT',
  'Подозрительные DHCP-запросы аренды': 'Подозрительные DHCP-запросы аренды'
}

export const label = (dictionary, value) => dictionary[value] || fallback(value)
export const severityLabel = (value) => label(severityLabels, value)
export const riskLevelLabel = (value) => label(riskLevelLabels, value)
export const eventTypeLabel = (value) => label(eventTypeLabels, value)
export const nodeTypeLabel = (value) => label(nodeTypeLabels, value)
export const nodeStatusLabel = (value) => label(nodeStatusLabels, value)
export const alertStatusLabel = (value) => label(alertStatusLabels, value)
export const incidentStatusLabel = (value) => label(incidentStatusLabels, value)
export const roleLabel = (value) => label(roleLabels, value)
export const ruleCategoryLabel = (value) => label(ruleCategoryLabels, value)
export const auditActionLabel = (value) => label(auditActionLabels, value)
export const entityTypeLabel = (value) => label(entityTypeLabels, value)
export const protocolLabel = (value) => label(protocolLabels, value)
export const ruleNameLabel = (value) => label(ruleNameLabels, value)
