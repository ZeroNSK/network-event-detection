import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import {
  alertStatusLabel,
  eventTypeLabel,
  incidentStatusLabel,
  protocolLabel,
  riskLevelLabel,
  ruleNameLabel,
  severityLabel
} from '../utils/labels'

const EventDetails = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const [event, setEvent] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchEvent()
  }, [id])

  const fetchEvent = async () => {
    try {
      const response = await api.get(`/events/${id}`)
      setEvent(response.data)
    } catch (error) {
      const status = error.response?.status || 500
      const message = error.response?.data?.detail || 'Ошибка загрузки события'
      navigate(`/error?status=${status}&message=${encodeURIComponent(message)}`)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="loading">Загрузка...</div>
  }

  if (!event) {
    return null
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Детали события #{event.id}</h1>
        <button 
          className="btn btn-secondary"
          onClick={() => navigate('/events')}
        >
          Назад к списку
        </button>
      </div>

      <div className="details-card">
        <div className="detail-row">
          <span className="detail-label">ID:</span>
          <span className="detail-value">{event.id}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Статус:</span>
          <span className="detail-value">
            <span className={`badge ${event.is_suspicious ? 'badge-danger' : 'badge-success'}`}>
              {event.is_suspicious ? 'Подозрительное' : 'Обычное'}
            </span>
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Балл риска:</span>
          <span className="detail-value">{event.risk_score}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Уровень риска:</span>
          <span className="detail-value">
            <span className={`badge badge-${event.risk_level}`}>
              {riskLevelLabel(event.risk_level)}
            </span>
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Причина обнаружения:</span>
          <span className="detail-value">{event.detection_reason || 'Анализ еще не выполнен'}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Время анализа:</span>
          <span className="detail-value">
            {event.analyzed_at ? new Date(event.analyzed_at).toLocaleString('ru-RU') : 'Не выполнен'}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Узел:</span>
          <span className="detail-value">
            {event.node ? `${event.node.name} (${event.node.ip_address})` : 'Нет данных'}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Правило обнаружения:</span>
          <span className="detail-value">
            {event.rule ? ruleNameLabel(event.rule.name) : 'Без правила'}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">IP источника:</span>
          <span className="detail-value">{event.source_ip}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">IP назначения:</span>
          <span className="detail-value">{event.destination_ip}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Протокол:</span>
          <span className="detail-value">{protocolLabel(event.protocol)}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Тип события:</span>
          <span className="detail-value">{eventTypeLabel(event.event_type)}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Уровень критичности:</span>
          <span className="detail-value">
            <span className={`badge badge-${event.severity}`}>
              {severityLabel(event.severity)}
            </span>
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Сообщение:</span>
          <span className="detail-value">{event.event_message}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Создано:</span>
          <span className="detail-value">
            {new Date(event.created_at).toLocaleString('ru-RU')}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Создал:</span>
          <span className="detail-value">Пользователь #{event.created_by}</span>
        </div>
      </div>

      <div className="details-card mt-20">
        <h2>Расчет риска</h2>
        <div className="risk-meter">
          <div className={`risk-meter-fill bar-${event.risk_level}`} style={{ width: `${event.risk_score}%` }} />
        </div>
        <p className="muted">
          Итоговый балл формируется из критичности, типа события, протокола, источника, типа узла и активных правил обнаружения.
        </p>
      </div>

      <div className="details-card mt-20">
        <h2>Связанные корреляционные оповещения</h2>
        {event.correlation_alerts?.length ? (
          <table className="compact-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Название</th>
                <th>Балл риска</th>
                <th>Статус</th>
              </tr>
            </thead>
            <tbody>
              {event.correlation_alerts.map(alert => (
                <tr key={alert.id} onClick={() => navigate(`/analysis/alerts/${alert.id}`)} className="clickable-row">
                  <td>{alert.id}</td>
                  <td>{alert.title}</td>
                  <td>{alert.risk_score}</td>
                  <td><span className={`badge badge-${alert.status}`}>{alertStatusLabel(alert.status)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">Связанных корреляционных оповещений нет.</p>
        )}
      </div>

      <div className="details-card mt-20">
        <h2>Связанные инциденты</h2>
        {event.incidents?.length ? (
          <table className="compact-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Название</th>
                <th>Статус</th>
                <th>Уровень</th>
              </tr>
            </thead>
            <tbody>
              {event.incidents.map(incident => (
                <tr key={incident.id} onClick={() => navigate(`/incidents/${incident.id}`)} className="clickable-row">
                  <td>{incident.id}</td>
                  <td>{incident.title}</td>
                  <td><span className={`badge badge-${incident.status}`}>{incidentStatusLabel(incident.status)}</span></td>
                  <td><span className={`badge badge-${incident.severity}`}>{severityLabel(incident.severity)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">Связанных инцидентов нет.</p>
        )}
      </div>
    </div>
  )
}

export default EventDetails
