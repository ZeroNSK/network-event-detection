import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { eventTypeLabel, incidentStatusLabel, riskLevelLabel } from '../utils/labels'

const AnalysisAlertDetails = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const [alert, setAlert] = useState(null)
  const [statusValue, setStatusValue] = useState('new')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchAlert()
  }, [id])

  const fetchAlert = async () => {
    try {
      const response = await api.get(`/analysis/alerts/${id}`)
      setAlert(response.data)
      setStatusValue(response.data.status)
    } catch (error) {
      const status = error.response?.status || 500
      const message = error.response?.data?.detail || 'Ошибка загрузки оповещения'
      navigate(`/error?status=${status}&message=${encodeURIComponent(message)}`)
    } finally {
      setLoading(false)
    }
  }

  const updateStatus = async () => {
    try {
      const response = await api.put(`/analysis/alerts/${id}`, { status: statusValue })
      setAlert({ ...alert, status: response.data.status })
      toast.success('Статус оповещения обновлен')
    } catch (error) {
      toast.error('Ошибка обновления оповещения')
    }
  }

  const deleteAlert = async () => {
    if (!window.confirm('Удалить корреляционное оповещение?')) return
    try {
      await api.delete(`/analysis/alerts/${id}`)
      toast.success('Корреляционное оповещение удалено')
      navigate('/analysis/alerts')
    } catch (error) {
      toast.error('Ошибка удаления оповещения')
    }
  }

  const createIncident = async () => {
    try {
      const response = await api.post(`/analysis/alerts/${id}/create-incident`)
      toast.success(`Инцидент #${response.data.id} создан или уже существует`)
      navigate(`/incidents/${response.data.id}`)
    } catch (error) {
      toast.error('Ошибка создания инцидента')
    }
  }

  if (loading) {
    return <div className="loading">Загрузка...</div>
  }

  if (!alert) {
    return null
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Корреляционное оповещение #{alert.id}</h1>
        <div className="actions">
          <button className="btn btn-primary" onClick={createIncident}>
            Создать инцидент
          </button>
          <button className="btn btn-secondary" onClick={() => navigate('/analysis/alerts')}>
            Назад
          </button>
          {user.role === 'admin' && (
            <button className="btn btn-danger" onClick={deleteAlert}>
              Удалить
            </button>
          )}
        </div>
      </div>

      <div className="details-card">
        <div className="detail-row">
          <span className="detail-label">Название:</span>
          <span className="detail-value">{alert.title}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Описание:</span>
          <span className="detail-value">{alert.description}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Балл риска:</span>
          <span className="detail-value">{alert.risk_score}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Уровень риска:</span>
          <span className="detail-value"><span className={`badge badge-${alert.risk_level}`}>{riskLevelLabel(alert.risk_level)}</span></span>
        </div>
        <div className="detail-row">
          <span className="detail-label">IP источника:</span>
          <span className="detail-value">{alert.source_ip || 'Нет данных'}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Узел:</span>
          <span className="detail-value">{alert.node ? `${alert.node.name} (${alert.node.ip_address})` : 'Нет данных'}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Окно событий:</span>
          <span className="detail-value">
            {new Date(alert.first_seen).toLocaleString('ru-RU')} - {new Date(alert.last_seen).toLocaleString('ru-RU')}
          </span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Статус:</span>
          <span className="detail-value inline-controls">
            <select value={statusValue} onChange={(e) => setStatusValue(e.target.value)}>
              <option value="new">Новый</option>
              <option value="in_progress">В работе</option>
              <option value="resolved">Решен</option>
              <option value="false_positive">Ложное срабатывание</option>
            </select>
            <button className="btn btn-sm btn-primary" onClick={updateStatus}>
              Сохранить
            </button>
          </span>
        </div>
      </div>

      <div className="details-card mt-20">
        <h2>Связанные события</h2>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Источник</th>
              <th>Назначение</th>
              <th>Тип</th>
              <th>Балл риска</th>
              <th>Создано</th>
            </tr>
          </thead>
          <tbody>
            {alert.events?.map(event => (
              <tr key={event.id} className="clickable-row" onClick={() => navigate(`/events/${event.id}`)}>
                <td>{event.id}</td>
                <td>{event.source_ip}</td>
                <td>{event.destination_ip}</td>
                <td>{eventTypeLabel(event.event_type)}</td>
                <td><span className={`badge badge-${event.risk_level}`}>{event.risk_score}</span></td>
                <td>{new Date(event.created_at).toLocaleString('ru-RU')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="details-card mt-20">
        <h2>Инциденты из оповещения</h2>
        {alert.incidents?.length ? (
          <table className="compact-table">
            <tbody>
              {alert.incidents.map(incident => (
                <tr key={incident.id} className="clickable-row" onClick={() => navigate(`/incidents/${incident.id}`)}>
                  <td>{incident.id}</td>
                  <td>{incident.title}</td>
                  <td><span className={`badge badge-${incident.status}`}>{incidentStatusLabel(incident.status)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">Инцидент из этого оповещения еще не создан.</p>
        )}
      </div>
    </div>
  )
}

export default AnalysisAlertDetails
