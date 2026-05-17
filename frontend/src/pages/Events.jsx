import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Events = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({
    severity: '',
    is_suspicious: '',
    event_type: '',
    risk_level: '',
    min_risk_score: '',
    max_risk_score: ''
  })
  const limit = 10

  useEffect(() => {
    fetchEvents()
  }, [page, filters.severity, filters.is_suspicious, filters.event_type, filters.risk_level, filters.min_risk_score, filters.max_risk_score])

  const fetchEvents = async () => {
    setLoading(true)
    try {
      const params = { page, limit }
      
      // Only add filters if they have values
      if (filters.severity) params.severity = filters.severity
      if (filters.is_suspicious !== '') params.is_suspicious = filters.is_suspicious
      if (filters.event_type) params.event_type = filters.event_type
      if (filters.risk_level) params.risk_level = filters.risk_level
      if (filters.min_risk_score) params.min_risk_score = filters.min_risk_score
      if (filters.max_risk_score) params.max_risk_score = filters.max_risk_score
      
      const response = await api.get('/events', { params })
      setEvents(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      console.error('Error fetching events:', error)
      toast.error('Ошибка загрузки событий')
    } finally {
      setLoading(false)
    }
  }

  const handleFilterChange = (e) => {
    setFilters({
      ...filters,
      [e.target.name]: e.target.value
    })
    setPage(1)
  }

  const handleDelete = async (id) => {
    if (!window.confirm('Вы уверены, что хотите удалить это событие?')) {
      return
    }

    try {
      await api.delete(`/events/${id}`)
      toast.success('Событие удалено')
      fetchEvents()
    } catch (error) {
      toast.error('Ошибка удаления события')
    }
  }

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Сетевые события</h1>
        <button 
          className="btn btn-primary"
          onClick={() => navigate('/events/new')}
        >
          Создать событие
        </button>
      </div>

      <div className="filters">
        <select name="severity" value={filters.severity} onChange={handleFilterChange}>
          <option value="">Все уровни</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>

        <select name="is_suspicious" value={filters.is_suspicious} onChange={handleFilterChange}>
          <option value="">Все события</option>
          <option value="true">Подозрительные</option>
          <option value="false">Обычные</option>
        </select>

        <select name="event_type" value={filters.event_type} onChange={handleFilterChange}>
          <option value="">Все типы</option>
          <option value="auth_failed">Auth Failed</option>
          <option value="port_scan">Port Scan</option>
          <option value="traffic_spike">Traffic Spike</option>
          <option value="unauthorized_access">Unauthorized Access</option>
          <option value="config_change">Config Change</option>
          <option value="connection_drop">Connection Drop</option>
          <option value="suspicious_ip">Suspicious IP</option>
          <option value="other">Other</option>
        </select>

        <select name="risk_level" value={filters.risk_level} onChange={handleFilterChange}>
          <option value="">Все risk_level</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>

        <input
          type="number"
          name="min_risk_score"
          value={filters.min_risk_score}
          onChange={handleFilterChange}
          min="0"
          max="100"
          placeholder="Мин. риск"
        />

        <input
          type="number"
          name="max_risk_score"
          value={filters.max_risk_score}
          onChange={handleFilterChange}
          min="0"
          max="100"
          placeholder="Макс. риск"
        />
      </div>

      {loading ? (
        <div className="loading">Загрузка...</div>
      ) : (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Источник</th>
                <th>Назначение</th>
                <th>Протокол</th>
                <th>Тип</th>
                <th>Уровень</th>
                <th>Risk</th>
                <th>Risk level</th>
                <th>Статус</th>
                <th>Причина</th>
                <th>Анализ</th>
                <th>Создано</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {events.map(event => (
                <tr 
                  key={event.id}
                  className={event.is_suspicious ? 'suspicious-row' : ''}
                >
                  <td>{event.id}</td>
                  <td>{event.source_ip}</td>
                  <td>{event.destination_ip}</td>
                  <td>{event.protocol}</td>
                  <td>{event.event_type}</td>
                  <td>
                    <span className={`badge badge-${event.severity}`}>
                      {event.severity}
                    </span>
                  </td>
                  <td>{event.risk_score}</td>
                  <td>
                    <span className={`badge badge-${event.risk_level}`}>
                      {event.risk_level}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${event.is_suspicious ? 'badge-danger' : 'badge-success'}`}>
                      {event.is_suspicious ? 'Подозрительное' : 'Обычное'}
                    </span>
                  </td>
                  <td className="text-cell">{event.detection_reason}</td>
                  <td>{event.analyzed_at ? new Date(event.analyzed_at).toLocaleString('ru-RU') : 'Не выполнен'}</td>
                  <td>{new Date(event.created_at).toLocaleString('ru-RU')}</td>
                  <td>
                    <button
                      className="btn btn-sm btn-info"
                      onClick={() => navigate(`/events/${event.id}`)}
                    >
                      Просмотр
                    </button>
                    {['admin', 'security_engineer'].includes(user.role) && (
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => navigate(`/events/${event.id}/edit`)}
                      >
                        Редактировать
                      </button>
                    )}
                    {user.role === 'admin' && (
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(event.id)}
                      >
                        Удалить
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="pagination">
            <button
              className="btn btn-secondary"
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              Предыдущая
            </button>
            <span>Страница {page} из {totalPages}</span>
            <button
              className="btn btn-secondary"
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              Следующая
            </button>
          </div>
        </>
      )}
    </div>
  )
}

export default Events
