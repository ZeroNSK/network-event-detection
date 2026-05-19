import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { eventTypeLabel, riskLevelLabel, severityLabel, protocolLabel } from '../utils/labels'

const Events = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [apiMismatch, setApiMismatch] = useState(false)
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
      
      // Добавляем только заполненные фильтры.
      if (filters.severity) params.severity = filters.severity
      if (filters.is_suspicious !== '') params.is_suspicious = filters.is_suspicious
      if (filters.event_type) params.event_type = filters.event_type
      if (filters.risk_level) params.risk_level = filters.risk_level
      if (filters.min_risk_score) params.min_risk_score = filters.min_risk_score
      if (filters.max_risk_score) params.max_risk_score = filters.max_risk_score
      
      const response = await api.get('/events', { params })
      const items = response.data.items || []
      setEvents(items)
      setTotal(response.data.total)
      setApiMismatch(items.length > 0 && items.some(event => event.risk_score === undefined))
    } catch (error) {
      console.error('Ошибка загрузки событий:', error)
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

  const totalPages = Math.max(1, Math.ceil(total / limit))

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <p className="page-kicker">Investigation table</p>
          <h1>Сетевые события</h1>
          <p className="page-description">Фильтруйте события по риску, типу и признакам подозрительной активности.</p>
        </div>
        <button 
          className="btn btn-primary"
          onClick={() => navigate('/events/new')}
        >
          Создать событие
        </button>
      </div>

      {apiMismatch && (
        <div className="alert-box alert-error">
          Серверная часть вернула старый формат событий без оценки риска. Пересоберите и перезапустите сервер, иначе риски не будут отображаться.
        </div>
      )}

      <div className="filters">
        <select name="severity" value={filters.severity} onChange={handleFilterChange}>
          <option value="">Все уровни</option>
          <option value="low">Низкий</option>
          <option value="medium">Средний</option>
          <option value="high">Высокий</option>
          <option value="critical">Критический</option>
        </select>

        <select name="is_suspicious" value={filters.is_suspicious} onChange={handleFilterChange}>
          <option value="">Все события</option>
          <option value="true">Подозрительные</option>
          <option value="false">Обычные</option>
        </select>

        <select name="event_type" value={filters.event_type} onChange={handleFilterChange}>
          <option value="">Все типы</option>
          <option value="auth_failed">Ошибка аутентификации</option>
          <option value="port_scan">Сканирование портов</option>
          <option value="traffic_spike">Всплеск трафика</option>
          <option value="unauthorized_access">Несанкционированный доступ</option>
          <option value="config_change">Изменение конфигурации</option>
          <option value="connection_drop">Потеря соединения</option>
          <option value="suspicious_ip">Подозрительный IP</option>
          <option value="other">Другое событие</option>
        </select>

        <select name="risk_level" value={filters.risk_level} onChange={handleFilterChange}>
          <option value="">Все уровни риска</option>
          <option value="low">Низкий</option>
          <option value="medium">Средний</option>
          <option value="high">Высокий</option>
          <option value="critical">Критический</option>
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
      ) : events.length === 0 ? (
        <div className="empty-state">
          <p className="page-kicker">No events</p>
          <h2>События не найдены</h2>
          <p>Измените фильтры, создайте событие вручную или импортируйте CSV-набор данных.</p>
          <div className="actions">
            <button className="btn btn-primary" onClick={() => navigate('/events/new')}>
              Создать событие
            </button>
            {['admin', 'security_engineer'].includes(user.role) && (
              <button className="btn btn-secondary" onClick={() => navigate('/dataset')}>
                Импорт CSV
              </button>
            )}
          </div>
        </div>
      ) : (
        <>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Источник</th>
                  <th>Назначение</th>
                  <th>Протокол</th>
                  <th>Тип</th>
                  <th>Уровень</th>
                  <th>Балл риска</th>
                  <th>Уровень риска</th>
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
                    <td className="mono-cell">{event.source_ip}</td>
                    <td className="mono-cell">{event.destination_ip}</td>
                    <td>{protocolLabel(event.protocol)}</td>
                    <td>{eventTypeLabel(event.event_type)}</td>
                    <td>
                      <span className={`badge badge-${event.severity}`}>
                        {severityLabel(event.severity)}
                      </span>
                    </td>
                    <td>
                      {event.risk_score !== undefined ? (
                        <div className="risk-cell">
                          <div className="risk-cell-top">
                            <strong>{event.risk_score}</strong>
                            <span className={`badge badge-${event.risk_level}`}>
                              {riskLevelLabel(event.risk_level)}
                            </span>
                          </div>
                          <div className="risk-mini-track">
                            <div
                              className={`risk-mini-fill bar-${event.risk_level}`}
                              style={{ width: `${Math.min(event.risk_score || 0, 100)}%` }}
                            />
                          </div>
                        </div>
                      ) : (
                        <span className="badge badge-secondary">нет данных</span>
                      )}
                    </td>
                    <td>
                      {event.risk_level ? (
                        <span className={`badge badge-${event.risk_level}`}>
                          {riskLevelLabel(event.risk_level)}
                        </span>
                      ) : (
                        <span className="badge badge-secondary">старый API</span>
                      )}
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
          </div>

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
