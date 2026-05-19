import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { alertStatusLabel, riskLevelLabel } from '../utils/labels'

const AnalysisAlerts = () => {
  const navigate = useNavigate()
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({ status: '', risk_level: '', source_ip: '' })
  const limit = 10

  useEffect(() => {
    fetchAlerts()
  }, [page, filters])

  const fetchAlerts = async () => {
    setLoading(true)
    try {
      const params = { page, limit, ...filters }
      Object.keys(params).forEach(key => {
        if (params[key] === '') delete params[key]
      })
      const response = await api.get('/analysis/alerts', { params })
      setAlerts(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      toast.error('Ошибка загрузки корреляционных оповещений')
    } finally {
      setLoading(false)
    }
  }

  const handleFilterChange = (e) => {
    setFilters({ ...filters, [e.target.name]: e.target.value })
    setPage(1)
  }

  const createIncident = async (alertId) => {
    try {
      const response = await api.post(`/analysis/alerts/${alertId}/create-incident`)
      toast.success(`Инцидент #${response.data.id} создан или уже существует`)
      navigate(`/incidents/${response.data.id}`)
    } catch (error) {
      toast.error('Ошибка создания инцидента')
    }
  }

  const totalPages = Math.max(Math.ceil(total / limit), 1)

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Корреляционные оповещения</h1>
        <button className="btn btn-secondary" onClick={() => navigate('/analysis')}>
          Назад к анализу
        </button>
      </div>

      <div className="filters">
        <select name="status" value={filters.status} onChange={handleFilterChange}>
          <option value="">Все статусы</option>
          <option value="new">Новый</option>
          <option value="in_progress">В работе</option>
          <option value="resolved">Решен</option>
          <option value="false_positive">Ложное срабатывание</option>
        </select>
        <select name="risk_level" value={filters.risk_level} onChange={handleFilterChange}>
          <option value="">Все уровни риска</option>
          <option value="low">Низкий</option>
          <option value="medium">Средний</option>
          <option value="high">Высокий</option>
          <option value="critical">Критический</option>
        </select>
        <input
          name="source_ip"
          value={filters.source_ip}
          onChange={handleFilterChange}
          placeholder="IP источника"
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
                <th>Название</th>
                <th>Статус</th>
                <th>Балл риска</th>
                <th>Уровень риска</th>
                <th>IP источника</th>
                <th>События</th>
                <th>Первое событие</th>
                <th>Последнее событие</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => (
                <tr key={alert.id}>
                  <td>{alert.id}</td>
                  <td>{alert.title}</td>
                  <td><span className={`badge badge-${alert.status}`}>{alertStatusLabel(alert.status)}</span></td>
                  <td>{alert.risk_score}</td>
                  <td><span className={`badge badge-${alert.risk_level}`}>{riskLevelLabel(alert.risk_level)}</span></td>
                  <td>{alert.source_ip || 'Нет данных'}</td>
                  <td>{alert.event_count}</td>
                  <td>{new Date(alert.first_seen).toLocaleString('ru-RU')}</td>
                  <td>{new Date(alert.last_seen).toLocaleString('ru-RU')}</td>
                  <td>
                    <button className="btn btn-sm btn-info" onClick={() => navigate(`/analysis/alerts/${alert.id}`)}>
                      Просмотр
                    </button>
                    <button className="btn btn-sm btn-primary" onClick={() => createIncident(alert.id)}>
                      Создать инцидент
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="pagination">
            <button className="btn btn-secondary" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>
              Предыдущая
            </button>
            <span>Страница {page} из {totalPages}</span>
            <button className="btn btn-secondary" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
              Следующая
            </button>
          </div>
        </>
      )}
    </div>
  )
}

export default AnalysisAlerts
