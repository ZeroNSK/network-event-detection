import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Rules = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({
    event_type: '',
    is_active: ''
  })
  const limit = 10

  useEffect(() => {
    fetchRules()
  }, [page, filters])

  const fetchRules = async () => {
    setLoading(true)
    try {
      const params = { page, limit, ...filters }
      // Remove empty filters
      Object.keys(params).forEach(key => {
        if (params[key] === '') delete params[key]
      })
      
      const response = await api.get('/rules', { params })
      setRules(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      toast.error('Ошибка загрузки правил')
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
    if (!window.confirm('Вы уверены, что хотите удалить это правило?')) {
      return
    }

    try {
      await api.delete(`/rules/${id}`)
      toast.success('Правило удалено')
      fetchRules()
    } catch (error) {
      toast.error('Ошибка удаления правила')
    }
  }

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Правила обнаружения</h1>
        {user.role === 'admin' && (
          <button 
            className="btn btn-primary"
            onClick={() => navigate('/rules/new')}
          >
            Создать правило
          </button>
        )}
      </div>

      <div className="filters">
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

        <select name="is_active" value={filters.is_active} onChange={handleFilterChange}>
          <option value="">Все статусы</option>
          <option value="true">Активные</option>
          <option value="false">Неактивные</option>
        </select>
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
                <th>Тип события</th>
                <th>Порог критичности</th>
                <th>Вес риска</th>
                <th>Окно</th>
                <th>Порог</th>
                <th>Категория</th>
                <th>Статус</th>
                <th>Создано</th>
                {user.role === 'admin' && <th>Действия</th>}
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.id}>
                  <td>{rule.id}</td>
                  <td>{rule.name}</td>
                  <td>{rule.event_type}</td>
                  <td>
                    <span className={`badge badge-${rule.severity_threshold}`}>
                      {rule.severity_threshold}
                    </span>
                  </td>
                  <td>{rule.risk_weight}</td>
                  <td>{rule.time_window_minutes} мин.</td>
                  <td>{rule.threshold_count}</td>
                  <td>{rule.rule_category}</td>
                  <td>
                    <span className={`badge ${rule.is_active ? 'badge-success' : 'badge-secondary'}`}>
                      {rule.is_active ? 'Активно' : 'Неактивно'}
                    </span>
                  </td>
                  <td>{new Date(rule.created_at).toLocaleString('ru-RU')}</td>
                  {user.role === 'admin' && (
                    <td>
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => navigate(`/rules/${rule.id}/edit`)}
                      >
                        Редактировать
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(rule.id)}
                      >
                        Удалить
                      </button>
                    </td>
                  )}
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

export default Rules
