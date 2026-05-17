import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Incidents = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({
    status: '',
    severity: ''
  })
  const limit = 10

  useEffect(() => {
    fetchIncidents()
  }, [page, filters])

  const fetchIncidents = async () => {
    setLoading(true)
    try {
      const params = { page, limit, ...filters }
      // Remove empty filters
      Object.keys(params).forEach(key => {
        if (params[key] === '') delete params[key]
      })
      
      const response = await api.get('/incidents', { params })
      setIncidents(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      toast.error('Ошибка загрузки инцидентов')
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
    if (!window.confirm('Вы уверены, что хотите удалить этот инцидент?')) {
      return
    }

    try {
      await api.delete(`/incidents/${id}`)
      toast.success('Инцидент удален')
      fetchIncidents()
    } catch (error) {
      toast.error('Ошибка удаления инцидента')
    }
  }

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Инциденты безопасности</h1>
        <button 
          className="btn btn-primary"
          onClick={() => navigate('/incidents/new')}
        >
          Создать инцидент
        </button>
      </div>

      <div className="filters">
        <select name="status" value={filters.status} onChange={handleFilterChange}>
          <option value="">Все статусы</option>
          <option value="new">New</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="rejected">Rejected</option>
        </select>

        <select name="severity" value={filters.severity} onChange={handleFilterChange}>
          <option value="">Все уровни</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
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
                <th>Статус</th>
                <th>Уровень</th>
                <th>Событие</th>
                <th>Назначен</th>
                <th>Создан</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map(incident => (
                <tr key={incident.id}>
                  <td>{incident.id}</td>
                  <td>{incident.title}</td>
                  <td>
                    <span className={`badge badge-${incident.status}`}>
                      {incident.status}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${incident.severity}`}>
                      {incident.severity}
                    </span>
                  </td>
                  <td>Event #{incident.event_id}</td>
                  <td>{incident.assigned_to ? `User #${incident.assigned_to}` : 'Не назначен'}</td>
                  <td>{new Date(incident.created_at).toLocaleString('ru-RU')}</td>
                  <td>
                    <button
                      className="btn btn-sm btn-info"
                      onClick={() => navigate(`/incidents/${incident.id}`)}
                    >
                      Просмотр
                    </button>
                    {['admin', 'security_engineer'].includes(user.role) && (
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => navigate(`/incidents/${incident.id}/edit`)}
                      >
                        Редактировать
                      </button>
                    )}
                    {user.role === 'admin' && (
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(incident.id)}
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

export default Incidents
