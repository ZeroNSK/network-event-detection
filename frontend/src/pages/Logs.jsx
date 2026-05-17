import { useState, useEffect } from 'react'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Logs = () => {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const limit = 20

  useEffect(() => {
    fetchLogs()
  }, [page])

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const response = await api.get('/logs', { params: { page, limit } })
      setLogs(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      toast.error('Ошибка загрузки журнала действий')
    } finally {
      setLoading(false)
    }
  }

  const totalPages = Math.ceil(total / limit)

  const getActionBadgeClass = (action) => {
    switch (action) {
      case 'create':
        return 'badge-success'
      case 'update':
        return 'badge-info'
      case 'delete':
        return 'badge-danger'
      case 'login':
        return 'badge-primary'
      default:
        return 'badge-secondary'
    }
  }

  return (
    <div className="page-container">
      <h1>Журнал действий пользователей</h1>

      {loading ? (
        <div className="loading">Загрузка...</div>
      ) : (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Пользователь</th>
                <th>Действие</th>
                <th>Тип сущности</th>
                <th>ID сущности</th>
                <th>Время</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log.id}>
                  <td>{log.id}</td>
                  <td>
                    {log.user ? (
                      <div>
                        <div>{log.user.username}</div>
                        <div style={{ fontSize: '0.85em', color: '#666' }}>
                          {log.user.role}
                        </div>
                      </div>
                    ) : (
                      `User #${log.user_id}`
                    )}
                  </td>
                  <td>
                    <span className={`badge ${getActionBadgeClass(log.action)}`}>
                      {log.action}
                    </span>
                  </td>
                  <td>{log.entity_type || '-'}</td>
                  <td>{log.entity_id || '-'}</td>
                  <td>{new Date(log.created_at).toLocaleString('ru-RU')}</td>
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

export default Logs
