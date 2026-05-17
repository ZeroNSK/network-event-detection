import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Nodes = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const [nodes, setNodes] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({
    node_type: '',
    status: ''
  })
  const limit = 10

  useEffect(() => {
    fetchNodes()
  }, [page, filters])

  const fetchNodes = async () => {
    setLoading(true)
    try {
      const params = { page, limit, ...filters }
      // Remove empty filters
      Object.keys(params).forEach(key => {
        if (params[key] === '') delete params[key]
      })
      
      const response = await api.get('/nodes', { params })
      setNodes(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      toast.error('Ошибка загрузки узлов')
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
    if (!window.confirm('Вы уверены, что хотите удалить этот узел?')) {
      return
    }

    try {
      await api.delete(`/nodes/${id}`)
      toast.success('Узел удален')
      fetchNodes()
    } catch (error) {
      toast.error('Ошибка удаления узла')
    }
  }

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Сетевые узлы</h1>
        {user.role === 'admin' && (
          <button 
            className="btn btn-primary"
            onClick={() => navigate('/nodes/new')}
          >
            Создать узел
          </button>
        )}
      </div>

      <div className="filters">
        <select name="node_type" value={filters.node_type} onChange={handleFilterChange}>
          <option value="">Все типы</option>
          <option value="router">Router</option>
          <option value="switch">Switch</option>
          <option value="base_station">Base Station</option>
          <option value="server">Server</option>
          <option value="firewall">Firewall</option>
          <option value="gateway">Gateway</option>
        </select>

        <select name="status" value={filters.status} onChange={handleFilterChange}>
          <option value="">Все статусы</option>
          <option value="active">Active</option>
          <option value="warning">Warning</option>
          <option value="offline">Offline</option>
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
                <th>Тип</th>
                <th>IP адрес</th>
                <th>Локация</th>
                <th>Статус</th>
                <th>Создан</th>
                {user.role === 'admin' && <th>Действия</th>}
              </tr>
            </thead>
            <tbody>
              {nodes.map(node => (
                <tr key={node.id}>
                  <td>{node.id}</td>
                  <td>{node.name}</td>
                  <td>{node.node_type}</td>
                  <td>{node.ip_address}</td>
                  <td>{node.location || '-'}</td>
                  <td>
                    <span className={`badge badge-${node.status}`}>
                      {node.status}
                    </span>
                  </td>
                  <td>{new Date(node.created_at).toLocaleString('ru-RU')}</td>
                  {user.role === 'admin' && (
                    <td>
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => navigate(`/nodes/${node.id}/edit`)}
                      >
                        Редактировать
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(node.id)}
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

export default Nodes
