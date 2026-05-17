import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const NodeForm = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const isEdit = Boolean(id)
  
  const [formData, setFormData] = useState({
    name: '',
    node_type: 'router',
    ip_address: '',
    location: '',
    status: 'active'
  })
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (isEdit) {
      fetchNode()
    }
  }, [id])

  const fetchNode = async () => {
    try {
      const response = await api.get(`/nodes/${id}`)
      setFormData(response.data)
    } catch (error) {
      const status = error.response?.status || 500
      const message = error.response?.data?.detail || 'Ошибка загрузки узла'
      navigate(`/error?status=${status}&message=${encodeURIComponent(message)}`)
    }
  }

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      if (isEdit) {
        await api.put(`/nodes/${id}`, formData)
        toast.success('Узел обновлен')
      } else {
        await api.post('/nodes', formData)
        toast.success('Узел создан')
      }
      navigate('/nodes')
    } catch (error) {
      const message = error.response?.data?.detail || 'Ошибка сохранения узла'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-container">
      <h1>{isEdit ? 'Редактировать узел' : 'Создать узел'}</h1>
      
      <form onSubmit={handleSubmit} className="form">
        <div className="form-group">
          <label htmlFor="name">Название *</label>
          <input
            type="text"
            id="name"
            name="name"
            value={formData.name}
            onChange={handleChange}
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="node_type">Тип узла *</label>
          <select
            id="node_type"
            name="node_type"
            value={formData.node_type}
            onChange={handleChange}
            required
          >
            <option value="router">Router</option>
            <option value="switch">Switch</option>
            <option value="base_station">Base Station</option>
            <option value="server">Server</option>
            <option value="firewall">Firewall</option>
            <option value="gateway">Gateway</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="ip_address">IP адрес *</label>
          <input
            type="text"
            id="ip_address"
            name="ip_address"
            value={formData.ip_address}
            onChange={handleChange}
            required
            placeholder="10.0.1.1"
          />
        </div>

        <div className="form-group">
          <label htmlFor="location">Локация</label>
          <input
            type="text"
            id="location"
            name="location"
            value={formData.location}
            onChange={handleChange}
            placeholder="Data Center A"
          />
        </div>

        <div className="form-group">
          <label htmlFor="status">Статус *</label>
          <select
            id="status"
            name="status"
            value={formData.status}
            onChange={handleChange}
            required
          >
            <option value="active">Active</option>
            <option value="warning">Warning</option>
            <option value="offline">Offline</option>
          </select>
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Сохранение...' : 'Сохранить'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate('/nodes')}
          >
            Отмена
          </button>
        </div>
      </form>
    </div>
  )
}

export default NodeForm
