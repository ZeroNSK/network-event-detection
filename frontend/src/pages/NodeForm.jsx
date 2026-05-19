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
            <option value="router">Маршрутизатор</option>
            <option value="switch">Коммутатор</option>
            <option value="base_station">Базовая станция</option>
            <option value="server">Сервер</option>
            <option value="firewall">Межсетевой экран</option>
            <option value="gateway">Шлюз</option>
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
            placeholder="Москва, центр обработки данных"
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
            <option value="active">Активен</option>
            <option value="warning">Требует внимания</option>
            <option value="offline">Недоступен</option>
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
