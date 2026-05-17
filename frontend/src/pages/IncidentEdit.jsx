import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const IncidentEdit = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    status: 'new',
    severity: 'medium',
    assigned_to: ''
  })
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchIncidentAndUsers()
  }, [id])

  const fetchIncidentAndUsers = async () => {
    try {
      const [incidentRes, usersRes] = await Promise.all([
        api.get(`/incidents/${id}`),
        api.get('/auth/users?limit=100').catch(() => ({ data: { items: [] } }))
      ])
      
      setFormData({
        title: incidentRes.data.title,
        description: incidentRes.data.description,
        status: incidentRes.data.status,
        severity: incidentRes.data.severity,
        assigned_to: incidentRes.data.assigned_to || ''
      })
      setUsers(usersRes.data.items || [])
    } catch (error) {
      const status = error.response?.status || 500
      const message = error.response?.data?.detail || 'Ошибка загрузки данных'
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
      const payload = {
        ...formData,
        assigned_to: formData.assigned_to ? parseInt(formData.assigned_to) : null
      }

      await api.put(`/incidents/${id}`, payload)
      toast.success('Инцидент обновлен')
      navigate(`/incidents/${id}`)
    } catch (error) {
      const message = error.response?.data?.detail || 'Ошибка обновления инцидента'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-container">
      <h1>Редактировать инцидент</h1>
      
      <form onSubmit={handleSubmit} className="form">
        <div className="form-group">
          <label htmlFor="title">Название *</label>
          <input
            type="text"
            id="title"
            name="title"
            value={formData.title}
            onChange={handleChange}
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="description">Описание *</label>
          <textarea
            id="description"
            name="description"
            value={formData.description}
            onChange={handleChange}
            required
            rows="4"
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
            <option value="new">New</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="rejected">Rejected</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="severity">Уровень критичности *</label>
          <select
            id="severity"
            name="severity"
            value={formData.severity}
            onChange={handleChange}
            required
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="assigned_to">Назначить пользователю</label>
          <select
            id="assigned_to"
            name="assigned_to"
            value={formData.assigned_to}
            onChange={handleChange}
          >
            <option value="">Не назначен</option>
            {users.map(user => (
              <option key={user.id} value={user.id}>
                {user.username} ({user.role})
              </option>
            ))}
          </select>
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Сохранение...' : 'Сохранить'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate(`/incidents/${id}`)}
          >
            Отмена
          </button>
        </div>
      </form>
    </div>
  )
}

export default IncidentEdit
