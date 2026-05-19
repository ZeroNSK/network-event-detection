import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { eventTypeLabel, roleLabel } from '../utils/labels'

const IncidentForm = () => {
  const navigate = useNavigate()
  
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'medium',
    event_id: '',
    assigned_to: ''
  })
  const [events, setEvents] = useState([])
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchEventsAndUsers()
  }, [])

  const fetchEventsAndUsers = async () => {
    try {
      // Загружаем подозрительные события и список пользователей.
      const [eventsRes, usersRes] = await Promise.all([
        api.get('/events?is_suspicious=true&limit=100'),
        api.get('/auth/users?limit=100').catch(() => ({ data: { items: [] } }))
      ])
      setEvents(eventsRes.data.items)
      setUsers(usersRes.data.items || [])
    } catch (error) {
      toast.error('Ошибка загрузки данных')
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
        event_id: parseInt(formData.event_id),
        assigned_to: formData.assigned_to ? parseInt(formData.assigned_to) : null
      }

      await api.post('/incidents', payload)
      toast.success('Инцидент создан')
      navigate('/incidents')
    } catch (error) {
      const message = error.response?.data?.detail || 'Ошибка создания инцидента'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-container">
      <h1>Создать инцидент</h1>
      
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
            placeholder="Краткое описание инцидента"
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
            placeholder="Подробное описание инцидента..."
          />
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
            <option value="low">Низкий</option>
            <option value="medium">Средний</option>
            <option value="high">Высокий</option>
            <option value="critical">Критический</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="event_id">Связанное событие *</label>
          <select
            id="event_id"
            name="event_id"
            value={formData.event_id}
            onChange={handleChange}
            required
          >
            <option value="">Выберите подозрительное событие</option>
            {events.map(event => (
              <option key={event.id} value={event.id}>
                #{event.id} - {eventTypeLabel(event.event_type)} ({event.source_ip} → {event.destination_ip})
              </option>
            ))}
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
                {user.username} ({roleLabel(user.role)})
              </option>
            ))}
          </select>
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Создание...' : 'Создать'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate('/incidents')}
          >
            Отмена
          </button>
        </div>
      </form>
    </div>
  )
}

export default IncidentForm
