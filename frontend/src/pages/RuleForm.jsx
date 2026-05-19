import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const RuleForm = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const isEdit = Boolean(id)
  
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    event_type: 'other',
    severity_threshold: 'medium',
    risk_weight: 0,
    time_window_minutes: 10,
    threshold_count: 1,
    rule_category: 'configuration',
    is_active: true
  })
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (isEdit) {
      fetchRule()
    }
  }, [id])

  const fetchRule = async () => {
    try {
      const response = await api.get(`/rules/${id}`)
      setFormData(response.data)
    } catch (error) {
      const status = error.response?.status || 500
      const message = error.response?.data?.detail || 'Ошибка загрузки правила'
      navigate(`/error?status=${status}&message=${encodeURIComponent(message)}`)
    }
  }

  const handleChange = (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value
    setFormData({
      ...formData,
      [e.target.name]: value
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      const payload = {
        ...formData,
        risk_weight: Number(formData.risk_weight),
        time_window_minutes: Number(formData.time_window_minutes),
        threshold_count: Number(formData.threshold_count)
      }
      if (isEdit) {
        await api.put(`/rules/${id}`, payload)
        toast.success('Правило обновлено')
      } else {
        await api.post('/rules', payload)
        toast.success('Правило создано')
      }
      navigate('/rules')
    } catch (error) {
      const message = error.response?.data?.detail || 'Ошибка сохранения правила'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-container">
      <h1>{isEdit ? 'Редактировать правило' : 'Создать правило'}</h1>
      
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
          <label htmlFor="description">Описание</label>
          <textarea
            id="description"
            name="description"
            value={formData.description}
            onChange={handleChange}
            rows="3"
            placeholder="Описание правила обнаружения..."
          />
        </div>

        <div className="form-group">
          <label htmlFor="event_type">Тип события *</label>
          <select
            id="event_type"
            name="event_type"
            value={formData.event_type}
            onChange={handleChange}
            required
          >
            <option value="auth_failed">Ошибка аутентификации</option>
            <option value="port_scan">Сканирование портов</option>
            <option value="traffic_spike">Всплеск трафика</option>
            <option value="unauthorized_access">Несанкционированный доступ</option>
            <option value="config_change">Изменение конфигурации</option>
            <option value="connection_drop">Потеря соединения</option>
            <option value="suspicious_ip">Подозрительный IP</option>
            <option value="other">Другое событие</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="severity_threshold">Порог критичности *</label>
          <select
            id="severity_threshold"
            name="severity_threshold"
            value={formData.severity_threshold}
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
          <label htmlFor="risk_weight">Вес риска *</label>
          <input
            type="number"
            id="risk_weight"
            name="risk_weight"
            value={formData.risk_weight}
            onChange={handleChange}
            min="0"
            max="100"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="time_window_minutes">Окно корреляции, минут *</label>
          <input
            type="number"
            id="time_window_minutes"
            name="time_window_minutes"
            value={formData.time_window_minutes}
            onChange={handleChange}
            min="1"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="threshold_count">Порог количества *</label>
          <input
            type="number"
            id="threshold_count"
            name="threshold_count"
            value={formData.threshold_count}
            onChange={handleChange}
            min="1"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="rule_category">Категория правила *</label>
          <select
            id="rule_category"
            name="rule_category"
            value={formData.rule_category}
            onChange={handleChange}
            required
          >
            <option value="authentication">Аутентификация</option>
            <option value="network_scan">Сканирование сети</option>
            <option value="traffic_anomaly">Аномалии трафика</option>
            <option value="unauthorized_access">Несанкционированный доступ</option>
            <option value="availability">Доступность</option>
            <option value="configuration">Конфигурация</option>
          </select>
        </div>

        <div className="form-group">
          <label>
            <input
              type="checkbox"
              name="is_active"
              checked={formData.is_active}
              onChange={handleChange}
            />
            {' '}Активно
          </label>
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Сохранение...' : 'Сохранить'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate('/rules')}
          >
            Отмена
          </button>
        </div>
      </form>
    </div>
  )
}

export default RuleForm
