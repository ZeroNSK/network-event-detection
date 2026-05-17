import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const EventForm = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const isEdit = Boolean(id)
  
  const [formData, setFormData] = useState({
    node_id: '',
    rule_id: '',
    source_ip: '',
    destination_ip: '',
    protocol: 'TCP',
    event_type: 'other',
    event_message: '',
    severity: 'low'
  })
  const [nodes, setNodes] = useState([])
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchNodesAndRules()
    if (isEdit) {
      fetchEvent()
    }
  }, [id])

  const fetchNodesAndRules = async () => {
    try {
      const [nodesRes, rulesRes] = await Promise.all([
        api.get('/nodes?limit=100'),
        api.get('/rules?limit=100')
      ])
      setNodes(nodesRes.data.items)
      setRules(rulesRes.data.items)
    } catch (error) {
      toast.error('Ошибка загрузки данных')
    }
  }

  const fetchEvent = async () => {
    try {
      const response = await api.get(`/events/${id}`)
      setFormData({
        node_id: response.data.node_id,
        rule_id: response.data.rule_id || '',
        source_ip: response.data.source_ip,
        destination_ip: response.data.destination_ip,
        protocol: response.data.protocol,
        event_type: response.data.event_type,
        event_message: response.data.event_message,
        severity: response.data.severity
      })
    } catch (error) {
      const status = error.response?.status || 500
      const message = error.response?.data?.detail || 'Ошибка загрузки события'
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
        node_id: parseInt(formData.node_id),
        rule_id: formData.rule_id ? parseInt(formData.rule_id) : null
      }

      if (isEdit) {
        await api.put(`/events/${id}`, payload)
        toast.success('Событие обновлено')
      } else {
        await api.post('/events', payload)
        toast.success('Событие создано')
      }
      navigate('/events')
    } catch (error) {
      const message = error.response?.data?.detail || 'Ошибка сохранения события'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-container">
      <h1>{isEdit ? 'Редактировать событие' : 'Создать событие'}</h1>
      
      <form onSubmit={handleSubmit} className="form">
        <div className="form-group">
          <label htmlFor="node_id">Узел *</label>
          <select
            id="node_id"
            name="node_id"
            value={formData.node_id}
            onChange={handleChange}
            required
          >
            <option value="">Выберите узел</option>
            {nodes.map(node => (
              <option key={node.id} value={node.id}>
                {node.name} ({node.ip_address})
              </option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="rule_id">Правило обнаружения</label>
          <select
            id="rule_id"
            name="rule_id"
            value={formData.rule_id}
            onChange={handleChange}
          >
            <option value="">Без правила</option>
            {rules.map(rule => (
              <option key={rule.id} value={rule.id}>
                {rule.name}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="source_ip">IP источника *</label>
          <input
            type="text"
            id="source_ip"
            name="source_ip"
            value={formData.source_ip}
            onChange={handleChange}
            required
            placeholder="192.168.1.1"
          />
        </div>

        <div className="form-group">
          <label htmlFor="destination_ip">IP назначения *</label>
          <input
            type="text"
            id="destination_ip"
            name="destination_ip"
            value={formData.destination_ip}
            onChange={handleChange}
            required
            placeholder="10.0.1.1"
          />
        </div>

        <div className="form-group">
          <label htmlFor="protocol">Протокол *</label>
          <select
            id="protocol"
            name="protocol"
            value={formData.protocol}
            onChange={handleChange}
            required
          >
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
            <option value="SSH">SSH</option>
            <option value="OTHER">OTHER</option>
          </select>
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
            <option value="auth_failed">Auth Failed</option>
            <option value="port_scan">Port Scan</option>
            <option value="traffic_spike">Traffic Spike</option>
            <option value="unauthorized_access">Unauthorized Access</option>
            <option value="config_change">Config Change</option>
            <option value="connection_drop">Connection Drop</option>
            <option value="suspicious_ip">Suspicious IP</option>
            <option value="other">Other</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="event_message">Сообщение *</label>
          <textarea
            id="event_message"
            name="event_message"
            value={formData.event_message}
            onChange={handleChange}
            required
            rows="4"
            placeholder="Описание события..."
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
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Сохранение...' : 'Сохранить'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate('/events')}
          >
            Отмена
          </button>
        </div>
      </form>
    </div>
  )
}

export default EventForm
