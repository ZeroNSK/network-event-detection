import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { eventTypeLabel, incidentStatusLabel, roleLabel, severityLabel } from '../utils/labels'

const IncidentDetails = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const [incident, setIncident] = useState(null)
  const [loading, setLoading] = useState(true)
  const [editingStatus, setEditingStatus] = useState(false)
  const [newStatus, setNewStatus] = useState('')
  const [accessGrants, setAccessGrants] = useState([])
  const [showAccessForm, setShowAccessForm] = useState(false)
  const [newAccessUserId, setNewAccessUserId] = useState('')
  const [newAccessLevel, setNewAccessLevel] = useState('read')
  const [users, setUsers] = useState([])
  const [canManageAccess, setCanManageAccess] = useState(false)

  useEffect(() => {
    fetchIncident()
    fetchAccessGrants()
    if (user.role === 'admin') {
      fetchUsers()
      setCanManageAccess(true)
    }
  }, [id])

  const fetchIncident = async () => {
    try {
      const response = await api.get(`/incidents/${id}`)
      setIncident(response.data)
      setNewStatus(response.data.status)
    } catch (error) {
      const status = error.response?.status || 500
      const message = error.response?.data?.detail || 'Ошибка загрузки инцидента'
      navigate(`/error?status=${status}&message=${encodeURIComponent(message)}`)
    } finally {
      setLoading(false)
    }
  }

  const fetchAccessGrants = async () => {
    try {
      const response = await api.get(`/incidents/${id}/access`)
      setAccessGrants(response.data)
      // Проверяем, есть ли у текущего пользователя право управлять доступом.
      const userAccess = response.data.find(a => a.user_id === user.id)
      if (userAccess && userAccess.access_level === 'manage') {
        setCanManageAccess(true)
        fetchUsers()
      }
    } catch (error) {
      console.error('Ошибка загрузки прав доступа:', error)
    }
  }

  const fetchUsers = async () => {
    try {
      const response = await api.get('/auth/users?limit=100')
      setUsers(response.data.items || [])
    } catch (error) {
      console.error('Ошибка загрузки пользователей:', error)
    }
  }

  const handleStatusUpdate = async () => {
    try {
      await api.put(`/incidents/${id}`, { status: newStatus })
      toast.success('Статус обновлен')
      setEditingStatus(false)
      fetchIncident()
    } catch (error) {
      toast.error('Ошибка обновления статуса')
    }
  }

  const handleGrantAccess = async (e) => {
    e.preventDefault()
    try {
      await api.post(`/incidents/${id}/access`, {
        user_id: parseInt(newAccessUserId),
        access_level: newAccessLevel
      })
      toast.success('Доступ предоставлен')
      setShowAccessForm(false)
      setNewAccessUserId('')
      setNewAccessLevel('read')
      fetchAccessGrants()
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Ошибка предоставления доступа')
    }
  }

  const handleUpdateAccess = async (accessId, newLevel) => {
    try {
      await api.put(`/incidents/${id}/access/${accessId}`, {
        access_level: newLevel
      })
      toast.success('Уровень доступа обновлен')
      fetchAccessGrants()
    } catch (error) {
      toast.error('Ошибка обновления доступа')
    }
  }

  const handleRevokeAccess = async (accessId) => {
    if (!confirm('Вы уверены, что хотите отозвать доступ?')) return
    
    try {
      await api.delete(`/incidents/${id}/access/${accessId}`)
      toast.success('Доступ отозван')
      fetchAccessGrants()
    } catch (error) {
      toast.error('Ошибка отзыва доступа')
    }
  }

  const getAccessLevelLabel = (level) => {
    const labels = {
      read: 'Чтение',
      write: 'Запись',
      manage: 'Управление'
    }
    return labels[level] || level
  }

  if (loading) {
    return <div className="loading">Загрузка...</div>
  }

  if (!incident) {
    return null
  }

  const availableUsers = users.filter(u => 
    !accessGrants.some(a => a.user_id === u.id)
  )

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Детали инцидента #{incident.id}</h1>
        <div>
          {['admin', 'security_engineer'].includes(user.role) && (
            <button 
              className="btn btn-secondary"
              onClick={() => navigate(`/incidents/${incident.id}/edit`)}
            >
              Редактировать
            </button>
          )}
          <button 
            className="btn btn-secondary"
            onClick={() => navigate('/incidents')}
          >
            Назад к списку
          </button>
        </div>
      </div>

      <div className="details-card">
        <div className="detail-row">
          <span className="detail-label">ID:</span>
          <span className="detail-value">{incident.id}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Название:</span>
          <span className="detail-value">{incident.title}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Описание:</span>
          <span className="detail-value">{incident.description}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Статус:</span>
          <span className="detail-value">
            {editingStatus ? (
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                <select 
                  value={newStatus} 
                  onChange={(e) => setNewStatus(e.target.value)}
                  className="form-control"
                >
                  <option value="new">Новый</option>
                  <option value="in_progress">В работе</option>
                  <option value="resolved">Решен</option>
                  <option value="rejected">Отклонен</option>
                </select>
                <button className="btn btn-sm btn-primary" onClick={handleStatusUpdate}>
                  Сохранить
                </button>
                <button className="btn btn-sm btn-secondary" onClick={() => setEditingStatus(false)}>
                  Отмена
                </button>
              </div>
            ) : (
              <>
                <span className={`badge badge-${incident.status}`}>
                  {incidentStatusLabel(incident.status)}
                </span>
                {['admin', 'security_engineer'].includes(user.role) && (
                  <button 
                    className="btn btn-sm btn-secondary"
                    onClick={() => setEditingStatus(true)}
                    style={{ marginLeft: '10px' }}
                  >
                    Изменить статус
                  </button>
                )}
              </>
            )}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Уровень критичности:</span>
          <span className="detail-value">
            <span className={`badge badge-${incident.severity}`}>
              {severityLabel(incident.severity)}
            </span>
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Связанное событие:</span>
          <span className="detail-value">
            {incident.event ? (
              <div>
                <div>Событие #{incident.event.id}</div>
                <div style={{ fontSize: '0.9em', color: '#666' }}>
                  {eventTypeLabel(incident.event.event_type)} - {incident.event.source_ip} → {incident.event.destination_ip}
                </div>
                <div style={{ fontSize: '0.9em', color: '#666' }}>
                  {incident.event.event_message}
                </div>
              </div>
            ) : (
              `Событие #${incident.event_id}`
            )}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Назначен:</span>
          <span className="detail-value">
            {incident.assigned_to ? `Пользователь #${incident.assigned_to}` : 'Не назначен'}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Создал:</span>
          <span className="detail-value">Пользователь #{incident.created_by}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Создан:</span>
          <span className="detail-value">
            {new Date(incident.created_at).toLocaleString('ru-RU')}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Обновлен:</span>
          <span className="detail-value">
            {new Date(incident.updated_at).toLocaleString('ru-RU')}
          </span>
        </div>
      </div>

      {/* Раздел управления доступом */}
      <div className="details-card" style={{ marginTop: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>Управление доступом</h2>
          {canManageAccess && (
            <button 
              className="btn btn-primary"
              onClick={() => setShowAccessForm(!showAccessForm)}
            >
              {showAccessForm ? 'Отмена' : 'Предоставить доступ'}
            </button>
          )}
        </div>

        {showAccessForm && (
          <form onSubmit={handleGrantAccess} style={{ marginBottom: '20px', padding: '15px', background: '#f5f5f5', borderRadius: '5px' }}>
            <div className="form-group">
              <label>Пользователь:</label>
              <select
                value={newAccessUserId}
                onChange={(e) => setNewAccessUserId(e.target.value)}
                className="form-control"
                required
              >
                <option value="">Выберите пользователя</option>
                {availableUsers.map(u => (
                  <option key={u.id} value={u.id}>
                    {u.username} ({roleLabel(u.role)})
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label>Уровень доступа:</label>
              <select
                value={newAccessLevel}
                onChange={(e) => setNewAccessLevel(e.target.value)}
                className="form-control"
                required
              >
                <option value="read">Чтение</option>
                <option value="write">Запись</option>
                <option value="manage">Управление</option>
              </select>
            </div>
            <button type="submit" className="btn btn-primary">
              Предоставить
            </button>
          </form>
        )}

        <table className="table">
          <thead>
            <tr>
              <th>Пользователь</th>
              <th>Роль</th>
              <th>Уровень доступа</th>
              <th>Предоставлен</th>
              {canManageAccess && <th>Действия</th>}
            </tr>
          </thead>
          <tbody>
            {accessGrants.map(access => (
              <tr key={access.id}>
                <td>{access.user?.username || `Пользователь #${access.user_id}`}</td>
                <td>{access.user ? roleLabel(access.user.role) : '-'}</td>
                <td>
                  {canManageAccess ? (
                    <select
                      value={access.access_level}
                      onChange={(e) => handleUpdateAccess(access.id, e.target.value)}
                      className="form-control"
                      style={{ width: 'auto', display: 'inline-block' }}
                    >
                      <option value="read">Чтение</option>
                      <option value="write">Запись</option>
                      <option value="manage">Управление</option>
                    </select>
                  ) : (
                    <span className="badge badge-info">
                      {getAccessLevelLabel(access.access_level)}
                    </span>
                  )}
                </td>
                <td>{new Date(access.created_at).toLocaleString('ru-RU')}</td>
                {canManageAccess && (
                  <td>
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => handleRevokeAccess(access.id)}
                    >
                      Отозвать
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {accessGrants.length === 0 && (
              <tr>
                <td colSpan={canManageAccess ? 5 : 4} style={{ textAlign: 'center' }}>
                  Нет предоставленных прав доступа
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default IncidentDetails
