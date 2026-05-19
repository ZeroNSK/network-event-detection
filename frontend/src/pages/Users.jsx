import { useEffect, useState } from 'react'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { roleLabel } from '../utils/labels'

const Users = () => {
  const currentUser = JSON.parse(localStorage.getItem('user') || '{}')
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [savingId, setSavingId] = useState(null)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const limit = 20

  useEffect(() => {
    fetchUsers()
  }, [page])

  const fetchUsers = async () => {
    setLoading(true)
    try {
      const response = await api.get('/auth/users', { params: { page, limit } })
      setUsers(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      toast.error('Ошибка загрузки пользователей')
    } finally {
      setLoading(false)
    }
  }

  const updateUser = async (targetUser, patch) => {
    setSavingId(targetUser.id)
    try {
      const response = await api.put(`/auth/users/${targetUser.id}`, patch)
      setUsers(items => items.map(item => (item.id === targetUser.id ? response.data : item)))
      toast.success('Пользователь обновлен')
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Ошибка обновления пользователя')
    } finally {
      setSavingId(null)
    }
  }

  const deactivateUser = async (targetUser) => {
    if (!window.confirm(`Отключить учетную запись ${targetUser.username}?`)) return

    setSavingId(targetUser.id)
    try {
      const response = await api.delete(`/auth/users/${targetUser.id}`)
      setUsers(items => items.map(item => (item.id === targetUser.id ? response.data : item)))
      toast.success('Учетная запись отключена')
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Ошибка отключения пользователя')
    } finally {
      setSavingId(null)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / limit))

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Пользователи</h1>
      </div>

      {loading ? (
        <div className="loading">Загрузка...</div>
      ) : (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Имя</th>
                <th>Email</th>
                <th>Роль</th>
                <th>Статус</th>
                <th>Создан</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {users.map(user => {
                const isSelf = user.id === currentUser.id
                const disabled = savingId === user.id || isSelf

                return (
                  <tr key={user.id}>
                    <td>{user.id}</td>
                    <td>{user.username}</td>
                    <td>{user.email}</td>
                    <td>
                      <select
                        value={user.role}
                        disabled={disabled}
                        onChange={(event) => updateUser(user, { role: event.target.value })}
                      >
                        <option value="admin">{roleLabel('admin')}</option>
                        <option value="security_engineer">{roleLabel('security_engineer')}</option>
                        <option value="operator">{roleLabel('operator')}</option>
                      </select>
                    </td>
                    <td>
                      <span className={`badge ${user.is_active ? 'badge-success' : 'badge-danger'}`}>
                        {user.is_active ? 'Активен' : 'Отключен'}
                      </span>
                    </td>
                    <td>{new Date(user.created_at).toLocaleString('ru-RU')}</td>
                    <td>
                      {user.is_active ? (
                        <button
                          className="btn btn-sm btn-danger"
                          disabled={disabled}
                          onClick={() => deactivateUser(user)}
                        >
                          Отключить
                        </button>
                      ) : (
                        <button
                          className="btn btn-sm btn-secondary"
                          disabled={savingId === user.id}
                          onClick={() => updateUser(user, { is_active: true })}
                        >
                          Включить
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
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

export default Users
