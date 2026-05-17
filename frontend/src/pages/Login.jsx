import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Login = () => {
  const navigate = useNavigate()
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  })
  const [loading, setLoading] = useState(false)

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
      const response = await api.post('/auth/login', formData)
      const { access_token, user } = response.data
      
      localStorage.setItem('token', access_token)
      localStorage.setItem('user', JSON.stringify(user))
      
      toast.success('Вход выполнен успешно')
      navigate('/dashboard')
    } catch (error) {
      const message = error.response?.data?.detail || 'Ошибка входа'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-container">
      <div className="auth-shell">
        <section className="auth-visual">
          <div className="auth-brand">
            <span className="auth-brand-mark">NS</span>
            <span>Сетевая безопасность</span>
          </div>
          <div className="auth-visual-content">
            <p className="auth-eyebrow">РГР · сеть связи</p>
            <h1>Система анализа сетевых событий</h1>
            <p>Контроль риска, корреляция alert и регистрация инцидентов в едином рабочем интерфейсе.</p>
          </div>
          <div className="auth-metrics">
            <div>
              <span>оценка риска</span>
              <strong>0-100</strong>
            </div>
            <div>
              <span>корреляция</span>
              <strong>активна</strong>
            </div>
            <div>
              <span>доступ</span>
              <strong>3 роли</strong>
            </div>
          </div>
        </section>

        <section className="auth-card">
          <div className="auth-card-header">
            <p className="auth-eyebrow">Авторизация</p>
            <h2>Вход в систему</h2>
            <p className="auth-subtitle">Введите учетные данные для доступа к панели мониторинга.</p>
          </div>
          
          <form onSubmit={handleSubmit} className="auth-form">
            <div className="form-group">
              <label htmlFor="username">Имя пользователя</label>
              <input
                type="text"
                id="username"
                name="username"
                value={formData.username}
                onChange={handleChange}
                required
                autoFocus
                placeholder="engineer"
              />
            </div>

            <div className="form-group">
              <label htmlFor="password">Пароль</label>
              <input
                type="password"
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                placeholder="••••••••"
              />
            </div>

            <button type="submit" className="btn btn-primary auth-submit" disabled={loading}>
              {loading ? 'Вход...' : 'Войти'}
            </button>
          </form>

          <p className="auth-link">
            Нет аккаунта? <Link to="/register">Зарегистрироваться</Link>
          </p>
        </section>
      </div>
    </div>
  )
}

export default Login
