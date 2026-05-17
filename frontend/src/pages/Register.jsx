import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Register = () => {
  const navigate = useNavigate()
  const [formData, setFormData] = useState({
    username: '',
    email: '',
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
      await api.post('/auth/register', formData)
      toast.success('Регистрация успешна! Войдите в систему')
      navigate('/login')
    } catch (error) {
      const message = error.response?.data?.detail || 'Ошибка регистрации'
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
            <h1>Регистрация участника мониторинга</h1>
            <p>Новая учетная запись создается с ролью оператора и может быть расширена администратором.</p>
          </div>
          <div className="auth-metrics">
            <div>
              <span>администратор</span>
              <strong>полный доступ</strong>
            </div>
            <div>
              <span>инженер</span>
              <strong>анализ</strong>
            </div>
            <div>
              <span>оператор</span>
              <strong>события</strong>
            </div>
          </div>
        </section>

        <section className="auth-card">
          <div className="auth-card-header">
            <p className="auth-eyebrow">Новая учетная запись</p>
            <h2>Регистрация</h2>
            <p className="auth-subtitle">Заполните данные пользователя для входа в систему.</p>
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
                placeholder="operator"
              />
            </div>

            <div className="form-group">
              <label htmlFor="email">Email</label>
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                placeholder="operator@telecom.local"
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
                minLength="6"
                placeholder="Не менее 6 символов"
              />
            </div>

            <button type="submit" className="btn btn-primary auth-submit" disabled={loading}>
              {loading ? 'Регистрация...' : 'Зарегистрироваться'}
            </button>
          </form>

          <p className="auth-link">
            Уже есть аккаунт? <Link to="/login">Войти</Link>
          </p>
        </section>
      </div>
    </div>
  )
}

export default Register
