import { useState, useEffect, useCallback } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'

const extractErrorDetail = (error) => {
  const detail = error.response?.data?.detail
  if (typeof detail === 'string') {
    return { message: detail, retryAfterSeconds: 0, attemptsRemaining: null }
  }
  if (detail && typeof detail === 'object') {
    return {
      message: detail.message || 'Ошибка входа',
      retryAfterSeconds: detail.retry_after_seconds || 0,
      attemptsRemaining: detail.attempts_remaining ?? null,
    }
  }
  return { message: 'Ошибка входа', retryAfterSeconds: 0, attemptsRemaining: null }
}

const Login = () => {
  const navigate = useNavigate()
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  })
  const [loading, setLoading] = useState(false)
  const [lockoutSeconds, setLockoutSeconds] = useState(0)

  const isLocked = lockoutSeconds > 0

  const syncLockoutFromServer = useCallback(async (username) => {
    const normalized = username.trim()
    if (!normalized) {
      setLockoutSeconds(0)
      return
    }

    try {
      const response = await api.get('/auth/login-lockout', {
        params: { username: normalized },
      })
      const { locked, retry_after_seconds: retryAfter } = response.data
      setLockoutSeconds(locked ? retryAfter : 0)
    } catch {
      // Не мешаем входу, если статус блокировки временно недоступен.
    }
  }, [])

  useEffect(() => {
    if (lockoutSeconds <= 0) {
      return undefined
    }

    const timerId = window.setInterval(() => {
      setLockoutSeconds((current) => (current > 1 ? current - 1 : 0))
    }, 1000)

    return () => window.clearInterval(timerId)
  }, [lockoutSeconds > 0])

  useEffect(() => {
    const debounceId = window.setTimeout(() => {
      syncLockoutFromServer(formData.username)
    }, 400)

    return () => window.clearTimeout(debounceId)
  }, [formData.username, syncLockoutFromServer])

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (isLocked) {
      toast.error(`Вход временно заблокирован. Подождите ${lockoutSeconds} с.`)
      return
    }

    setLoading(true)

    try {
      const response = await api.post('/auth/login', formData)
      const { access_token, user } = response.data
      
      localStorage.setItem('token', access_token)
      localStorage.setItem('user', JSON.stringify(user))
      
      toast.success('Вход выполнен успешно')
      navigate('/dashboard')
    } catch (error) {
      const { message, retryAfterSeconds, attemptsRemaining } = extractErrorDetail(error)

      if (error.response?.status === 429 && retryAfterSeconds > 0) {
        setLockoutSeconds(retryAfterSeconds)
        toast.error(message)
      } else {
        if (attemptsRemaining !== null && attemptsRemaining > 0) {
          toast.error(`${message} (осталось попыток: ${attemptsRemaining})`)
        } else {
          toast.error(message)
        }
        await syncLockoutFromServer(formData.username)
      }
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
            <p>Контроль риска, корреляция оповещений и регистрация инцидентов в едином рабочем интерфейсе.</p>
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
                disabled={isLocked || loading}
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
                disabled={isLocked || loading}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary auth-submit"
              disabled={loading || isLocked}
            >
              {loading ? 'Вход...' : isLocked ? `Заблокировано (${lockoutSeconds} с)` : 'Войти'}
            </button>

            {isLocked && (
              <p className="auth-lockout-timer" role="status" aria-live="polite">
                Слишком много неверных попыток. Повторный вход через{' '}
                <strong>{lockoutSeconds}</strong> с
              </p>
            )}
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
