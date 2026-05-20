import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'

const parseStatusCode = (value) => {
  const parsed = Number.parseInt(value, 10)
  return Number.isNaN(parsed) ? 500 : parsed
}

const ErrorPage = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()

  const statusCode = location.state?.error?.status || parseStatusCode(searchParams.get('status'))
  const message = location.state?.error?.message || searchParams.get('message') || 'Произошла ошибка'
  const errorCode = location.state?.error?.code || searchParams.get('code')
  const from = location.state?.from || searchParams.get('from') || '/dashboard'

  const getErrorTitle = (code) => {
    switch (code) {
      case 400:
        return 'Неверный запрос'
      case 401:
        return 'Требуется вход'
      case 403:
        return 'Доступ запрещен'
      case 404:
        return 'Ресурс не найден'
      case 409:
        return 'Конфликт данных'
      case 422:
        return 'Ошибка валидации'
      case 429:
        return 'Слишком много запросов'
      case 500:
        return 'Ошибка сервера'
      case 503:
        return 'Сервис недоступен'
      default:
        return 'Ошибка'
    }
  }

  const getErrorDescription = (code) => {
    switch (code) {
      case 400:
        return 'Сервер отклонил запрос из-за некорректных данных.'
      case 401:
        return 'Сессия истекла или пользователь не авторизован.'
      case 403:
        return 'У текущей роли нет прав на это действие или раздел.'
      case 404:
        return 'Запрошенный объект или маршрут не найден.'
      case 409:
        return 'Действие конфликтует с уже существующими данными.'
      case 422:
        return 'Проверьте заполненные поля и повторите действие.'
      case 429:
        return 'Сработало ограничение частоты запросов.'
      case 500:
        return 'На стороне сервера произошла внутренняя ошибка.'
      case 503:
        return 'Сервер временно недоступен или соединение прервано.'
      default:
        return 'Произошла непредвиденная ошибка.'
    }
  }

  const goToDashboard = () => {
    navigate('/dashboard', { replace: true })
  }

  const goToLogin = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    navigate('/login', { replace: true })
  }

  const retrySourcePage = () => {
    window.location.assign(from)
  }

  return (
    <main className="error-page" role="alert" aria-live="assertive">
      <section className="error-panel">
        <p className="error-eyebrow">Системное сообщение</p>

        <div className="error-code">{statusCode}</div>

        <h1>{getErrorTitle(statusCode)}</h1>
        <p className="error-description">{getErrorDescription(statusCode)}</p>

        {message && message !== getErrorDescription(statusCode) && (
          <div className="error-details">
            <span>Детали</span>
            <p>{message}</p>
          </div>
        )}

        <dl className="error-meta">
          <div>
            <dt>Маршрут</dt>
            <dd>{from}</dd>
          </div>
          {errorCode && (
            <div>
              <dt>Код API</dt>
              <dd>{errorCode}</dd>
            </div>
          )}
        </dl>

        <div className="error-actions">
          <button className="btn btn-primary" onClick={goToDashboard}>
            На панель
          </button>

          <button className="btn btn-secondary" onClick={retrySourcePage}>
            Повторить
          </button>

          {statusCode === 401 || statusCode === 403 ? (
            <button className="btn btn-danger" onClick={goToLogin}>
              Войти другим пользователем
            </button>
          ) : null}
        </div>
      </section>
    </main>
  )
}

export default ErrorPage
