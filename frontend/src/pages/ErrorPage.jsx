import { useNavigate, useLocation, useSearchParams } from 'react-router-dom'

const ErrorPage = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()
  
  // Получаем информацию об ошибке из состояния страницы или параметров запроса.
  const statusFromState = location.state?.error?.status
  const messageFromState = location.state?.error?.message
  
  const statusFromQuery = searchParams.get('status')
  const messageFromQuery = searchParams.get('message')
  
  const statusCode = statusFromState || parseInt(statusFromQuery) || 500
  const message = messageFromState || messageFromQuery || 'Произошла ошибка'
  const from = location.state?.from || '/dashboard'
  
  const getErrorTitle = (code) => {
    switch (code) {
      case 400:
        return 'Неверный запрос'
      case 401:
        return 'Не авторизован'
      case 403:
        return 'Доступ запрещен'
      case 404:
        return 'Не найдено'
      case 409:
        return 'Конфликт данных'
      case 500:
        return 'Ошибка сервера'
      default:
        return 'Ошибка'
    }
  }
  
  const getErrorDescription = (code) => {
    switch (code) {
      case 400:
        return 'Запрос содержит неверные данные'
      case 401:
        return 'Необходима авторизация для доступа к этой странице'
      case 403:
        return 'У вас недостаточно прав для выполнения этого действия'
      case 404:
        return 'Запрашиваемый ресурс не найден'
      case 409:
        return 'Данные конфликтуют с существующими записями'
      case 500:
        return 'Внутренняя ошибка сервера'
      default:
        return 'Произошла непредвиденная ошибка'
    }
  }
  
  return (
    <div className="page-container" style={{ 
      display: 'flex', 
      flexDirection: 'column', 
      alignItems: 'center', 
      justifyContent: 'center',
      minHeight: '60vh',
      textAlign: 'center'
    }}>
      <div style={{ 
        maxWidth: '600px', 
        padding: '40px',
        backgroundColor: '#f8f9fa',
        borderRadius: '8px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
      }}>
        <h1 style={{ 
          fontSize: '72px', 
          margin: '0 0 20px 0',
          color: '#dc3545'
        }}>
          {statusCode}
        </h1>
        
        <h2 style={{ 
          fontSize: '32px', 
          margin: '0 0 20px 0',
          color: '#333'
        }}>
          {getErrorTitle(statusCode)}
        </h2>
        
        <p style={{ 
          fontSize: '18px', 
          margin: '0 0 10px 0',
          color: '#666'
        }}>
          {getErrorDescription(statusCode)}
        </p>
        
        {message && message !== getErrorDescription(statusCode) && (
          <p style={{ 
            fontSize: '16px', 
            margin: '20px 0',
            padding: '15px',
            backgroundColor: '#fff',
            borderRadius: '4px',
            color: '#555',
            fontStyle: 'italic'
          }}>
            {message}
          </p>
        )}
        
        <div style={{ marginTop: '30px', display: 'flex', gap: '10px', justifyContent: 'center' }}>
          <button 
            className="btn btn-primary"
            onClick={() => navigate(-1)}
            style={{ minWidth: '120px' }}
          >
            ← Назад
          </button>
          
          <button 
            className="btn btn-secondary"
            onClick={() => navigate('/dashboard')}
            style={{ minWidth: '120px' }}
          >
            На главную
          </button>
        </div>
      </div>
    </div>
  )
}

export default ErrorPage
