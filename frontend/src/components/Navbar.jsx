import { Link, useNavigate } from 'react-router-dom'

const Navbar = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  
  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    navigate('/login')
  }
  
  return (
    <nav className="navbar">
      <div className="navbar-content">
        <div>
          <Link to="/dashboard">Dashboard</Link>
          <Link to="/events">События</Link>
          <Link to="/nodes">Узлы</Link>
          <Link to="/rules">Правила</Link>
          <Link to="/incidents">Инциденты</Link>
          <Link to="/analytics">Аналитика</Link>
          {['admin', 'security_engineer'].includes(user.role) && (
            <>
              <Link to="/analysis">Анализ</Link>
              <Link to="/dataset">Dataset</Link>
            </>
          )}
          {['admin', 'security_engineer'].includes(user.role) && (
            <Link to="/logs">Журнал</Link>
          )}
        </div>
        <div>
          <span style={{ marginRight: '20px' }}>
            {user.username} ({user.role})
          </span>
          <button onClick={handleLogout} className="btn btn-danger">
            Выход
          </button>
        </div>
      </div>
    </nav>
  )
}

export default Navbar
