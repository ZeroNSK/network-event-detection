import { NavLink, useNavigate } from 'react-router-dom'
import { roleLabel } from '../utils/labels'

const Navbar = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const canUseSecurityTools = ['admin', 'security_engineer'].includes(user.role)

  const navGroups = [
    {
      title: 'Операции',
      items: [
        { to: '/dashboard', label: 'Панель' },
        { to: '/events', label: 'События' },
        { to: '/incidents', label: 'Инциденты' },
        { to: '/analytics', label: 'Аналитика' }
      ]
    },
    {
      title: 'Инфраструктура',
      items: [
        { to: '/nodes', label: 'Узлы' },
        { to: '/rules', label: 'Правила' }
      ]
    },
    {
      title: 'Расследования',
      items: [
        { to: '/analysis', label: 'Анализ', hidden: !canUseSecurityTools },
        { to: '/dataset', label: 'Набор данных', hidden: !canUseSecurityTools },
        { to: '/logs', label: 'Журнал', hidden: !canUseSecurityTools },
        { to: '/users', label: 'Пользователи', hidden: user.role !== 'admin' }
      ]
    }
  ]
  
  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    navigate('/login')
  }
  
  return (
    <aside className="app-sidebar">
      <div className="app-brand">
        <span className="app-brand-mark">NS</span>
        <div>
          <strong>NetSec RGR</strong>
          <span>Security operations</span>
        </div>
      </div>

      <div className="app-user">
        <span>{user.username}</span>
        <strong>{roleLabel(user.role)}</strong>
      </div>

      <nav className="app-nav" aria-label="Основная навигация">
        {navGroups.map(group => {
          const visibleItems = group.items.filter(item => !item.hidden)
          if (!visibleItems.length) return null

          return (
            <div className="app-nav-group" key={group.title}>
              <p>{group.title}</p>
              {visibleItems.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => `app-nav-link${isActive ? ' active' : ''}`}
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          )
        })}
      </nav>

      <button onClick={handleLogout} className="btn btn-danger app-logout">
        Выход
      </button>
    </aside>
  )
}

export default Navbar
