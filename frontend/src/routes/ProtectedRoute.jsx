import { Navigate, Outlet } from 'react-router-dom'
import Navbar from '../components/Navbar'

const ProtectedRoute = () => {
  const token = localStorage.getItem('token')
  
  if (!token) {
    return <Navigate to="/login" replace />
  }
  
  return (
    <div className="app-shell">
      <Navbar />
      <main className="app-main">
        <Outlet />
      </main>
    </div>
  )
}

export default ProtectedRoute
