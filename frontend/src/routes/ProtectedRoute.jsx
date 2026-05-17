import { Navigate, Outlet } from 'react-router-dom'
import Navbar from '../components/Navbar'

const ProtectedRoute = () => {
  const token = localStorage.getItem('token')
  
  if (!token) {
    return <Navigate to="/login" replace />
  }
  
  return (
    <>
      <Navbar />
      <div className="container">
        <Outlet />
      </div>
    </>
  )
}

export default ProtectedRoute
