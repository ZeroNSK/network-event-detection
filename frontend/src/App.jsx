import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import EventForm from './pages/EventForm'
import EventDetails from './pages/EventDetails'
import Nodes from './pages/Nodes'
import NodeForm from './pages/NodeForm'
import Rules from './pages/Rules'
import RuleForm from './pages/RuleForm'
import Incidents from './pages/Incidents'
import IncidentForm from './pages/IncidentForm'
import IncidentEdit from './pages/IncidentEdit'
import IncidentDetails from './pages/IncidentDetails'
import Logs from './pages/Logs'
import Analysis from './pages/Analysis'
import AnalysisAlerts from './pages/AnalysisAlerts'
import AnalysisAlertDetails from './pages/AnalysisAlertDetails'
import Analytics from './pages/Analytics'
import Dataset from './pages/Dataset'
import ErrorPage from './pages/ErrorPage'
import ProtectedRoute from './routes/ProtectedRoute'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/error" element={<ErrorPage />} />
        
        <Route element={<ProtectedRoute />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          
          <Route path="/nodes" element={<Nodes />} />
          <Route path="/nodes/new" element={<NodeForm />} />
          <Route path="/nodes/:id/edit" element={<NodeForm />} />
          
          <Route path="/events" element={<Events />} />
          <Route path="/events/new" element={<EventForm />} />
          <Route path="/events/:id" element={<EventDetails />} />
          <Route path="/events/:id/edit" element={<EventForm />} />
          
          <Route path="/rules" element={<Rules />} />
          <Route path="/rules/new" element={<RuleForm />} />
          <Route path="/rules/:id/edit" element={<RuleForm />} />
          
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/new" element={<IncidentForm />} />
          <Route path="/incidents/:id" element={<IncidentDetails />} />
          <Route path="/incidents/:id/edit" element={<IncidentEdit />} />
          
          <Route path="/analysis" element={<Analysis />} />
          <Route path="/analysis/alerts" element={<AnalysisAlerts />} />
          <Route path="/analysis/alerts/:id" element={<AnalysisAlertDetails />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/dataset" element={<Dataset />} />
          
          <Route path="/logs" element={<Logs />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
