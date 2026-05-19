import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { riskLevelLabel } from '../utils/labels'

const Analysis = () => {
  const navigate = useNavigate()
  const [summary, setSummary] = useState(null)
  const [runResult, setRunResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [loadError, setLoadError] = useState('')

  useEffect(() => {
    fetchSummary()
  }, [])

  const fetchSummary = async () => {
    try {
      const response = await api.get('/analytics/summary')
      setSummary(response.data)
      setLoadError('')
    } catch (error) {
      setLoadError('Серверная часть не вернула данные аналитики. Скорее всего, клиентская часть подключена к старому API без /api/analytics.')
      toast.error('Ошибка загрузки аналитики')
    } finally {
      setLoading(false)
    }
  }

  const runAnalysis = async () => {
    setRunning(true)
    try {
      const response = await api.post('/analysis/run')
      setRunResult(response.data)
      toast.success('Анализ выполнен')
      fetchSummary()
    } catch (error) {
      toast.error('Ошибка запуска анализа')
    } finally {
      setRunning(false)
    }
  }

  if (loading) {
    return <div className="loading">Загрузка...</div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Анализ сетевых событий</h1>
        <div className="actions">
          <button className="btn btn-primary" onClick={runAnalysis} disabled={running}>
            {running ? 'Анализ выполняется...' : 'Запустить анализ'}
          </button>
          <button className="btn btn-secondary" onClick={() => navigate('/analysis/alerts')}>
            Корреляционные оповещения
          </button>
        </div>
      </div>

      {loadError && (
        <div className="alert-box alert-error">
          {loadError}
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card stat-info">
          <div className="stat-content">
            <h3>Средний балл риска</h3>
            <p className="stat-value">{summary?.average_risk_score || 0}</p>
          </div>
        </div>
        <div className="stat-card stat-warning">
          <div className="stat-content">
            <h3>Подозрительные события</h3>
            <p className="stat-value">{summary?.suspicious_events || 0}</p>
          </div>
        </div>
        <div className="stat-card stat-danger">
          <div className="stat-content">
            <h3>Критические оповещения</h3>
            <p className="stat-value">{summary?.critical_alerts || 0}</p>
          </div>
        </div>
      </div>

      {runResult && (
        <div className="panel">
          <h2>Результат запуска</h2>
          <div className="summary-line">
            <span>Проанализировано событий: <strong>{runResult.analyzed_events}</strong></span>
            <span>Создано оповещений: <strong>{runResult.alerts_created}</strong></span>
            <span>Обновлено оповещений: <strong>{runResult.alerts_updated}</strong></span>
          </div>
        </div>
      )}

      <div className="dashboard-grid">
        <div className="panel">
          <h2>Распределение уровней риска</h2>
          {['low', 'medium', 'high', 'critical'].map(level => {
            const value = summary?.risk_distribution?.[level] || 0
            const max = Math.max(...Object.values(summary?.risk_distribution || { low: 1 }), 1)
            return (
              <div className="bar-row" key={level}>
                <span className={`badge badge-${level}`}>{riskLevelLabel(level)}</span>
                <div className="bar-track">
                  <div className={`bar-fill bar-${level}`} style={{ width: `${(value / max) * 100}%` }} />
                </div>
                <strong>{value}</strong>
              </div>
            )
          })}
        </div>

        <div className="panel">
          <h2>Топ IP-источников</h2>
          <table className="compact-table">
            <tbody>
              {summary?.top_source_ips?.map(item => (
                <tr key={item.source_ip}>
                  <td>{item.source_ip}</td>
                  <td>{item.events_count}</td>
                  <td>{item.average_risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Analysis
