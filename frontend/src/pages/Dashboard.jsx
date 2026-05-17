import { useState, useEffect } from 'react'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Dashboard = () => {
  const [stats, setStats] = useState({
    total_events: 0,
    suspicious_events: 0,
    critical_events: 0,
    active_incidents: 0,
    average_risk_score: 0,
    critical_alerts: 0,
    risk_distribution: {},
    top_source_ips: [],
    top_event_types: [],
    warningNodes: 0,
    offlineNodes: 0
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchStats()
  }, [])

  const fetchStats = async () => {
    try {
      const [
        summaryRes,
        warningNodesRes,
        offlineNodesRes
      ] = await Promise.all([
        api.get('/analytics/summary'),
        api.get('/nodes?status=warning&limit=1'),
        api.get('/nodes?status=offline&limit=1')
      ])

      setStats({
        ...summaryRes.data,
        warningNodes: warningNodesRes.data.total,
        offlineNodes: offlineNodesRes.data.total
      })
    } catch (error) {
      toast.error('Ошибка загрузки статистики')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="loading">Загрузка...</div>
  }

  return (
    <div className="dashboard">
      <h1>Панель мониторинга</h1>
      
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <h3>Всего событий</h3>
            <p className="stat-value">{stats.total_events}</p>
          </div>
        </div>

        <div className="stat-card stat-warning">
          <div className="stat-icon">⚠️</div>
          <div className="stat-content">
            <h3>Подозрительные события</h3>
            <p className="stat-value">{stats.suspicious_events}</p>
          </div>
        </div>

        <div className="stat-card stat-danger">
          <div className="stat-icon">🔴</div>
          <div className="stat-content">
            <h3>Критические события</h3>
            <p className="stat-value">{stats.critical_events}</p>
          </div>
        </div>

        <div className="stat-card stat-info">
          <div className="stat-icon">🎯</div>
          <div className="stat-content">
            <h3>Активные инциденты</h3>
            <p className="stat-value">{stats.active_incidents}</p>
          </div>
        </div>

        <div className="stat-card stat-info">
          <div className="stat-icon">R</div>
          <div className="stat-content">
            <h3>Средний risk_score</h3>
            <p className="stat-value">{stats.average_risk_score}</p>
          </div>
        </div>

        <div className="stat-card stat-danger">
          <div className="stat-icon">A</div>
          <div className="stat-content">
            <h3>Critical alerts</h3>
            <p className="stat-value">{stats.critical_alerts}</p>
          </div>
        </div>

        <div className="stat-card stat-warning">
          <div className="stat-icon">⚡</div>
          <div className="stat-content">
            <h3>Узлы в состоянии Warning</h3>
            <p className="stat-value">{stats.warningNodes}</p>
          </div>
        </div>

        <div className="stat-card stat-danger">
          <div className="stat-icon">❌</div>
          <div className="stat-content">
            <h3>Узлы Offline</h3>
            <p className="stat-value">{stats.offlineNodes}</p>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="panel">
          <h2>Распределение риска</h2>
          {['low', 'medium', 'high', 'critical'].map(level => {
            const value = stats.risk_distribution?.[level] || 0
            const max = Math.max(...Object.values(stats.risk_distribution || { low: 1 }), 1)
            return (
              <div className="bar-row" key={level}>
                <span className={`badge badge-${level}`}>{level}</span>
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
              {stats.top_source_ips?.map(item => (
                <tr key={item.source_ip}>
                  <td>{item.source_ip}</td>
                  <td>{item.events_count}</td>
                  <td>{item.average_risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Топ типов событий</h2>
          <table className="compact-table">
            <tbody>
              {stats.top_event_types?.map(item => (
                <tr key={item.event_type}>
                  <td>{item.event_type}</td>
                  <td>{item.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
