import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { eventTypeLabel, riskLevelLabel } from '../utils/labels'

const Dashboard = () => {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')
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

  const attentionTotal = (stats.critical_alerts || 0) + (stats.critical_events || 0) + (stats.active_incidents || 0) + (stats.warningNodes || 0) + (stats.offlineNodes || 0)
  const canOpenAlerts = ['admin', 'security_engineer'].includes(user.role)
  const attentionRoute = canOpenAlerts ? '/analysis/alerts' : '/events'

  return (
    <div className="dashboard">
      <div className="page-header">
        <div>
          <p className="page-kicker">SOC overview</p>
          <h1>Панель мониторинга</h1>
          <p className="page-description">Краткая картина риска, подозрительных событий и инцидентов в инфраструктуре.</p>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/events/new')}>
          Создать событие
        </button>
      </div>
      
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">EV</div>
          <div className="stat-content">
            <h3>Всего событий</h3>
            <p className="stat-value">{stats.total_events}</p>
          </div>
        </div>

        <div className="stat-card stat-warning">
          <div className="stat-icon">RS</div>
          <div className="stat-content">
            <h3>Подозрительные события</h3>
            <p className="stat-value">{stats.suspicious_events}</p>
          </div>
        </div>

        <div className="stat-card stat-danger">
          <div className="stat-icon">CR</div>
          <div className="stat-content">
            <h3>Критические события</h3>
            <p className="stat-value">{stats.critical_events}</p>
          </div>
        </div>

        <div className="stat-card stat-info">
          <div className="stat-icon">IR</div>
          <div className="stat-content">
            <h3>Активные инциденты</h3>
            <p className="stat-value">{stats.active_incidents}</p>
          </div>
        </div>

        <div className="stat-card stat-info">
          <div className="stat-icon">R</div>
          <div className="stat-content">
            <h3>Средний балл риска</h3>
            <p className="stat-value">{stats.average_risk_score}</p>
          </div>
        </div>

        <div className="stat-card stat-danger">
          <div className="stat-icon">AL</div>
          <div className="stat-content">
            <h3>Критические оповещения</h3>
            <p className="stat-value">{stats.critical_alerts}</p>
          </div>
        </div>

        <div className="stat-card stat-warning">
          <div className="stat-icon">NW</div>
          <div className="stat-content">
            <h3>Узлы требуют внимания</h3>
            <p className="stat-value">{stats.warningNodes}</p>
          </div>
        </div>

        <div className="stat-card stat-danger">
          <div className="stat-icon">OFF</div>
          <div className="stat-content">
            <h3>Недоступные узлы</h3>
            <p className="stat-value">{stats.offlineNodes}</p>
          </div>
        </div>
      </div>

      <section className={`attention-panel ${attentionTotal ? 'attention-panel-active' : ''}`}>
        <div>
          <p className="page-kicker">Needs attention</p>
          <h2>{attentionTotal ? 'Есть активные сигналы для проверки' : 'Критичных сигналов сейчас нет'}</h2>
          <p>
            {attentionTotal
              ? 'Начните с критических оповещений, активных инцидентов и недоступных узлов.'
              : 'Риск остается под контролем. Продолжайте мониторинг новых сетевых событий.'}
          </p>
        </div>
        <div className="attention-metrics">
          <span><strong>{stats.critical_alerts || 0}</strong> крит. оповещений</span>
          <span><strong>{stats.active_incidents || 0}</strong> активных инцидентов</span>
          <span><strong>{stats.offlineNodes || 0}</strong> недоступных узлов</span>
        </div>
        <button className="btn btn-secondary" onClick={() => navigate(attentionRoute)}>
          Открыть очередь
        </button>
      </section>

      <div className="dashboard-grid">
        <div className="panel">
          <h2>Распределение риска</h2>
          {['low', 'medium', 'high', 'critical'].map(level => {
            const value = stats.risk_distribution?.[level] || 0
            const max = Math.max(...Object.values(stats.risk_distribution || { low: 1 }), 1)
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
              {stats.top_source_ips?.length ? (
                stats.top_source_ips.map(item => (
                  <tr key={item.source_ip}>
                    <td className="mono-cell">{item.source_ip}</td>
                    <td>{item.events_count}</td>
                    <td>{item.average_risk_score}</td>
                  </tr>
                ))
              ) : (
                <tr><td className="empty-table-cell">IP-источники появятся после регистрации событий.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Топ типов событий</h2>
          <table className="compact-table">
            <tbody>
              {stats.top_event_types?.length ? (
                stats.top_event_types.map(item => (
                  <tr key={item.event_type}>
                    <td>{eventTypeLabel(item.event_type)}</td>
                    <td>{item.count}</td>
                  </tr>
                ))
              ) : (
                <tr><td className="empty-table-cell">Типы событий появятся после импорта или ручного ввода.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
