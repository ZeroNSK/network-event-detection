import { useEffect, useState } from 'react'
import { toast } from 'react-toastify'
import api from '../api/axios'
import { eventTypeLabel, riskLevelLabel } from '../utils/labels'

const emptySummary = {
  total_events: 0,
  suspicious_events: 0,
  total_incidents: 0,
  active_incidents: 0,
  critical_events: 0,
  critical_alerts: 0,
  average_risk_score: 0,
  events_last_24h: 0,
  alerts_last_24h: 0,
  top_source_ips: [],
  top_event_types: [],
  top_nodes_by_events: [],
  risk_distribution: {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  }
}

const Analytics = () => {
  const [summary, setSummary] = useState(emptySummary)
  const [timeline, setTimeline] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')

  useEffect(() => {
    fetchAnalytics()
  }, [])

  const fetchAnalytics = async () => {
    try {
      const [summaryRes, timelineRes] = await Promise.all([
        api.get('/analytics/summary'),
        api.get('/analytics/timeline')
      ])
      setSummary(summaryRes.data)
      setTimeline(timelineRes.data.slice(-24))
      setLoadError('')
    } catch (error) {
      setSummary(emptySummary)
      setTimeline([])
      setLoadError('Серверная часть не вернула данные аналитики. Проверьте, что она пересобрана и содержит маршруты /api/analytics.')
      toast.error('Ошибка загрузки аналитики')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="loading">Загрузка...</div>
  }

  const riskDistribution = summary?.risk_distribution || {}
  const maxRisk = Math.max(...Object.values(riskDistribution), 1)
  const maxTimeline = Math.max(...timeline.map(item => item.events_count), 1)

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <p className="page-kicker">Risk intelligence</p>
          <h1>Аналитика</h1>
          <p className="page-description">Тренды, источники и распределение риска для оперативной оценки состояния сети.</p>
        </div>
      </div>

      {loadError && (
        <div className="alert-box alert-error">
          {loadError}
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card"><div className="stat-content"><h3>Всего событий</h3><p className="stat-value">{summary.total_events}</p></div></div>
        <div className="stat-card stat-warning"><div className="stat-content"><h3>Подозрительные</h3><p className="stat-value">{summary.suspicious_events}</p></div></div>
        <div className="stat-card stat-info"><div className="stat-content"><h3>Средний балл риска</h3><p className="stat-value">{summary.average_risk_score}</p></div></div>
        <div className="stat-card stat-danger"><div className="stat-content"><h3>Критические оповещения</h3><p className="stat-value">{summary.critical_alerts}</p></div></div>
        <div className="stat-card"><div className="stat-content"><h3>События за 24 часа</h3><p className="stat-value">{summary.events_last_24h}</p></div></div>
        <div className="stat-card"><div className="stat-content"><h3>Оповещения за 24 часа</h3><p className="stat-value">{summary.alerts_last_24h}</p></div></div>
      </div>

      <div className="dashboard-grid">
        <div className="panel">
          <h2>Распределение риска</h2>
          {['low', 'medium', 'high', 'critical'].map(level => (
            <div className="bar-row" key={level}>
              <span className={`badge badge-${level}`}>{riskLevelLabel(level)}</span>
              <div className="bar-track">
                <div className={`bar-fill bar-${level}`} style={{ width: `${((riskDistribution[level] || 0) / maxRisk) * 100}%` }} />
              </div>
              <strong>{riskDistribution[level] || 0}</strong>
            </div>
          ))}
        </div>

        <div className="panel">
          <h2>Топ IP-источников</h2>
          <table className="compact-table">
            <thead><tr><th>IP</th><th>События</th><th>Средний риск</th></tr></thead>
            <tbody>
              {summary.top_source_ips.length ? (
                summary.top_source_ips.map(item => (
                  <tr key={item.source_ip}>
                    <td className="mono-cell">{item.source_ip}</td>
                    <td>{item.events_count}</td>
                    <td>{item.average_risk_score}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan="3" className="empty-table-cell">Нет событий для ранжирования источников.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Топ типов событий</h2>
          <table className="compact-table">
            <thead><tr><th>Тип</th><th>Количество</th></tr></thead>
            <tbody>
              {summary.top_event_types.length ? (
                summary.top_event_types.map(item => (
                  <tr key={item.event_type}>
                    <td>{eventTypeLabel(item.event_type)}</td>
                    <td>{item.count}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan="2" className="empty-table-cell">Типы событий появятся после регистрации трафика.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Топ узлов по событиям</h2>
          <table className="compact-table">
            <thead><tr><th>Узел</th><th>События</th></tr></thead>
            <tbody>
              {summary.top_nodes_by_events.length ? (
                summary.top_nodes_by_events.map(item => (
                  <tr key={item.node_id}>
                    <td>{item.node_name}</td>
                    <td>{item.events_count}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan="2" className="empty-table-cell">Узлы появятся после привязки событий к инфраструктуре.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel mt-20">
        <div className="panel-header">
          <div>
            <h2>Динамика событий по времени</h2>
            <p>Сравнение общего потока, подозрительных событий и корреляционных оповещений.</p>
          </div>
          <div className="chart-legend">
            <span><i className="legend-events" /> события</span>
            <span><i className="legend-suspicious" /> подозрительные</span>
            <span><i className="legend-alerts" /> оповещения</span>
          </div>
        </div>
        {timeline.length ? (
          <div className="timeline-chart">
            {timeline.map(item => (
              <div className="timeline-column" key={item.period} title={item.period}>
                <div className="timeline-bars">
                  <span className="timeline-bar events" style={{ height: `${(item.events_count / maxTimeline) * 120}px` }} />
                  <span className="timeline-bar suspicious" style={{ height: `${(item.suspicious_count / maxTimeline) * 120}px` }} />
                  <span className="timeline-bar alerts" style={{ height: `${(item.alerts_count / maxTimeline) * 120}px` }} />
                </div>
                <small>{item.period.slice(11)}</small>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state compact-empty">
            <h2>Нет данных временной шкалы</h2>
            <p>После появления событий здесь будет видна динамика активности и всплески риска.</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default Analytics
