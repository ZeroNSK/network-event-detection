import { useEffect, useState } from 'react'
import { toast } from 'react-toastify'
import api from '../api/axios'

const Dataset = () => {
  const [file, setFile] = useState(null)
  const [importedEvents, setImportedEvents] = useState([])
  const [recentEvents, setRecentEvents] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchRecentEvents()
  }, [])

  const fetchRecentEvents = async () => {
    try {
      const response = await api.get('/events?limit=10')
      setRecentEvents(response.data.items)
    } catch (error) {
      toast.error('Ошибка загрузки последних событий')
    }
  }

  const importDataset = async (e) => {
    e.preventDefault()
    if (!file) {
      toast.error('Выберите CSV-файл')
      return
    }

    const data = new FormData()
    data.append('file', file)
    setLoading(true)
    try {
      const response = await api.post('/dataset/import', data, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      setImportedEvents(response.data.events)
      toast.success(`Импортировано событий: ${response.data.imported}`)
      fetchRecentEvents()
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Ошибка импорта dataset')
    } finally {
      setLoading(false)
    }
  }

  const downloadFile = async (url, filename) => {
    try {
      const response = await api.get(url, { responseType: 'blob' })
      const blobUrl = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = blobUrl
      link.setAttribute('download', filename)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(blobUrl)
    } catch (error) {
      toast.error('Ошибка скачивания файла')
    }
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Dataset</h1>
      </div>

      <div className="dashboard-grid">
        <div className="panel">
          <h2>Импорт CSV</h2>
          <form onSubmit={importDataset} className="dataset-form">
            <input type="file" accept=".csv,text/csv" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Импорт...' : 'Импортировать'}
            </button>
          </form>
        </div>

        <div className="panel">
          <h2>Экспорт</h2>
          <div className="actions">
            <button className="btn btn-secondary" onClick={() => downloadFile('/dataset/sample', 'sample_network_events.csv')}>
              Скачать пример CSV
            </button>
            <button className="btn btn-info" onClick={() => downloadFile('/dataset/export/events', 'network_events_export.csv')}>
              Экспорт событий
            </button>
            <button className="btn btn-info" onClick={() => downloadFile('/dataset/export/incidents', 'incidents_export.csv')}>
              Экспорт инцидентов
            </button>
          </div>
        </div>
      </div>

      {importedEvents.length > 0 && (
        <div className="panel mt-20">
          <h2>Последний импорт</h2>
          <table className="compact-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Источник</th>
                <th>Назначение</th>
                <th>Тип</th>
                <th>Risk</th>
                <th>Risk level</th>
              </tr>
            </thead>
            <tbody>
              {importedEvents.map(event => (
                <tr key={event.id}>
                  <td>{event.id}</td>
                  <td>{event.source_ip}</td>
                  <td>{event.destination_ip}</td>
                  <td>{event.event_type}</td>
                  <td>{event.risk_score}</td>
                  <td><span className={`badge badge-${event.risk_level}`}>{event.risk_level}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel mt-20">
        <h2>Последние события</h2>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Источник</th>
              <th>Назначение</th>
              <th>Тип</th>
              <th>Risk</th>
              <th>Создано</th>
            </tr>
          </thead>
          <tbody>
            {recentEvents.map(event => (
              <tr key={event.id}>
                <td>{event.id}</td>
                <td>{event.source_ip}</td>
                <td>{event.destination_ip}</td>
                <td>{event.event_type}</td>
                <td><span className={`badge badge-${event.risk_level}`}>{event.risk_score}</span></td>
                <td>{new Date(event.created_at).toLocaleString('ru-RU')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default Dataset
