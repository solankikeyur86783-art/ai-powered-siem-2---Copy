import { useState, useEffect } from 'react'
import Icon from '../components/Icons.jsx'
import { honeypotApi } from '../services/api.js'

const sevColor = { CRITICAL: 'var(--r)', HIGH: 'var(--o)', MEDIUM: 'var(--y)', LOW: 'var(--g)' }

export default function HoneypotPage() {
  const [tab, setTab] = useState('hits')
  const [captures, setCaptures] = useState([])
  const [status, setStatus] = useState({})
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(null)

  const fetchData = async () => {
    setLoading(true)
    try {
      const [capData, statusData, statsData] = await Promise.all([
        honeypotApi.captures(24),
        honeypotApi.status(),
        honeypotApi.stats(24),
      ])
      setCaptures(capData.captures || [])
      setStatus(statusData || {})
      setStats(statsData || {})
    } catch (e) {
      console.error('Honeypot fetch error:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  const handleStart = async (service) => {
    setActionLoading(service)
    try {
      await honeypotApi.start(service)
      await fetchData()
    } catch (e) {
      console.error('Start error:', e)
    } finally {
      setActionLoading(null)
    }
  }

  const handleStop = async (service) => {
    setActionLoading(service)
    try {
      await honeypotApi.stop(service)
      await fetchData()
    } catch (e) {
      console.error('Stop error:', e)
    } finally {
      setActionLoading(null)
    }
  }

  const formatTs = (ts) => {
    if (!ts) return '—'
    try { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) } catch { return ts }
  }

  // Use stats.honeypots (includes per-service capture counts) with status.honeypots as fallback
  const nodes = (stats.honeypots && stats.honeypots.length > 0) ? stats.honeypots : (status.honeypots || [])
  const activeCount = nodes.filter(n => n.active).length

  const statCards = [
    { label: 'Total Hits Today', val: stats.total_captures ?? captures.length, color: 'var(--r)' },
    { label: 'Unique Sources', val: stats.unique_ips ?? '—', color: 'var(--o)' },
    { label: 'Active Nodes', val: activeCount, color: 'var(--g)' },
    { label: 'New Credentials', val: stats.credential_attempts ?? '—', color: 'var(--p)' },
  ]

  return (
    <div className="page-content anim-fade">
      {/* Stats */}
      <div className="stat-grid">
        {statCards.map(s => (
          <div className="stat-card" key={s.label}>
            <div className="stat-bar" style={{ background: s.color }} />
            <div className="stat-label">{s.label}</div>
            <div className="stat-num" style={{ color: s.color }}>{loading ? '…' : s.val}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="row" style={{ gap: 2 }}>
            {['hits', 'nodes'].map(t => (
              <button key={t} onClick={() => setTab(t)} className="btn" style={{
                background: tab === t ? 'var(--b-dim)' : 'transparent',
                color: tab === t ? 'var(--b)' : 'var(--t3)',
                borderColor: tab === t ? 'rgba(59,125,232,0.3)' : 'transparent',
                textTransform: 'capitalize',
              }}>{t === 'hits' ? 'Attack Hits' : 'Honeypot Nodes'}</button>
            ))}
          </div>
          <div className="live-tag">
            <span className="live-dot" />
            Live monitoring
          </div>
        </div>

        {tab === 'hits' && (
          <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 280px)' }}>
            {loading ? (
              <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
                <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading captures…
              </div>
            ) : (
              <table className="siem-table">
                <thead>
                  <tr><th>Time</th><th>Source IP</th><th>Country</th><th>Port / Service</th><th>Payload</th><th>Severity</th></tr>
                </thead>
                <tbody>
                  {captures.length === 0 ? (
                    <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--t3)', padding: 24 }}>No captures in last 24h</td></tr>
                  ) : captures.map((h, i) => {
                    const sev = (h.severity || 'MEDIUM').toUpperCase()
                    return (
                      <tr key={h.id || i}>
                        <td><span className="mono" style={{ fontSize: 11 }}>{formatTs(h.timestamp)}</span></td>
                        <td><span className="mono" style={{ fontSize: 11, color: 'var(--r)' }}>{h.source_ip || h.src || '—'}</span></td>
                        <td style={{ fontSize: 12 }}>{h.country || h.geo?.country || '—'}</td>
                        <td>
                          <span className="tag" style={{ color: 'var(--b)', borderColor: 'rgba(59,125,232,0.3)', fontSize: 10 }}>
                            {h.service || '—'}:{h.port || '—'}
                          </span>
                        </td>
                        <td>
                          <code style={{
                            fontFamily: 'IBM Plex Mono, monospace', fontSize: 10.5,
                            background: 'var(--bg2)', padding: '2px 6px', borderRadius: 4,
                            color: 'var(--o)', maxWidth: 220, display: 'inline-block',
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          }}>{ h.payload_preview || h.payload || h.data || '—'}</code>
                        </td>
                        <td><span className={`sev sev-${sev}`}>{sev}</span></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'nodes' && (
          <div className="scroll-y" style={{ padding: 12, flex: 1, maxHeight: 'calc(100vh - 280px)', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {nodes.length === 0 && !loading && (
              <div className="empty-state"><Icon.Server style={{ width: 24 }} /><p>No honeypot nodes configured</p></div>
            )}
            {nodes.map(n => (
              <div key={n.name || n.service} style={{
                background: 'var(--bg2)', border: '1px solid var(--ln)',
                borderRadius: 10, padding: '14px 16px',
                display: 'flex', alignItems: 'center', gap: 14,
              }}>
                <div style={{
                  width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                  background: n.active ? 'var(--g)' : 'var(--r)',
                  boxShadow: `0 0 8px ${n.active ? 'var(--g)' : 'var(--r)'}`,
                  animation: n.active ? 'blink 3s infinite' : 'none',
                }} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 700, color: 'var(--t1)', marginBottom: 5 }}>{n.name || n.service}</div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    <span className="tag" style={{ color: 'var(--c)', borderColor: 'rgba(14,165,233,0.3)', fontSize: 10 }}>
                      {n.service}:{n.port}
                    </span>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 22, fontWeight: 600, color: 'var(--t1)' }}>{n.captures ?? 0}</div>
                  <div style={{ fontSize: 10, color: 'var(--t3)' }}>hits today</div>
                </div>
                <div className="row" style={{ gap: 6 }}>
                  <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: 'var(--t3)' }}>{n.ip || '—'}</span>
                  <span className="tag" style={{ color: n.active ? 'var(--g)' : 'var(--r)', borderColor: 'currentColor', fontSize: 9 }}>
                    {n.active ? 'ACTIVE' : 'INACTIVE'}
                  </span>
                  {n.active
                    ? <button className="btn btn-danger" style={{ fontSize: 10 }} disabled={actionLoading === n.service} onClick={() => handleStop(n.service)}>Stop</button>
                    : <button className="btn btn-primary" style={{ fontSize: 10 }} disabled={actionLoading === n.service} onClick={() => handleStart(n.service)}>Start</button>
                  }
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
