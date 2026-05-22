import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import Icon from '../components/Icons.jsx'
import { logsApi } from '../services/api.js'
import { fmtLog } from '../services/timeUtils.js'

const LEVELS = ['INFO', 'WARN', 'ERROR', 'DEBUG', 'CRITICAL']
const levelColor = { INFO: 'var(--b)', WARN: 'var(--y)', ERROR: 'var(--r)', DEBUG: 'var(--t3)', CRITICAL: 'var(--r)' }
const levelBg = { INFO: 'var(--b-dim)', WARN: 'var(--y-dim)', ERROR: 'var(--r-dim)', DEBUG: 'rgba(100,100,120,0.1)', CRITICAL: 'var(--r-dim)' }

export default function LogsPage() {
  const [searchParams] = useSearchParams()
  const initialQuery = searchParams.get('q') || ''
  
  const [logs, setLogs] = useState([])
  const [total, setTotal] = useState(0)
  const [query, setQuery] = useState(initialQuery)
  const [levelFilter, setLevelFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState(null)

  const fetchLogs = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: 100, hours: 24 }
      if (levelFilter !== 'all') params.log_level = levelFilter
      if (query) params.search = query
      const data = await logsApi.list(params)
      setLogs(data.logs || [])
      setTotal(data.total || 0)
    } catch (e) {
      console.error('Logs fetch error:', e)
    } finally {
      setLoading(false)
    }
  }, [query, levelFilter])

  useEffect(() => {
    const t = setTimeout(fetchLogs, 300) // debounce search
    return () => clearTimeout(t)
  }, [fetchLogs])

  // ✅ Fixed: uses local IST time (not UTC toISOString)
  const formatTs = (ts) => fmtLog(ts)

  const toggleExpand = (id) => {
    setExpandedId(prev => prev === id ? null : id)
  }

  return (
    <div className="page-content anim-fade">
      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="card-title"><Icon.File />Log Search</div>
          <div className="row">
            <div style={{ position: 'relative' }}>
              <Icon.Search style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', width: 13, height: 13, color: 'var(--t3)' }} />
              <input className="inp" style={{ paddingLeft: 30, width: 260 }} placeholder="Search logs…" value={query} onChange={e => setQuery(e.target.value)} />
            </div>
            <select className="sel" value={levelFilter} onChange={e => setLevelFilter(e.target.value)}>
              <option value="all">All levels</option>
              {LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
            <button className="btn" onClick={() => {
              const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' })
              const url = URL.createObjectURL(blob)
              const link = document.createElement('a')
              link.href = url
              link.download = `logs_export_${new Date().toISOString().split('T')[0]}.json`
              link.click()
              URL.revokeObjectURL(url)
            }}><Icon.Download />Export</button>
          </div>
        </div>

        {/* Log count bar */}
        <div style={{ padding: '6px 14px', borderBottom: '1px solid var(--ln)', fontSize: 11, color: 'var(--t3)', background: 'var(--bg2)' }}>
          Showing <strong style={{ color: 'var(--t1)' }}>{logs.length}</strong> of <strong style={{ color: 'var(--t1)' }}>{total}</strong> log entries
        </div>

        {/* Log header */}
        <div className="log-row" style={{ cursor: 'default', background: 'var(--bg2)', borderBottom: '1px solid var(--ln)' }}>
          <span style={{ width: 32, flexShrink: 0, fontSize: 9, fontWeight: 700, color: 'var(--t3)', letterSpacing: '0.1em', textTransform: 'uppercase', textAlign: 'center' }}>INFO</span>
          <span className="log-ts" style={{ color: 'var(--t3)', fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase' }}>TIMESTAMP</span>
          <span className="log-level" style={{ color: 'var(--t3)', fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase' }}>LEVEL</span>
          <span className="log-src" style={{ color: 'var(--t3)', fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase' }}>SOURCE</span>
          <span className="log-msg" style={{ color: 'var(--t3)', fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase' }}>MESSAGE</span>
        </div>

        <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 220px)' }}>
          {loading ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
              <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading logs…
            </div>
          ) : logs.length === 0 ? (
            <div className="empty-state"><Icon.File style={{ width: 24 }} /><p>No logs found</p></div>
          ) : logs.map((l, i) => {
            const level = (l.log_level || l.level || 'INFO').toUpperCase()
            const rowId = l.id || l._id || i
            const isExpanded = expandedId === rowId
            return (
              <div key={rowId}>
                {/* Main log row */}
                <div
                  className="log-row"
                  onClick={() => toggleExpand(rowId)}
                  style={{
                    background: isExpanded ? 'var(--bg2)' : undefined,
                    borderLeft: isExpanded ? `3px solid ${levelColor[level] || 'var(--b)'}` : '3px solid transparent',
                  }}
                >
                  {/* Info button */}
                  <span
                    style={{
                      width: 32, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}
                    title="View log details"
                  >
                    <span style={{
                      width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: isExpanded ? (levelBg[level] || 'var(--b-dim)') : 'var(--bg3)',
                      border: `1px solid ${isExpanded ? (levelColor[level] || 'var(--b)') : 'var(--ln2)'}`,
                      color: isExpanded ? (levelColor[level] || 'var(--b)') : 'var(--t3)',
                      transition: 'all 0.2s',
                      fontSize: 11, fontWeight: 800, fontFamily: 'serif',
                    }}>
                      {isExpanded ? '▲' : 'i'}
                    </span>
                  </span>
                  <span className="log-ts">{formatTs(l.timestamp)}</span>
                  <span className="log-level" style={{ color: levelColor[level] || 'var(--t3)' }}>{level}</span>
                  <span className="log-src">{l.source || l.hostname || '—'}</span>
                  <span className="log-msg">{l.message || '—'}</span>
                </div>

                {/* Expanded detail panel */}
                {isExpanded && (
                  <div className="anim-fade" style={{
                    background: 'var(--bg2)',
                    borderBottom: '2px solid var(--ln)',
                    borderLeft: `3px solid ${levelColor[level] || 'var(--b)'}`,
                    padding: '16px 20px 16px 50px',
                  }}>
                    {/* Header with level badge */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                      <span style={{
                        fontSize: 10, fontWeight: 700, letterSpacing: '0.08em',
                        padding: '3px 10px', borderRadius: 5,
                        background: levelBg[level] || 'var(--b-dim)',
                        color: levelColor[level] || 'var(--b)',
                        fontFamily: 'IBM Plex Mono, monospace',
                      }}>
                        {level}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--t3)', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
                        Log Entry Detail
                      </span>
                    </div>

                    {/* Info grid */}
                    <div style={{
                      display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
                      gap: '10px 20px', marginBottom: 14,
                    }}>
                      {[
                        { label: 'Timestamp', value: formatTs(l.timestamp) },
                        { label: 'Source', value: l.source || '—' },
                        { label: 'Hostname', value: l.hostname || '—' },
                        { label: 'Event ID', value: l.event_id || l.eventId || '—' },
                        { label: 'Level', value: level },
                        { label: 'Log ID', value: l.id || l._id || '—' },
                      ].map(item => (
                        <div key={item.label} style={{
                          background: 'var(--bg1)', borderRadius: 8, padding: '8px 12px',
                          border: '1px solid var(--ln)',
                        }}>
                          <div style={{ fontSize: 9, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>
                            {item.label}
                          </div>
                          <div style={{
                            fontSize: 12, fontWeight: 600, color: 'var(--t1)',
                            fontFamily: 'IBM Plex Mono, monospace',
                            wordBreak: 'break-all',
                          }}>
                            {item.value}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Full message */}
                    <div style={{
                      background: 'var(--bg1)', borderRadius: 8, padding: '12px 14px',
                      border: '1px solid var(--ln)', marginBottom: 12,
                    }}>
                      <div style={{ fontSize: 9, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                        Full Message
                      </div>
                      <div style={{
                        fontSize: 11.5, color: 'var(--t1)', lineHeight: 1.6,
                        fontFamily: 'IBM Plex Mono, monospace',
                        whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                        maxHeight: 200, overflowY: 'auto',
                      }}>
                        {l.message || '—'}
                      </div>
                    </div>

                    {/* Raw JSON */}
                    <details style={{ marginTop: 4 }}>
                      <summary style={{
                        fontSize: 10, fontWeight: 700, color: 'var(--b)', cursor: 'pointer',
                        padding: '4px 0', letterSpacing: '0.04em',
                      }}>
                        ▸ View Raw JSON
                      </summary>
                      <div style={{
                        background: 'var(--bg1)', borderRadius: 8, padding: '10px 14px',
                        border: '1px solid var(--ln)', marginTop: 6,
                        fontSize: 10.5, color: 'var(--t2)', lineHeight: 1.6,
                        fontFamily: 'IBM Plex Mono, monospace',
                        whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                        maxHeight: 240, overflowY: 'auto',
                      }}>
                        {JSON.stringify(l, null, 2)}
                      </div>
                    </details>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
