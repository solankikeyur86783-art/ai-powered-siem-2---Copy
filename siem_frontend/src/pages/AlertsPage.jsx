import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import Icon from '../components/Icons.jsx'
import { alertsApi, forensicsApi } from '../services/api.js'
import { fmtFull } from '../services/timeUtils.js'

const sevColor = { CRITICAL: 'var(--r)', HIGH: 'var(--o)', MEDIUM: 'var(--y)', LOW: 'var(--g)', INFO: 'var(--b)' }
const statusStyle = {
  open: { color: 'var(--r)', bg: 'var(--r-dim)' },
  investigating: { color: 'var(--y)', bg: 'var(--y-dim)' },
  resolved: { color: 'var(--g)', bg: 'var(--g-dim)' },
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([])
  const [summary, setSummary] = useState({})
  const [filter, setFilter] = useState('all')
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [investigating, setInvestigating] = useState(null)
  const [investigation, setInvestigation] = useState({})
  const [collecting, setCollecting] = useState(null)
  const navigate = useNavigate()

  const fetchAlerts = async () => {
    try {
      const params = {}
      if (filter !== 'all') {
        if (['critical','high','medium','low'].includes(filter)) params.severity = filter
        else params.status = filter
      }
      const [data, sumData] = await Promise.all([
        alertsApi.list(params),
        alertsApi.summary()
      ])
      setAlerts(data.alerts || [])
      setSummary(sumData || {})
    } catch (e) {
      console.error('Alerts fetch error:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchAlerts() }, [filter])

  const handleInvestigate = async (alertId) => {
    setInvestigating(alertId)
    try {
      const res = await alertsApi.investigate(alertId)
      setInvestigation(prev => ({ ...prev, [alertId]: res.investigation }))
      // Refresh alerts to show updated status
      fetchAlerts()
    } catch (e) {
      console.error('Investigation error:', e)
    } finally {
      setInvestigating(null)
    }
  }
  
  const handleOpenCase = async (alertId) => {
    setCollecting(alertId)
    try {
      await forensicsApi.collect(alertId)
      navigate('/forensics')
    } catch (e) {
      alert('Forensic collection failed: ' + e.message)
    } finally {
      setCollecting(null)
    }
  }

  const handleUpdate = async (alertId, data) => {
    try {
      await alertsApi.update(alertId, data)
      fetchAlerts()
    } catch (e) {
      console.error('Update error:', e)
    }
  }

  const handleDelete = async (alertId) => {
    try {
      await alertsApi.delete(alertId)
      setSelected(null)
      fetchAlerts()
    } catch (e) {
      console.error('Delete error:', e)
    }
  }

  // ✅ Fixed: local IST time via timeUtils
  const formatTime = (ts) => fmtFull(ts)

  return (
    <div className="page-content anim-fade">
      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="card-title"><Icon.Alert />Security Alerts</div>
          <div className="row">
            <select className="sel" value={filter} onChange={e => setFilter(e.target.value)}>
              <option value="all">All alerts</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
            <button className="btn btn-primary" onClick={() => navigate('/rules')}><Icon.Plus />New Rule</button>
          </div>
        </div>

        {/* Summary row */}
        <div className="row" style={{ padding: '10px 16px', borderBottom: '1px solid var(--ln)', gap: 16 }}>
          {[
            { label: 'Total', val: summary.total ?? alerts.length, color: 'var(--t1)' },
            { label: 'Critical', val: summary.critical ?? 0, color: 'var(--r)' },
            { label: 'High', val: summary.high ?? 0, color: 'var(--o)' },
            { label: 'Open', val: summary.open ?? 0, color: 'var(--b)' },
          ].map(s => (
            <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
              <span style={{ color: s.color, fontFamily: 'IBM Plex Mono, monospace', fontWeight: 700, fontSize: 15 }}>{s.val}</span>
              <span style={{ color: 'var(--t3)' }}>{s.label}</span>
            </div>
          ))}
        </div>

        <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 220px)' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--t3)' }}>
              <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading alerts…
            </div>
          ) : alerts.length === 0 ? (
            <div className="empty-state"><Icon.Check style={{ width: 24, height: 24 }} /><p>No alerts match this filter</p></div>
          ) : alerts.map(a => {
            const sev = (a.severity || 'low').toUpperCase()
            const status = a.status || 'open'
            const st = statusStyle[status] || statusStyle.open
            return (
              <div className="alert-item" key={a.id} onClick={() => setSelected(a.id === selected ? null : a.id)}>
                <div className="alert-sev-bar" style={{ background: sevColor[sev] || 'var(--b)' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="alert-title">{a.title || a.rule_name || 'Alert'}</div>
                  <div className="alert-meta">
                    <span><Icon.Globe style={{ width: 10, height: 10, display: 'inline', verticalAlign: 'middle', marginRight: 3 }} />{a.source_ip || '—'}</span>
                    {a.destination_ip && <span>→ {a.destination_ip}</span>}
                    <span className="mono" style={{ fontSize: 10 }}>{formatTime(a.created_at)}</span>
                    {a.rule_name && <span>{a.rule_name}</span>}
                  </div>
                  {selected === a.id && (
                    <div className="anim-fade" style={{ marginTop: 10, padding: '14px', background: 'var(--bg2)', borderRadius: 10, border: '1px solid var(--ln)', fontSize: 12 }}>
                      {/* Metadata Grid */}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14, background: 'var(--bg3)', padding: 10, borderRadius: 8 }}>
                        <div className="col">
                          <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase' }}>Target Host</span>
                          <span style={{ fontWeight: 600, color: 'var(--t1)' }}>{a.hostname || 'Unknown Host'}</span>
                        </div>
                        <div className="col">
                          <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase' }}>Source IP</span>
                          <span className="mono" style={{ color: 'var(--b)' }}>{a.source_ip || 'Internal'}</span>
                        </div>
                        {a.mitre_tactic && (
                          <div className="col">
                            <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase' }}>MITRE Tactic</span>
                            <span className="tag" style={{ background: 'var(--o-dim)', color: 'var(--o)', borderColor: 'var(--o)' }}>{a.mitre_tactic}</span>
                          </div>
                        )}
                        {a.mitre_technique && (
                          <div className="col">
                            <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase' }}>Technique</span>
                            <span className="tag" style={{ background: 'var(--b-dim)', color: 'var(--b)', borderColor: 'var(--b)' }}>{a.mitre_technique}</span>
                          </div>
                        )}
                      </div>

                      <div style={{ color: 'var(--t2)', lineHeight: 1.7 }}>
                        {(investigation[a.id] || a.llm_summary) ? (
                          <div className="anim-fade-up">
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                               <span className="live-dot" style={{ background: 'var(--b)', animationDuration: '3s' }} />
                               <strong style={{ color: 'var(--b)', textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.05em' }}>🤖 AI Investigation Summary</strong>
                            </div>
                            <div style={{ 
                              padding: '12px', 
                              background: 'var(--bg1)', 
                              borderRadius: 6, 
                              border: '1px solid var(--ln2)',
                              fontSize: 11.5,
                              lineHeight: 1.6,
                              color: 'var(--t1)',
                              whiteSpace: 'pre-wrap'
                            }}>
                              {investigation[a.id] ? (typeof investigation[a.id] === 'string' ? investigation[a.id] : JSON.stringify(investigation[a.id], null, 2)) : a.llm_summary}
                            </div>
                          </div>
                        ) : (
                          <>
                            <strong style={{ color: 'var(--t1)' }}>Detection Context:</strong> 
                            <p style={{ marginTop: 4, color: 'var(--t3)' }}>
                              This alert was triggered by the <strong>{a.rule_name || 'Heuristic'}</strong> detection logic. 
                              The AI agents are currently analyzing the behavior pattern from source <code>{a.source_ip || 'local'}</code>. 
                              Click <strong>Investigate</strong> for a deep-dive report.
                            </p>
                          </>
                        )}
                      </div>
                      <div className="row" style={{ marginTop: 10, gap: 8 }}>
                        <button className="btn btn-primary" style={{ fontSize: 11 }} disabled={investigating === a.id} onClick={(e) => { e.stopPropagation(); handleInvestigate(a.id) }}>
                          <Icon.Eye />{investigating === a.id ? 'Investigating…' : 'Investigate'}
                        </button>
                        {(sev === 'CRITICAL' || sev === 'HIGH') && (
                          <button className="btn" style={{ fontSize: 11, borderColor: 'var(--p)', color: 'var(--p)' }} disabled={collecting === a.id} onClick={(e) => { e.stopPropagation(); handleOpenCase(a.id) }}>
                            <Icon.Activity />{collecting === a.id ? 'Collecting…' : 'Open Forensic Case'}
                          </button>
                        )}
                        <button className="btn" style={{ fontSize: 11 }} onClick={(e) => { e.stopPropagation(); handleUpdate(a.id, { status: 'resolved' }) }}>
                          <Icon.Check />Mark Resolved
                        </button>
                        <button className="btn btn-danger" style={{ fontSize: 11 }} onClick={(e) => { e.stopPropagation(); handleDelete(a.id) }}>
                          <Icon.X />Dismiss
                        </button>
                      </div>
                    </div>
                  )}
                </div>
                <div className="col" style={{ alignItems: 'flex-end', gap: 6 }}>
                  <span className={`sev sev-${sev}`}>{sev}</span>
                  <span className="tag" style={{ color: st.color, background: st.bg, borderColor: st.color, fontSize: 9 }}>{status.toUpperCase()}</span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
