import { useState, useEffect } from 'react'
import Icon from '../components/Icons.jsx'
import { reportsApi } from '../services/api.js'

const REPORT_TYPES = [
  { value: 'executive', label: 'Executive Summary' },
  { value: 'threat_intel', label: 'Threat Intelligence' },
  { value: 'compliance', label: 'Compliance Audit' },
  { value: 'incident', label: 'Incident Report' },
  { value: 'agent_health', label: 'Agent Health' },
]

const typeIcon = { executive: 'Report', threat_intel: 'Lock', compliance: 'File', incident: 'Activity', agent_health: 'Server' }
const typeColor = { executive: 'var(--r)', threat_intel: 'var(--o)', compliance: 'var(--g)', incident: 'var(--b)', agent_health: 'var(--p)' }

export default function ReportsPage() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [showGen, setShowGen] = useState(false)
  const [genType, setGenType] = useState('executive')
  const [genHours, setGenHours] = useState(24)
  const [expanded, setExpanded] = useState(null)
  const [deleting, setDeleting] = useState(null)

  const fetchReports = async () => {
    try {
      const data = await reportsApi.list()
      setReports(data.reports || [])
    } catch (e) {
      console.error('Reports fetch error:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchReports() }, [])

  const generate = async () => {
    setGenerating(true)
    try {
      await reportsApi.generate({ report_type: genType, hours: genHours })
      setShowGen(false)
      fetchReports()
    } catch (e) {
      console.error('Generate error:', e)
    } finally {
      setGenerating(false)
    }
  }

  const deleteReport = async (id) => {
    setDeleting(id)
    try {
      await reportsApi.delete(id)
      setReports(r => r.filter(rep => rep.id !== id))
      if (expanded === id) setExpanded(null)
    } catch (e) {
      console.error('Delete error:', e)
    } finally {
      setDeleting(null)
    }
  }

  const formatDate = (ts) => {
    if (!ts) return '—'
    try { return new Date(ts).toLocaleDateString() } catch { return ts }
  }

  return (
    <div className="page-content anim-fade">
      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="card-title"><Icon.Report />Reports</div>
          <div className="row">
            <button className="btn btn-primary" onClick={() => setShowGen(!showGen)}>
              <Icon.Plus />{showGen ? 'Cancel' : 'Generate Report'}
            </button>
          </div>
        </div>

        {/* Generate Form */}
        {showGen && (
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--ln)', background: 'var(--bg2)', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <select className="sel" value={genType} onChange={e => setGenType(e.target.value)}>
              {REPORT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
            <select className="sel" value={genHours} onChange={e => setGenHours(Number(e.target.value))}>
              <option value={1}>Last 1h</option>
              <option value={24}>Last 24h</option>
              <option value={168}>Last 7d</option>
              <option value={720}>Last 30d</option>
            </select>
            <button className="btn btn-primary" style={{ fontSize: 12 }} onClick={generate} disabled={generating}>
              <Icon.Zap />{generating ? 'Generating…' : 'Generate'}
            </button>
          </div>
        )}

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--t3)' }}>
            <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading reports…
          </div>
        ) : reports.length === 0 ? (
          <div className="empty-state">
            <Icon.Report style={{ width: 28 }} />
            <p>No reports yet. Click "Generate Report" to create your first one.</p>
          </div>
        ) : reports.map((r, i) => {
          const rtype = r.report_type || 'executive'
          const IcoName = typeIcon[rtype] || 'Report'
          const Ico = Icon[IcoName]
          const color = typeColor[rtype] || 'var(--b)'
          const label = REPORT_TYPES.find(t => t.value === rtype)?.label || rtype
          return (
            <div key={r.id || i}>
              <div className="report-row">
                <div className="report-icon" style={{ background: color + '18' }}>
                  <Ico style={{ color }} />
                </div>
                <div style={{ flex: 1 }}>
                  <div className="report-name">{r.title || label}</div>
                  <div className="report-meta">
                    {label} · {formatDate(r.created_at)} · by {r.generated_by || 'system'}
                  </div>
                </div>
                <button className="btn" style={{ fontSize: 11 }} onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                  <Icon.Eye />{expanded === r.id ? 'Hide' : 'View'}
                </button>
                <button className="btn btn-danger" style={{ fontSize: 11 }} disabled={deleting === r.id} onClick={() => deleteReport(r.id)}>
                  <Icon.X />{deleting === r.id ? '…' : 'Delete'}
                </button>
              </div>

              {/* Expanded summary */}
              {expanded === (r.id || i) && (
                <div className="report-detail anim-fade" style={{ 
                  padding: '24px', background: 'var(--bg1)', borderTop: '1px solid var(--ln)',
                  margin: '0 16px 16px', borderRadius: 12, border: '1px solid var(--ln2)' 
                }}>
                  <div className="row" style={{ justifyContent: 'space-between', marginBottom: 20 }}>
                    <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--t1)' }}>{label}</div>
                    <button className="btn btn-primary" onClick={() => window.print()} style={{ fontSize: 11 }}>
                      <Icon.Download /> Download PDF
                    </button>
                  </div>

                  <div style={{ fontSize: 14, color: 'var(--t2)', lineHeight: 1.8, background: 'var(--bg2)', padding: 15, borderRadius: 8, marginBottom: 24, borderLeft: '3px solid var(--b)' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--b)', marginBottom: 8 }}>Executive Summary</div>
                    {r.executive_summary || r.summary || "This report summarizes security activity for the specified period."}
                  </div>

                  <div className="row" style={{ gap: 12, marginBottom: 24 }}>
                    {r.key_metrics && Object.entries(r.key_metrics).map(([k, v]) => (
                      <div key={k} className="card" style={{ flex: 1, padding: '12px 14px', background: 'var(--bg2)', minWidth: 100 }}>
                        <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--t3)', marginBottom: 4 }}>{k.replace(/_/g, ' ')}</div>
                        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--t1)', fontFamily: 'IBM Plex Mono, monospace' }}>{v}</div>
                      </div>
                    ))}
                  </div>

                  <div className="row" style={{ gap: 20, alignItems: 'flex-start' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--t3)', marginBottom: 12 }}>Top Attacking IPs</div>
                      <table className="siem-table mini">
                        <thead><tr><th>Source IP</th><th>Hits</th><th>Max Severity</th></tr></thead>
                        <tbody>
                          {(r.top_attacking_ips || []).slice(0, 5).map((ip, j) => (
                            <tr key={j}>
                              <td className="mono" style={{ fontSize: 11 }}>{ip.ip}</td>
                              <td className="mono" style={{ fontSize: 11 }}>{ip.count}</td>
                              <td><span className={`sev sev-${(ip.severity || 'low').toUpperCase()}`}>{ip.severity}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--t3)', marginBottom: 12 }}>Detection Recommendations</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {(r.recommendations || []).map((rec, k) => (
                          <div key={k} style={{ fontSize: 12, color: 'var(--t2)', display: 'flex', gap: 8 }}>
                            <span style={{ color: 'var(--g)' }}>•</span> {rec}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
