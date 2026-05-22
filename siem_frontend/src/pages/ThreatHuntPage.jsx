import React, { useState, useEffect } from 'react'
import Icon from '../components/Icons.jsx'
import { huntApi } from '../services/api.js'

const sevColor = { CRITICAL: 'var(--r)', HIGH: 'var(--o)', MEDIUM: 'var(--y)', LOW: 'var(--g)' }

export default function ThreatHuntPage() {
  const [templates, setTemplates] = useState([])
  const [query, setQuery] = useState('')
  const [hours, setHours] = useState(24)
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [savedHunts, setSavedHunts] = useState([])
  const [expandedRow, setExpandedRow] = useState(null)

  useEffect(() => {
    huntApi.templates()
      .then(d => setTemplates(d.templates || []))
      .catch(console.error)
    huntApi.saved()
      .then(d => setSavedHunts(d.queries || []))
      .catch(console.error)
  }, [])

  const runHunt = async () => {
    if (!query.trim()) return
    setLoading(true)
    setResults(null)
    setExpandedRow(null)
    try {
      // Try as NL query first
      const res = await huntApi.nlQuery(query, hours)
      setResults(res.results?.samples || res.results?.logs || res.results?.matches || [])
    } catch (e) {
      console.error('Hunt error:', e)
      setResults([])
    } finally {
      setLoading(false)
    }
  }

  const saveHunt = async () => {
    if (!query.trim()) return
    setSaving(true)
    try {
      await huntApi.save(`Hunt — ${query.substring(0, 30)}`, query)
      const d = await huntApi.saved()
      setSavedHunts(d.queries || [])
    } catch (e) {
      console.error('Save error:', e)
    } finally {
      setSaving(false)
    }
  }

  const deleteHunt = async (id, e) => {
    e.stopPropagation()
    try {
      await huntApi.deleteSaved(id)
      setSavedHunts(prev => prev.filter(h => h.id !== id))
    } catch (err) {
      console.error('Delete error:', err)
    }
  }

  const formatTs = (ts) => {
    if (!ts) return '—'
    try { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) } catch { return ts }
  }

  return (
    <div className="page-content anim-fade">
      <div className="card">
        <div className="card-head">
          <div className="card-title"><Icon.Search />Threat Hunt Query</div>
          <div className="row">
            <select className="sel" value={hours} onChange={e => setHours(Number(e.target.value))}>
              <option value={1}>Last 1h</option>
              <option value={6}>Last 6h</option>
              <option value={24}>Last 24h</option>
              <option value={72}>Last 3d</option>
            </select>
            <button className="btn" onClick={saveHunt} disabled={saving}><Icon.Download />{saving ? 'Saving…' : 'Save Hunt'}</button>
            <button className="btn btn-primary" onClick={runHunt} disabled={loading}>
              <Icon.Zap />{loading ? 'Hunting…' : 'Run Hunt'}
            </button>
          </div>
        </div>
        <div style={{ padding: 16 }}>
          <textarea
            className="inp" rows={4}
            style={{ resize: 'vertical', fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, lineHeight: 1.7 }}
            placeholder={`event_type:network AND src_port:445 AND direction:outbound\nOR process_name:lsass AND access_mask:0x1410\nOR dns_query_type:TXT AND query_count:>10`}
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
          <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--t3)', alignSelf: 'center' }}>Saved Hunts:</span>
            {savedHunts.length > 0 ? (
              savedHunts.map(h => (
                <div key={h.id} style={{ display: 'inline-flex' }}>
                  <button className="btn" style={{ fontSize: 11, borderColor: 'var(--b)', color: 'var(--b)', borderTopRightRadius: 0, borderBottomRightRadius: 0, paddingRight: 6 }} onClick={() => setQuery(typeof h.query === 'string' ? h.query : JSON.stringify(h.query))} title="Load query">{h.name.replace('Hunt — ', '')}</button>
                  <button className="btn" style={{ fontSize: 11, borderColor: 'var(--b)', color: 'var(--b)', borderLeft: 'none', borderTopLeftRadius: 0, borderBottomLeftRadius: 0, padding: '0 6px' }} onClick={(e) => deleteHunt(h.id, e)} title="Delete saved hunt">✕</button>
                </div>
              ))
            ) : <span style={{ fontSize: 11, color: 'var(--t3)', alignSelf: 'center' }}>None yet</span>}
          </div>
          <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--t3)', alignSelf: 'center' }}>Templates:</span>
            {templates.length > 0
              ? templates.map(t => (
                  <button key={t.id || t.name} className="btn" style={{ fontSize: 11 }} onClick={() => setQuery(t.description || t.name)}>{t.name}</button>
                ))
              : ['Detect lateral movement via SMB', 'Find privilege escalation attempts', 'Identify C2 beacon patterns', 'Detect DNS tunneling'].map(p => (
                  <button key={p} className="btn" style={{ fontSize: 11 }} onClick={() => setQuery(p)}>{p}</button>
                ))
            }
          </div>
        </div>
      </div>

      {loading && (
        <div className="card" style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
            <div className="live-dot" style={{ background: 'var(--b)' }} />
            <span>Scanning {hours}h of event data…</span>
          </div>
        </div>
      )}

      {results && !loading && (
        <div className="card">
          <div className="card-head">
            <div className="card-title"><Icon.Activity />Hunt Results</div>
            <span style={{ fontSize: 12, color: 'var(--t3)' }}>{results.length} matches found</span>
          </div>
          <div className="scroll-y" style={{ display: 'flex', flexDirection: 'column', maxHeight: '50vh' }}>
            {results.length === 0 ? (
              <div className="empty-state"><Icon.Check style={{ width: 24 }} /><p>No matches found for this query</p></div>
            ) : (
              <table className="siem-table">
                <thead>
                  <tr><th>Time</th><th>Host</th><th>IP</th><th>Event</th><th>Risk</th></tr>
                </thead>
                <tbody>
                  {results.map((r, i) => {
                    const risk = String(r.severity || r.risk || r.log_level || 'MEDIUM').toUpperCase()
                    const timeField = r.timestamp || r.created_at || r['@timestamp']
                    const hostField = r.hostname || r.host?.name || r.winlog?.computer_name || r.agent?.name || '—'
                    const ipField = r.source_ip || r.ip || r.source?.ip || r.client?.ip || '—'
                    
                    let eventField = r.message || r.description || r.title || r.rule_name
                    if (!eventField && r.event) {
                      eventField = typeof r.event === 'object' ? JSON.stringify(r.event) : String(r.event)
                    }
                    if (!eventField) eventField = JSON.stringify(r).substring(0, 100) + '...'

                    return (
                      <React.Fragment key={i}>
                        <tr className="hunt-result" onClick={() => setExpandedRow(expandedRow === i ? null : i)} style={{ cursor: 'pointer' }}>
                          <td><span className="mono" style={{ fontSize: 11 }}>{formatTs(timeField)}</span></td>
                          <td style={{ color: 'var(--t1)', fontWeight: 600 }}>{hostField}</td>
                          <td><span className="mono" style={{ fontSize: 11, color: 'var(--b)' }}>{ipField}</span></td>
                          <td style={{ maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{eventField}</td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                              <span className={`sev sev-${risk}`}>{risk}</span>
                              <span style={{ fontSize: 10, color: 'var(--b)', background: 'var(--bg2)', padding: '2px 6px', borderRadius: 4, border: '1px solid var(--ln)' }}>INFO ▼</span>
                            </div>
                          </td>
                        </tr>
                        {expandedRow === i && (
                          <tr className="anim-fade" style={{ background: 'var(--bg2)' }}>
                            <td colSpan={5} style={{ padding: 16 }}>
                              <div style={{ color: 'var(--t2)', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: '#080b12', padding: 16, borderRadius: 6, border: '1px solid var(--ln)', maxHeight: 400, overflowY: 'auto' }}>
                                {Object.keys(r.raw || r).length > 0 ? JSON.stringify(r.raw || r, null, 2) : eventField}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {!results && !loading && (
        <div className="card">
          <div className="empty-state">
            <Icon.Search style={{ width: 32, height: 32 }} />
            <p>Write a hunt query above and click Run Hunt</p>
          </div>
        </div>
      )}
    </div>
  )
}
