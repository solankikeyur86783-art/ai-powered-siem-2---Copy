import { useState, useEffect, useRef, useCallback } from 'react'
import Icon from '../components/Icons.jsx'

// API calls for agents
const BASE = 'http://localhost:8000'
function tok() { return localStorage.getItem('siem-token') || '' }
const hdrs = () => ({ 'Content-Type': 'application/json', ...(tok() ? { Authorization: `Bearer ${tok()}` } : {}) })

async function agentGet(path) {
  const res = await fetch(`${BASE}${path}`, { headers: hdrs() })
  if (!res.ok) throw new Error(res.statusText)
  return res.json()
}
async function agentPost(path, body = null) {
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers: hdrs(), body: body ? JSON.stringify(body) : undefined })
  if (!res.ok) throw new Error(res.statusText)
  return res.json()
}
async function agentDelete(path) {
  const res = await fetch(`${BASE}${path}`, { method: 'DELETE', headers: hdrs() })
  if (!res.ok) throw new Error(res.statusText)
  return res.json()
}

const statusColor = { online: 'var(--g)', operational: 'var(--g)', warn: 'var(--y)', offline: 'var(--r)', error: 'var(--r)' }

const sevColor = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#3b82f6',
  low: '#6b7280',
}

const agentIcons = {
  soc_agent: '🔵',
  analyst_agent: '🟡',
  responder_agent: '🔴',
  hunter_agent: '🕵️',
  forensics_agent: '🔍',
  auto_blocker: '🛡️',
}

export default function AgentsPage() {
  const [status, setStatus] = useState(null)
  const [actions, setActions] = useState([])
  const [liveFeed, setLiveFeed] = useState([])
  const [feedStats, setFeedStats] = useState({})
  const [blockedIps, setBlockedIps] = useState([])
  const [blockedMeta, setBlockedMeta] = useState({})
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('live-feed')
  const [showDeploy, setShowDeploy] = useState(false)
  const [newAgent, setNewAgent] = useState({ name: '', type: 'ai_agent' })
  const [deploying, setDeploying] = useState(false)
  const [showDrill, setShowDrill] = useState(false)
  const [drillResults, setDrillResults] = useState(null)
  const [drilling, setDrilling] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [deleting, setDeleting] = useState(false)
  const [unblocking, setUnblocking] = useState(null)
  const feedRef = useRef(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const [statusData, actionsData, feedData, blockedData] = await Promise.all([
        agentGet('/api/agents/status'),
        agentGet('/api/agents/actions?limit=50&hours=24'),
        agentGet('/api/agents/live-feed?limit=30&hours=24'),
        agentGet('/api/agents/blocked-ips'),
      ])
      setStatus(statusData)
      setActions(actionsData.actions || [])
      setLiveFeed(feedData.actions || [])
      setFeedStats(feedData.stats || {})
      setBlockedIps(blockedData.blocked || [])
      setBlockedMeta({ total: blockedData.total_ever_blocked, active: blockedData.currently_active })
    } catch (e) {
      console.error('Agents fetch error:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  // Auto-refresh every 5 seconds
  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [fetchData])

  // WebSocket for real-time agent events
  useEffect(() => {
    let ws
    try {
      ws = new WebSocket('ws://localhost:8000/ws')
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'agent_activity') {
            setLiveFeed(prev => [{
              id: `ws-${Date.now()}`,
              agent_type: msg.event?.replace('_complete', '_agent').replace('pipeline_', 'system_'),
              action: msg.event,
              alert_id: msg.alert_id,
              timestamp: msg.timestamp,
              result: msg.data?.summary || msg.data?.message || msg.event,
              success: true,
              details: msg.data,
              _live: true,
            }, ...prev].slice(0, 50))
          }
        } catch {}
      }
    } catch {}
    return () => ws && ws.close()
  }, [])

  const handleDeploy = async () => {
    if (!newAgent.name) return
    setDeploying(true)
    try {
      await agentPost('/api/agents/deploy', newAgent)
      setShowDeploy(false)
      setNewAgent({ name: '', type: 'ai_agent' })
      fetchData()
    } catch (e) {
      alert('Deployment failed: ' + e.message)
    } finally {
      setDeploying(false)
    }
  }

  const handleDrill = async () => {
    setDrilling(true)
    setShowDrill(true)
    setDrillResults(null)
    try {
      const res = await agentPost('/api/agents/test_all')
      setDrillResults(res)
      fetchData()
    } catch (e) {
      alert('Security Drill failed: ' + e.message)
    } finally {
      setDrilling(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      const id = deleteTarget.id || deleteTarget.name
      await agentDelete(`/api/agents/${id}`)
      setDeleteTarget(null)
      fetchData()
    } catch (e) {
      alert('Delete failed: ' + e.message)
    } finally {
      setDeleting(false)
    }
  }

  const handleUnblock = async (ip) => {
    setUnblocking(ip)
    try {
      await agentPost(`/api/agents/unblock/${ip}`)
      fetchData()
    } catch (e) {
      alert('Unblock failed: ' + e.message)
    } finally {
      setUnblocking(null)
    }
  }

  const agentTypes = status?.agents || []
  const online = agentTypes.length
  const totalActions = status?.actions_today ?? 0
  const successRate = status?.success_rate ?? 0

  const formatTime = (ts) => {
    if (!ts) return '—'
    try {
      const diff = Date.now() - new Date(ts).getTime()
      const s = Math.floor(diff / 1000)
      if (s < 60) return `${s}s ago`
      const m = Math.floor(s / 60)
      if (m < 60) return `${m}m ago`
      return `${Math.floor(m / 60)}h ago`
    } catch { return ts }
  }

  const byType = status?.by_agent_type || []

  return (
    <div className="page-content anim-fade">
      {/* Summary Cards */}
      <div className="row" style={{ gap: 12 }}>
        {[
          { label: 'Active Agents', val: loading ? '…' : online, color: 'var(--b)', icon: '🤖' },
          { label: 'Actions Today', val: loading ? '…' : totalActions, color: 'var(--g)', icon: '⚡' },
          { label: 'Success Rate', val: loading ? '…' : `${successRate}%`, color: 'var(--y)', icon: '✅' },
          { label: 'IPs Blocked', val: loading ? '…' : (status?.blocked_ips_count ?? blockedMeta.active ?? 0), color: '#ef4444', icon: '🛡️' },
          { label: 'Auto Forensics', val: loading ? '…' : (status?.auto_forensic_cases ?? 0), color: '#8b5cf6', icon: '📂' },
          { label: 'System Status', val: loading ? '…' : (status?.status || '—').toUpperCase(), color: 'var(--g)', icon: '🟢' },
        ].map(s => (
          <div className="card" key={s.label} style={{ flex: 1, padding: '14px 16px', minWidth: 120 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <span style={{ fontSize: 14 }}>{s.icon}</span>
              <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.07em', textTransform: 'uppercase', color: 'var(--t3)' }}>{s.label}</span>
            </div>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 24, fontWeight: 500, color: s.color, lineHeight: 1 }}>{s.val}</div>
          </div>
        ))}
      </div>

      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="row" style={{ gap: 2 }}>
            {['live-feed', 'agents', 'actions', 'blocked-ips'].map(t => (
              <button key={t} onClick={() => setTab(t)} className="btn" style={{
                background: tab === t ? 'var(--b-dim)' : 'transparent',
                color: tab === t ? 'var(--b)' : 'var(--t3)',
                borderColor: tab === t ? 'rgba(59,125,232,0.3)' : 'transparent',
                textTransform: 'capitalize',
              }}>
                {t === 'live-feed' ? <><Icon.Activity />Live Feed</>
                  : t === 'agents' ? <><Icon.Server />AI Agents</>
                    : t === 'actions' ? <><Icon.Activity />Action Log</>
                      : <><Icon.Shield />Blocked IPs</>
                }
              </button>
            ))}
          </div>
          <div className="row">
            <button className="btn" onClick={fetchData} disabled={loading}><Icon.Refresh />Refresh</button>
            <button className="btn" onClick={handleDrill} disabled={drilling} style={{ borderColor: 'var(--y)', color: 'var(--y)' }}>
              <Icon.Activity /> {drilling ? 'Drill in Progress...' : 'Run Security Drill'}
            </button>
            <button className="btn btn-primary" onClick={() => setShowDeploy(true)}><Icon.Plus />Deploy Agent</button>
          </div>
        </div>

        {/* ══════════════════ LIVE FEED TAB ══════════════════ */}
        {tab === 'live-feed' && (
          <div className="scroll-y" ref={feedRef} style={{ flex: 1, maxHeight: 'calc(100vh - 310px)' }}>
            {loading && liveFeed.length === 0 ? (
              <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
                <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading agent activity…
              </div>
            ) : liveFeed.length === 0 ? (
              <div className="empty-state">
                <Icon.Activity style={{ width: 24 }} />
                <p>No agent activity yet. Run an attack simulation or security drill to see agents in action.</p>
              </div>
            ) : (
              <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                {/* Feed Stats Bar */}
                <div style={{
                  display: 'flex', gap: 16, padding: '10px 14px', borderRadius: 10,
                  background: 'linear-gradient(135deg, rgba(59,125,232,0.08), rgba(139,92,246,0.06))',
                  border: '1px solid rgba(59,125,232,0.15)', marginBottom: 8,
                }}>
                  {[
                    { label: 'Total Actions', val: feedStats.total_actions ?? 0, color: 'var(--b)' },
                    { label: 'Success Rate', val: `${feedStats.success_rate ?? 0}%`, color: 'var(--g)' },
                    { label: 'Auto-Blocked', val: feedStats.blocked_ips ?? 0, color: '#ef4444' },
                    { label: 'Forensic Cases', val: feedStats.auto_forensic_cases ?? 0, color: '#8b5cf6' },
                  ].map(s => (
                    <div key={s.label} style={{ flex: 1, textAlign: 'center' }}>
                      <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--t3)', letterSpacing: '0.05em' }}>{s.label}</div>
                      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 18, fontWeight: 600, color: s.color }}>{s.val}</div>
                    </div>
                  ))}
                </div>

                {/* Feed Items */}
                {liveFeed.map((item, i) => (
                  <LiveFeedItem key={item.id || i} item={item} formatTime={formatTime} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* ══════════════════ AGENTS TAB ══════════════════ */}
        {tab === 'agents' && (
          <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 310px)' }}>
            {loading ? (
              <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
                <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading agents…
              </div>
            ) : agentTypes.length === 0 ? (
              <div className="empty-state"><Icon.Server style={{ width: 24 }} /><p>No agents registered</p></div>
            ) : (
              <table className="siem-table">
                <thead>
                  <tr>
                    <th>Agent</th><th>Type</th><th>Actions Today</th><th>Success</th><th>Status</th><th style={{ width: 70, textAlign: 'center' }}>Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {agentTypes.map((agent, i) => {
                    const agentName = agent.name || agent
                    const typeStats = byType.find(b => b._id === agentName) || {}
                    const displayStatus = agent.status || 'operational'
                    return (
                      <tr key={agent.id || agentName}>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontSize: 18 }}>{agentIcons[agentName] || '🤖'}</span>
                            <div>
                              <div style={{ fontWeight: 600, color: 'var(--t1)', marginBottom: 2 }}>{agentName.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</div>
                              <div style={{ fontSize: 10, fontFamily: 'IBM Plex Mono, monospace', color: 'var(--t3)' }}>{agent.description || agentName}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className="tag" style={{ fontSize: 9, color: 'var(--b)', borderColor: 'rgba(59,125,232,0.3)' }}>{agent.type?.replace(/_/g, ' ') || 'AI Agent'}</span>
                        </td>
                        <td>
                          <span className="mono" style={{ fontSize: 13, fontWeight: 600, color: 'var(--t1)' }}>{typeStats.count ?? 0}</span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <div style={{ flex: 1, height: 4, background: 'var(--bg3)', borderRadius: 2, maxWidth: 60 }}>
                              <div style={{
                                height: '100%', borderRadius: 2, background: 'var(--g)',
                                width: typeStats.count ? `${Math.round(typeStats.success / typeStats.count * 100)}%` : '0%'
                              }} />
                            </div>
                            <span className="mono" style={{ fontSize: 11 }}>
                              {typeStats.count ? `${Math.round(typeStats.success / typeStats.count * 100)}%` : '—'}
                            </span>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <div className={`agent-dot dot-${displayStatus === 'offline' ? 'offline' : 'online'}`} />
                            <span style={{
                              color: displayStatus === 'offline' ? 'var(--r)' : 'var(--g)',
                              fontSize: 11,
                              fontWeight: 600
                            }}>
                              {displayStatus.toUpperCase()}
                            </span>
                          </div>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <button
                            className="btn"
                            title={`Remove ${agentName}`}
                            onClick={(e) => { e.stopPropagation(); setDeleteTarget(agent) }}
                            style={{
                              padding: '4px 10px',
                              fontSize: 10,
                              color: 'var(--r)',
                              borderColor: 'rgba(239,68,68,0.35)',
                              background: 'rgba(239,68,68,0.08)',
                              fontWeight: 700,
                              letterSpacing: '0.04em',
                              gap: 4,
                            }}
                          >
                            <Icon.X style={{ width: 12, height: 12 }} />
                            DEL
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ══════════════════ ACTIONS TAB ══════════════════ */}
        {tab === 'actions' && (
          <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 310px)' }}>
            {loading ? (
              <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
                <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading actions…
              </div>
            ) : actions.length === 0 ? (
              <div className="empty-state"><Icon.Activity style={{ width: 24 }} /><p>No agent actions in last 24h</p></div>
            ) : (
              <table className="siem-table">
                <thead>
                  <tr><th>Time</th><th>Agent</th><th>Action</th><th>Alert Target</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {actions.map((a, i) => (
                    <ActionRow key={a.id || i} action={a} formatTime={formatTime} />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ══════════════════ BLOCKED IPS TAB ══════════════════ */}
        {tab === 'blocked-ips' && (
          <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 310px)' }}>
            {loading ? (
              <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
                <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading blocked IPs…
              </div>
            ) : blockedIps.length === 0 ? (
              <div className="empty-state">
                <Icon.Shield style={{ width: 24 }} />
                <p>No IPs currently blocked. Agents will auto-block malicious IPs when threats are detected.</p>
              </div>
            ) : (
              <>
                <div style={{
                  display: 'flex', gap: 12, padding: '12px 16px',
                  background: 'linear-gradient(135deg, rgba(239,68,68,0.06), rgba(239,68,68,0.02))',
                  borderBottom: '1px solid rgba(239,68,68,0.1)',
                }}>
                  <div style={{ flex: 1 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--t3)' }}>Currently Blocked</span>
                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 20, fontWeight: 600, color: '#ef4444' }}>{blockedMeta.active ?? 0}</div>
                  </div>
                  <div style={{ flex: 1 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--t3)' }}>Total Ever Blocked</span>
                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 20, fontWeight: 600, color: 'var(--t2)' }}>{blockedMeta.total ?? 0}</div>
                  </div>
                </div>
                <table className="siem-table">
                  <thead>
                    <tr><th>IP Address</th><th>Blocked At</th><th>Severity</th><th>Reason</th><th>Alert</th><th style={{ width: 90 }}>Action</th></tr>
                  </thead>
                  <tbody>
                    {blockedIps.map((b, i) => (
                      <tr key={b.id || i}>
                        <td>
                          <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: '#ef4444' }}>{b.ip}</span>
                        </td>
                        <td><span className="mono" style={{ fontSize: 11 }}>{formatTime(b.blocked_at)}</span></td>
                        <td>
                          <span className="tag" style={{
                            fontSize: 9, fontWeight: 700,
                            color: sevColor[b.severity] || 'var(--t3)',
                            borderColor: sevColor[b.severity] || 'var(--ln2)',
                            background: `${sevColor[b.severity] || 'var(--bg3)'}15`,
                          }}>
                            {(b.severity || 'unknown').toUpperCase()}
                          </span>
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--t2)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {b.reason}
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--b)' }}>{b.alert_title || '—'}</td>
                        <td>
                          <button
                            className="btn"
                            onClick={() => handleUnblock(b.ip)}
                            disabled={unblocking === b.ip}
                            style={{
                              padding: '4px 10px', fontSize: 10, fontWeight: 700,
                              color: 'var(--g)', borderColor: 'rgba(34,197,94,0.4)',
                              background: 'rgba(34,197,94,0.08)',
                            }}
                          >
                            {unblocking === b.ip ? 'Unblocking…' : '🔓 Unblock'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        )}
      </div>

      {/* ══════════════════ DEPLOY MODAL ══════════════════ */}
      {showDeploy && (
        <div className="modal-overlay" onClick={() => setShowDeploy(false)}>
          <div className="modal-card anim-slide-up" onClick={e => e.stopPropagation()} style={{ maxWidth: 400 }}>
            <div className="modal-head">
              <div className="modal-title">Deploy New AI Agent</div>
              <button className="btn-icon" onClick={() => setShowDeploy(false)}><Icon.X /></button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label className="form-label">Agent Name</label>
                <input
                  className="inp"
                  placeholder="e.g. Threat_Hunter_Beta"
                  value={newAgent.name}
                  onChange={e => setNewAgent({ ...newAgent, name: e.target.value })}
                  autoFocus
                />
              </div>
              <div className="form-group" style={{ marginTop: 15 }}>
                <label className="form-label">Agent Type / Skill</label>
                <select
                  className="sel"
                  style={{ width: '100%', height: 38 }}
                  value={newAgent.type}
                  onChange={e => setNewAgent({ ...newAgent, type: e.target.value })}
                >
                  <option value="ai_agent">Standard AI Agent</option>
                  <option value="soc_agent">SOC Triage Specialist</option>
                  <option value="analyst_agent">Forensic Analyst</option>
                  <option value="responder_agent">Automated Responder</option>
                  <option value="hunter_agent">Threat Hunter Specialist</option>
                  <option value="forensics_agent">Digital Forensics Lead</option>
                </select>
              </div>
              <p style={{ fontSize: 11, color: 'var(--t3)', marginTop: 15 }}>
                Deploying a new agent will allocate a local container instance and register its heartbeat with the central orchestrator.
              </p>
            </div>
            <div className="modal-foot">
              <button className="btn" onClick={() => setShowDeploy(false)}>Cancel</button>
              <button
                className="btn btn-primary"
                onClick={handleDeploy}
                disabled={deploying || !newAgent.name}
              >
                {deploying ? 'Deploying...' : 'Confirm Deployment'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════ DELETE MODAL ══════════════════ */}
      {deleteTarget && (
        <div className="modal-overlay" onClick={() => !deleting && setDeleteTarget(null)}>
          <div className="modal-card anim-slide-up" onClick={e => e.stopPropagation()} style={{ maxWidth: 420 }}>
            <div className="modal-head">
              <div className="modal-title" style={{ color: 'var(--r)' }}>Remove Agent</div>
              <button className="btn-icon" onClick={() => setDeleteTarget(null)} disabled={deleting}><Icon.X /></button>
            </div>
            <div className="modal-body">
              <div style={{ textAlign: 'center', padding: '10px 0 20px' }}>
                <div style={{
                  width: 52, height: 52, borderRadius: '50%', margin: '0 auto 16px',
                  background: 'rgba(239,68,68,0.1)', border: '2px solid rgba(239,68,68,0.3)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center'
                }}>
                  <Icon.X style={{ width: 24, height: 24, color: 'var(--r)' }} />
                </div>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--t1)', marginBottom: 8 }}>
                  Remove "{(deleteTarget.name || deleteTarget).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}"?
                </div>
                <div style={{ fontSize: 12, color: 'var(--t3)', lineHeight: 1.5 }}>
                  This agent will be unregistered and its heartbeat stopped. All historical action logs will remain.
                </div>
              </div>
            </div>
            <div className="modal-foot" style={{ justifyContent: 'center', gap: 10 }}>
              <button className="btn" onClick={() => setDeleteTarget(null)} disabled={deleting}>Cancel</button>
              <button
                className="btn"
                onClick={handleDelete}
                disabled={deleting}
                style={{
                  background: deleting ? 'rgba(239,68,68,0.3)' : 'rgba(239,68,68,0.15)',
                  color: 'var(--r)',
                  borderColor: 'rgba(239,68,68,0.4)',
                  fontWeight: 700,
                }}
              >
                {deleting ? 'Removing...' : 'Yes, Remove Agent'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════ DRILL MODAL ══════════════════ */}
      {showDrill && (
        <div className="modal-overlay" onClick={() => !drilling && setShowDrill(false)}>
          <div className="modal-card anim-slide-up" onClick={e => e.stopPropagation()} style={{ maxWidth: 540 }}>
            <div className="modal-head">
              <div className="modal-title">AI Defense Grid Training (Fire Drill)</div>
              {!drilling && <button className="btn-icon" onClick={() => setShowDrill(false)}><Icon.X /></button>}
            </div>
            <div className="modal-body">
              {drilling && !drillResults ? (
                <div style={{ padding: '30px 0', textAlign: 'center' }}>
                  <div className="live-dot" style={{ background: 'var(--y)', width: 12, height: 12, margin: '0 auto 15px' }} />
                  <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--t1)' }}>Synchronizing Agent Grid...</div>
                  <div style={{ fontSize: 13, color: 'var(--t3)', marginTop: 8 }}>All 5 agents running in parallel — triage, analysis, response, hunting, forensics</div>
                </div>
              ) : drillResults ? (
                <div>
                  <div style={{ background: 'var(--bg3)', padding: 12, borderRadius: 10, marginBottom: 20, borderLeft: '3px solid var(--y)' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--t3)' }}>Target Identified</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--t1)', marginTop: 4 }}>{drillResults.target}</div>
                    <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
                      {drillResults.auto_blocked && (
                        <span className="tag" style={{ fontSize: 9, color: '#ef4444', borderColor: 'rgba(239,68,68,0.4)', background: 'rgba(239,68,68,0.1)' }}>
                          🛡️ IP AUTO-BLOCKED
                        </span>
                      )}
                      {drillResults.forensic_case_id && (
                        <span className="tag" style={{ fontSize: 9, color: '#8b5cf6', borderColor: 'rgba(139,92,246,0.4)', background: 'rgba(139,92,246,0.1)' }}>
                          📂 FORENSIC CASE CREATED
                        </span>
                      )}
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {drillResults.report.map((step, idx) => {
                      const AgentIcon = Icon[step.icon] || Icon.Server
                      return (
                        <div key={idx} className="anim-fade" style={{ animationDelay: `${idx * 0.1}s`, display: 'flex', gap: 15 }}>
                          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                            <div style={{
                              width: 32, height: 32, borderRadius: '50%', background: 'var(--bg2)',
                              display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--ln2)',
                              color: 'var(--b)'
                            }}>
                              <AgentIcon style={{ width: 16 }} />
                            </div>
                            {idx < drillResults.report.length - 1 && (
                              <div style={{ width: 1, flex: 1, background: 'var(--ln2)', margin: '4px 0' }} />
                            )}
                          </div>
                          <div style={{ flex: 1, paddingBottom: 15 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                              <span style={{ fontWeight: 700, color: 'var(--t1)', fontSize: 13 }}>{step.label}</span>
                              <span className="tag" style={{ fontSize: 8, background: 'var(--g-dim)', color: 'var(--g)', border: 'none' }}>CHECKED IN</span>
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--t2)', lineBreak: 'anywhere' }}>
                              {step.result?.summary || step.result?.action || 'Operation successful'}
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              ) : null}
            </div>
            <div className="modal-foot">
              <button className="btn btn-primary" onClick={() => setShowDrill(false)} disabled={drilling}>
                Acknowledge Results
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}


/* ══════════════════ LIVE FEED ITEM ══════════════════ */
function LiveFeedItem({ item, formatTime }) {
  const [expanded, setExpanded] = useState(false)
  const agentName = item.agent_type || 'system'
  const emoji = agentIcons[agentName] || '🤖'
  const isBlock = item.action === 'auto_block_ip'
  const isForensics = item.action === 'evidence_collection'
  const isHunt = item.action === 'proactive_hunt'

  const accentColor = isBlock ? '#ef4444' : isForensics ? '#8b5cf6' : isHunt ? '#f59e0b' : 'var(--b)'

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      className={item._live ? 'anim-fade' : ''}
      style={{
        padding: '10px 14px',
        borderRadius: 10,
        background: item._live ? 'rgba(59,125,232,0.06)' : 'var(--bg2)',
        border: `1px solid ${item._live ? 'rgba(59,125,232,0.2)' : 'var(--ln)'}`,
        cursor: 'pointer',
        transition: 'all 0.15s ease',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {/* Agent Icon */}
        <div style={{
          width: 32, height: 32, borderRadius: '50%',
          background: `${accentColor}15`,
          border: `1.5px solid ${accentColor}40`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 16, flexShrink: 0,
        }}>
          {emoji}
        </div>

        {/* Content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span style={{ fontWeight: 700, color: 'var(--t1)', fontSize: 12 }}>
              {agentName.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
            </span>
            <span className="tag" style={{
              fontSize: 8, border: 'none', padding: '1px 6px',
              background: `${accentColor}20`, color: accentColor,
            }}>
              {(item.action || '').replace(/_/g, ' ').toUpperCase()}
            </span>
            {item._live && (
              <span className="live-dot" style={{ background: 'var(--g)', width: 6, height: 6 }} />
            )}
          </div>
          <div style={{ fontSize: 11, color: 'var(--t2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: expanded ? 'normal' : 'nowrap' }}>
            {item.result || item.details?.summary || 'Processing...'}
          </div>
          {item.alert_title && item.alert_title !== 'System Task' && (
            <div style={{ fontSize: 9, color: 'var(--t3)', marginTop: 2 }}>
              Alert: {item.alert_title}
              {item.source_ip && item.source_ip !== 'N/A' && <> | IP: <span style={{ color: accentColor }}>{item.source_ip}</span></>}
            </div>
          )}
        </div>

        {/* Status & Time */}
        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <div>
            <span className="tag" style={{
              fontSize: 8,
              color: item.success ? 'var(--g)' : 'var(--r)',
              borderColor: item.success ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)',
            }}>
              {item.success ? '✓ SUCCESS' : '✗ FAILED'}
            </span>
          </div>
          <div className="mono" style={{ fontSize: 9, color: 'var(--t4)', marginTop: 3 }}>{formatTime(item.timestamp)}</div>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && item.details && (
        <div className="anim-fade" style={{
          marginTop: 10, padding: 12, borderRadius: 8,
          background: 'var(--bg1)', border: '1px solid var(--ln2)',
        }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase', marginBottom: 8 }}>
            🛡️ Full Agent Report
          </div>
          <pre style={{
            fontSize: 11, color: 'var(--t1)', whiteSpace: 'pre-wrap',
            fontFamily: 'IBM Plex Mono, monospace', lineHeight: 1.5,
            maxHeight: 300, overflow: 'auto', margin: 0,
          }}>
            {typeof item.details === 'string' ? item.details : JSON.stringify(item.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}


/* ══════════════════ ACTION ROW (legacy table) ══════════════════ */
function ActionRow({ action: a, formatTime }) {
  const [ex, setEx] = useState(false)
  return (
    <>
      <tr onClick={() => setEx(!ex)} style={{ cursor: 'pointer' }}>
        <td><span className="mono" style={{ fontSize: 11 }}>{formatTime(a.timestamp)}</span></td>
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 14 }}>{agentIcons[a.agent_type] || '🤖'}</span>
            <span style={{ color: 'var(--t1)', fontWeight: 600 }}>{(a.agent_type || '—').replace(/_/g, ' ')}</span>
          </div>
        </td>
        <td>
          <span className="tag" style={{ border: 'none', background: 'var(--bg3)', fontSize: 10, color: 'var(--t2)' }}>
            {(a.action || '—').toUpperCase()}
          </span>
        </td>
        <td>
          <div style={{ fontWeight: 600, color: 'var(--b)', fontSize: 12 }}>{a.alert_title || '—'}</div>
          {a.hostname && <div style={{ fontSize: 9, color: 'var(--t3)' }}>Host: {a.hostname}</div>}
          {a.source_ip && a.source_ip !== 'N/A' && <div style={{ fontSize: 9, color: 'var(--t3)' }}>IP: {a.source_ip}</div>}
        </td>
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="tag" style={{
              fontSize: 9,
              color: a.success ? 'var(--g)' : 'var(--r)',
              borderColor: 'currentColor'
            }}>{a.success ? 'SUCCESS' : 'FAILED'}</span>
            <span style={{ fontSize: 10, color: 'var(--t4)' }}>{ex ? '▲' : '▼'}</span>
          </div>
        </td>
      </tr>
      {ex && (
        <tr className="anim-fade" style={{ background: 'var(--bg2)' }}>
          <td colSpan={5} style={{ padding: '16px 20px', borderBottom: '2px solid var(--ln)' }}>
            <div className="col">
              <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase', marginBottom: 10, letterSpacing: '0.05em' }}>
                🛡️ Agent Findings & Full Report
              </div>
              <div style={{
                background: 'var(--bg1)',
                padding: '16px',
                borderRadius: 8,
                border: '1px solid var(--ln2)',
                fontSize: 12,
                lineHeight: 1.6,
                color: 'var(--t1)',
                whiteSpace: 'pre-wrap'
              }}>
                {a.details?.summary || (typeof a.details === 'string' ? a.details : JSON.stringify(a.details, null, 2)) || 'No detailed report available for this action.'}
              </div>
              {a.details?.investigation && (
                <div style={{ marginTop: 12, paddingLeft: 12, borderLeft: '3px solid var(--b)' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--b)' }}>Deep Investigation Logic:</span>
                  <p style={{ marginTop: 4, fontSize: 11, color: 'var(--t2)' }}>
                    {a.details.investigation.attack_narrative || 'Analyzing related logs and historical telemetry...'}
                  </p>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
