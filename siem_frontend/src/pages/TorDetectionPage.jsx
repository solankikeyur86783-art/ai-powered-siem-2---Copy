import { useState, useEffect, useRef } from 'react'
import { torApi } from '../services/api.js'
import Icon from '../components/Icons.jsx'

const TOR_PORTS = [9001, 9030, 9050, 9051, 9150, 9151]
const s = (n) => `${n}`

function StatCard({ label, value, sub, color = 'var(--b)', icon }) {
  const Ico = Icon[icon] || Icon.Shield
  return (
    <div className="stat-card">
      <div className="stat-bar" style={{ background: color }} />
      <div className="stat-label">{label}</div>
      <div className="stat-num" style={{ color }}>{value ?? '—'}</div>
      <div className="stat-sub" style={{ color: 'var(--t4)', fontSize: 11 }}>{sub}</div>
      <div className="stat-ico" style={{ background: color + '22' }}>
        <Ico style={{ width: 15, height: 15, color }} />
      </div>
    </div>
  )
}

function Badge({ text, color }) {
  return (
    <span style={{
      background: color + '22', color, border: `1px solid ${color}55`,
      borderRadius: 4, padding: '2px 7px', fontSize: 10, fontWeight: 700,
      fontFamily: 'IBM Plex Mono, monospace', whiteSpace: 'nowrap'
    }}>{text}</span>
  )
}

export default function TorDetectionPage() {
  const [stats, setStats]         = useState(null)
  const [alerts, setAlerts]       = useState([])
  const [tickets, setTickets]     = useState([])
  const [blocked, setBlocked]     = useState([])
  const [loading, setLoading]     = useState(true)
  const [scanLoading, setScanLoading] = useState(false)
  const [scanResult, setScanResult]   = useState(null)
  const [ipInput, setIpInput]     = useState('')
  const [ipResult, setIpResult]   = useState(null)
  const [ipLoading, setIpLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('alerts')
  const [irLoading, setIrLoading] = useState({})
  const [irResults, setIrResults] = useState({})
  const [behaviorEvent, setBehaviorEvent] = useState({
    source_ip: '', dest_port: '', request_count: 0,
    unique_ua_count: 0, user_agent: '', is_encrypted: false
  })
  const [behaviorResult, setBehaviorResult] = useState(null)
  const [behaviorLoading, setBehaviorLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  const load = async () => {
    try {
      const [s, a, t, b] = await Promise.allSettled([
        torApi.stats(24), torApi.alerts(24), torApi.tickets(), torApi.blocked()
      ])
      if (s.status === 'fulfilled') setStats(s.value)
      if (a.status === 'fulfilled') setAlerts(a.value.alerts || [])
      if (t.status === 'fulfilled') setTickets(t.value.tickets || [])
      if (b.status === 'fulfilled') setBlocked(b.value.blocked_ips || [])
    } catch(e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => { load(); const i = setInterval(load, 30000); return () => clearInterval(i) }, [])

  const handleScan = async () => {
    setScanLoading(true); setScanResult(null)
    try { const r = await torApi.scan(24); setScanResult(r); await load() }
    catch(e) { setScanResult({ error: e.message }) }
    finally { setScanLoading(false) }
  }

  const handleCheckIp = async () => {
    if (!ipInput.trim()) return
    setIpLoading(true); setIpResult(null)
    try { const r = await torApi.checkIp(ipInput.trim()); setIpResult(r); await load() }
    catch(e) { setIpResult({ error: e.message }) }
    finally { setIpLoading(false) }
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    try { await torApi.refresh(); await load() }
    catch(e) {}
    finally { setRefreshing(false) }
  }

  const handleIR = async (ip, alertId) => {
    setIrLoading(p => ({ ...p, [ip]: true }))
    try {
      const r = await torApi.triggerIR(ip, alertId)
      setIrResults(p => ({ ...p, [ip]: r }))
      await load()
    } catch(e) { setIrResults(p => ({ ...p, [ip]: { error: e.message } })) }
    finally { setIrLoading(p => ({ ...p, [ip]: false })) }
  }

  const handleBehavior = async () => {
    setBehaviorLoading(true); setBehaviorResult(null)
    try {
      const ev = { ...behaviorEvent, dest_port: Number(behaviorEvent.dest_port) || 0 }
      const r = await torApi.behavioral(ev)
      setBehaviorResult(r); await load()
    } catch(e) { setBehaviorResult({ error: e.message }) }
    finally { setBehaviorLoading(false) }
  }

  const feedOk = stats?.feed_ok
  const nodeCount = stats?.node_count ?? 0

  if (loading) return (
    <div className="page-content anim-fade">
      <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--t3)' }}>
        <span className="live-dot" style={{ background: 'var(--b)', display: 'inline-block', marginRight: 8 }} />
        Loading Tor Detection…
      </div>
    </div>
  )

  return (
    <div className="page-content anim-fade">

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 22, fontWeight: 700, margin: 0, color: 'var(--t1)', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 22 }}>🧅</span> Tor Detection Center
          </h2>
          <p style={{ margin: '4px 0 0', color: 'var(--t4)', fontSize: 12 }}>
            Live Tor exit-node feed · Behavioral analysis · Automated IR
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={handleRefresh} disabled={refreshing}
            style={{ opacity: refreshing ? 0.6 : 1 }}>
            {refreshing ? '⟳ Refreshing…' : '⟳ Refresh Feed'}
          </button>
          <button className="btn" onClick={handleScan} disabled={scanLoading}
            style={{ background: scanLoading ? 'var(--surface2)' : 'var(--b)', color: scanLoading ? 'var(--t3)' : '#fff', border: 'none' }}>
            {scanLoading ? '⟳ Scanning…' : '⚡ Scan Logs Now'}
          </button>
        </div>
      </div>

      {/* Feed Banner */}
      <div style={{
        background: feedOk ? 'rgba(48,209,88,0.07)' : 'rgba(255,59,48,0.07)',
        border: `1px solid ${feedOk ? 'rgba(48,209,88,0.25)' : 'rgba(255,59,48,0.25)'}`,
        borderRadius: 10, padding: '12px 18px', marginBottom: 18,
        display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap'
      }}>
        <span style={{ fontSize: 18 }}>{feedOk ? '🟢' : '🔴'}</span>
        <div>
          <div style={{ fontWeight: 700, color: feedOk ? 'var(--g)' : 'var(--r)', fontSize: 13 }}>
            Tor Exit Node Feed — {feedOk ? 'LIVE' : 'OFFLINE'}
          </div>
          <div style={{ color: 'var(--t4)', fontSize: 11 }}>
            {nodeCount.toLocaleString()} exit nodes loaded
            {stats?.last_refresh ? ` · Refreshed ${new Date(stats.last_refresh).toLocaleTimeString()}` : ''}
            {' · Auto-refresh every 30 min'}
          </div>
        </div>
        <span style={{ marginLeft: 'auto', fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: 'var(--t3)' }}>
          check.torproject.org/torbulkexitlist
        </span>
      </div>

      {/* Stat Cards */}
      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <StatCard label="Exit Nodes" value={nodeCount.toLocaleString()} sub="in live feed" color="var(--b)" icon="Shield" />
        <StatCard label="Tor Alerts (24h)" value={stats?.tor_alerts_24h ?? 0} sub="HIGH severity" color="var(--o)" icon="Alert" />
        <StatCard label="IR Tickets (24h)" value={stats?.ir_tickets_24h ?? 0} sub="auto-created" color="var(--r)" icon="File" />
        <StatCard label="Blocked IPs" value={stats?.blocked_ips_total ?? 0} sub="auto-blocked" color="#8b5cf6" icon="Lock" />
      </div>

      {/* Scan Result Banner */}
      {scanResult && (
        <div style={{
          background: scanResult.error ? 'rgba(255,59,48,0.08)' : 'rgba(48,209,88,0.08)',
          border: `1px solid ${scanResult.error ? 'rgba(255,59,48,0.3)' : 'rgba(48,209,88,0.3)'}`,
          borderRadius: 8, padding: '12px 16px', marginBottom: 16,
          color: scanResult.error ? 'var(--r)' : 'var(--g)', fontSize: 13
        }}>
          {scanResult.error
            ? `❌ Scan error: ${scanResult.error}`
            : `✅ Scan complete — ${scanResult.matches_found} Tor IPs found in last 24h · ${scanResult.alerts_created?.length ?? 0} alerts created`
          }
        </div>
      )}

      {/* Two columns: IP Checker + Behavioral Analyzer */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 18 }}>

        {/* IP Checker */}
        <div className="card">
          <div className="card-head">
            <div className="card-title"><Icon.Search />IP Tor Checker</div>
          </div>
          <div style={{ padding: '0 16px 16px' }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              <input
                id="tor-ip-input"
                value={ipInput}
                onChange={e => setIpInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleCheckIp()}
                placeholder="Enter IP address…"
                style={{
                  flex: 1, background: 'var(--surface2)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '8px 12px', color: 'var(--t1)', fontSize: 13,
                  fontFamily: 'IBM Plex Mono, monospace', outline: 'none'
                }}
              />
              <button className="btn" onClick={handleCheckIp} disabled={ipLoading}
                style={{ background: 'var(--b)', color: '#fff', border: 'none', minWidth: 80 }}>
                {ipLoading ? '…' : 'Check'}
              </button>
            </div>
            {ipResult && !ipResult.error && (
              <div style={{
                background: ipResult.is_tor_exit_node ? 'rgba(255,59,48,0.08)' : 'rgba(48,209,88,0.08)',
                border: `1px solid ${ipResult.is_tor_exit_node ? 'rgba(255,59,48,0.3)' : 'rgba(48,209,88,0.3)'}`,
                borderRadius: 8, padding: '12px 14px'
              }}>
                <div style={{ fontWeight: 700, fontSize: 14, color: ipResult.is_tor_exit_node ? 'var(--r)' : 'var(--g)', marginBottom: 6 }}>
                  {ipResult.is_tor_exit_node ? '🧅 CONFIRMED TOR EXIT NODE' : '✅ NOT a Tor Exit Node'}
                </div>
                <div style={{ fontSize: 11, color: 'var(--t3)', fontFamily: 'IBM Plex Mono, monospace' }}>
                  IP: {ipResult.ip} · Feed: {ipResult.feed_node_count?.toLocaleString()} nodes
                </div>
                {ipResult.is_tor_exit_node && (
                  <button className="btn" onClick={() => handleIR(ipResult.ip, ipResult.alert_id)}
                    disabled={irLoading[ipResult.ip]}
                    style={{ marginTop: 10, background: 'var(--r)', color: '#fff', border: 'none', fontSize: 12 }}>
                    {irLoading[ipResult.ip] ? '⟳ Running IR…' : '🚨 Trigger IR Workflow'}
                  </button>
                )}
              </div>
            )}
            {ipResult?.error && (
              <div style={{ color: 'var(--r)', fontSize: 12 }}>❌ {ipResult.error}</div>
            )}
          </div>
        </div>

        {/* Behavioral Analyzer */}
        <div className="card">
          <div className="card-head">
            <div className="card-title"><Icon.Activity />Behavioral Signal Analyzer</div>
          </div>
          <div style={{ padding: '0 16px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              { key: 'source_ip', label: 'Source IP', placeholder: '1.2.3.4' },
              { key: 'dest_port', label: 'Dest Port', placeholder: `e.g. ${TOR_PORTS[0]}` },
              { key: 'request_count', label: 'Request Count', placeholder: '>100 = signal', type: 'number' },
              { key: 'unique_ua_count', label: 'Unique User-Agents', placeholder: '>3 = signal', type: 'number' },
              { key: 'user_agent', label: 'User-Agent', placeholder: 'Tor Browser…' },
            ].map(f => (
              <div key={f.key} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <label style={{ fontSize: 10, color: 'var(--t4)', width: 120, flexShrink: 0, letterSpacing: '0.07em' }}>{f.label.toUpperCase()}</label>
                <input
                  type={f.type || 'text'}
                  value={behaviorEvent[f.key]}
                  onChange={e => setBehaviorEvent(p => ({ ...p, [f.key]: f.type === 'number' ? Number(e.target.value) : e.target.value }))}
                  placeholder={f.placeholder}
                  style={{
                    flex: 1, background: 'var(--surface2)', border: '1px solid var(--border)',
                    borderRadius: 5, padding: '6px 10px', color: 'var(--t1)', fontSize: 12,
                    fontFamily: 'IBM Plex Mono, monospace', outline: 'none'
                  }}
                />
              </div>
            ))}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <label style={{ fontSize: 10, color: 'var(--t4)', width: 120, letterSpacing: '0.07em' }}>ENCRYPTED TRAFFIC</label>
              <input type="checkbox" checked={behaviorEvent.is_encrypted}
                onChange={e => setBehaviorEvent(p => ({ ...p, is_encrypted: e.target.checked }))} />
            </div>
            <button className="btn" onClick={handleBehavior} disabled={behaviorLoading}
              style={{ background: 'var(--o)', color: '#fff', border: 'none', marginTop: 4 }}>
              {behaviorLoading ? '⟳ Analyzing…' : '🔍 Analyze Signals'}
            </button>
            {behaviorResult && !behaviorResult.error && (
              <div style={{
                background: behaviorResult.is_suspicious ? 'rgba(255,59,48,0.08)' : 'rgba(48,209,88,0.08)',
                border: `1px solid ${behaviorResult.is_suspicious ? 'rgba(255,59,48,0.3)' : 'rgba(48,209,88,0.3)'}`,
                borderRadius: 8, padding: '10px 12px', marginTop: 4
              }}>
                <div style={{ fontWeight: 700, color: behaviorResult.is_suspicious ? 'var(--r)' : 'var(--g)', fontSize: 13, marginBottom: 6 }}>
                  {behaviorResult.is_suspicious ? '⚠ SUSPICIOUS — Tor-like behavior' : '✅ Clean — insufficient signals'}
                </div>
                <div style={{ fontSize: 11, color: 'var(--t3)', marginBottom: 4 }}>
                  Score: {behaviorResult.behavioral_score}/5 signals matched
                </div>
                {behaviorResult.signals?.map((sig, i) => (
                  <div key={i} style={{ fontSize: 11, color: 'var(--o)', fontFamily: 'IBM Plex Mono, monospace' }}>
                    ▸ {sig.description}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tabs: Alerts / Tickets / Blocked */}
      <div className="card">
        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)' }}>
          {[
            { key: 'alerts', label: `Tor Alerts (${alerts.length})` },
            { key: 'tickets', label: `IR Tickets (${tickets.length})` },
            { key: 'blocked', label: `Blocked IPs (${blocked.length})` },
          ].map(t => (
            <button key={t.key} onClick={() => setActiveTab(t.key)} style={{
              padding: '12px 20px', background: 'transparent', border: 'none',
              borderBottom: activeTab === t.key ? '2px solid var(--b)' : '2px solid transparent',
              color: activeTab === t.key ? 'var(--t1)' : 'var(--t3)',
              fontWeight: activeTab === t.key ? 700 : 400, fontSize: 13, cursor: 'pointer',
              fontFamily: 'Manrope, sans-serif'
            }}>{t.label}</button>
          ))}
        </div>

        {/* Alerts Tab */}
        {activeTab === 'alerts' && (
          <div className="tbl-scroll">
            <table className="siem-table">
              <thead><tr>
                <th>IP</th><th>Title</th><th>Severity</th><th>Events</th><th>Created</th><th>Action</th>
              </tr></thead>
              <tbody>
                {alerts.length === 0 ? (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--t3)', padding: 24 }}>
                    No Tor alerts in last 24h
                  </td></tr>
                ) : alerts.map((a, i) => (
                  <tr key={a.id || i}>
                    <td><span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: 'var(--r)' }}>{a.source_ip || '—'}</span></td>
                    <td style={{ fontSize: 12 }}>{a.title}</td>
                    <td><Badge text={(a.severity || 'HIGH').toUpperCase()} color="var(--o)" /></td>
                    <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12 }}>{a.event_count ?? 1}</td>
                    <td style={{ fontSize: 11, color: 'var(--t4)' }}>
                      {a.created_at ? new Date(a.created_at).toLocaleString() : '—'}
                    </td>
                    <td>
                      {irResults[a.source_ip]?.success
                        ? <Badge text="IR Done ✓" color="var(--g)" />
                        : <button className="btn" onClick={() => handleIR(a.source_ip, a.id)}
                            disabled={irLoading[a.source_ip]}
                            style={{ fontSize: 11, background: 'var(--r)', color: '#fff', border: 'none', padding: '4px 10px' }}>
                            {irLoading[a.source_ip] ? '⟳' : '🚨 IR'}
                          </button>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* IR Tickets Tab */}
        {activeTab === 'tickets' && (
          <div className="tbl-scroll">
            <table className="siem-table">
              <thead><tr>
                <th>Ticket ID</th><th>IP</th><th>Title</th><th>Status</th><th>Created</th>
              </tr></thead>
              <tbody>
                {tickets.length === 0 ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--t3)', padding: 24 }}>No IR tickets yet</td></tr>
                ) : tickets.map((t, i) => (
                  <tr key={t.id || i}>
                    <td><span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: 'var(--b)' }}>{t.ticket_id}</span></td>
                    <td><span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: 'var(--r)' }}>{t.source_ip}</span></td>
                    <td style={{ fontSize: 12 }}>{t.title}</td>
                    <td><Badge text={(t.status || 'open').toUpperCase()} color={t.status === 'closed' ? 'var(--g)' : 'var(--o)'} /></td>
                    <td style={{ fontSize: 11, color: 'var(--t4)' }}>
                      {t.created_at ? new Date(t.created_at).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Blocked IPs Tab */}
        {activeTab === 'blocked' && (
          <div className="tbl-scroll">
            <table className="siem-table">
              <thead><tr>
                <th>IP</th><th>Reason</th><th>Auto-Blocked</th><th>Blocked At</th>
              </tr></thead>
              <tbody>
                {blocked.length === 0 ? (
                  <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--t3)', padding: 24 }}>No blocked Tor IPs</td></tr>
                ) : blocked.map((b, i) => (
                  <tr key={b.id || i}>
                    <td><span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: 'var(--r)' }}>{b.ip}</span></td>
                    <td><Badge text="tor_exit_node" color="#8b5cf6" /></td>
                    <td><Badge text={b.auto_blocked ? 'AUTO' : 'MANUAL'} color={b.auto_blocked ? 'var(--o)' : 'var(--t3)'} /></td>
                    <td style={{ fontSize: 11, color: 'var(--t4)' }}>
                      {b.blocked_at ? new Date(b.blocked_at).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* IR Result banners */}
      {Object.entries(irResults).map(([ip, res]) => res && (
        <div key={ip} style={{
          marginTop: 12, background: res.error ? 'rgba(255,59,48,0.08)' : 'rgba(48,209,88,0.08)',
          border: `1px solid ${res.error ? 'rgba(255,59,48,0.3)' : 'rgba(48,209,88,0.3)'}`,
          borderRadius: 8, padding: '12px 16px'
        }}>
          {res.error
            ? <span style={{ color: 'var(--r)' }}>❌ IR failed for {ip}: {res.error}</span>
            : <div>
                <div style={{ fontWeight: 700, color: 'var(--g)', marginBottom: 6 }}>
                  ✅ IR Workflow complete for {ip} · Ticket: {res.ticket_id}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {res.steps_executed?.map((st, i) => (
                    <span key={i} style={{
                      fontSize: 11, fontFamily: 'IBM Plex Mono, monospace',
                      background: 'var(--surface2)', borderRadius: 4, padding: '3px 8px', color: 'var(--t3)'
                    }}>
                      Step {st.step}: {st.action} → {st.status}
                    </span>
                  ))}
                </div>
              </div>
          }
        </div>
      ))}

    </div>
  )
}
