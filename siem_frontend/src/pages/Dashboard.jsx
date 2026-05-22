import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Sparkline from '../components/Sparkline.jsx'
import DonutChart from '../components/DonutChart.jsx'
import Icon from '../components/Icons.jsx'
import { dashboardApi, aiApi, torApi } from '../services/api.js'

const sevColor = { critical: 'var(--r)', high: 'var(--o)', medium: 'var(--y)', low: 'var(--g)', info: 'var(--b)' }

const MITRE_COLOR = {
  CRITICAL: { color: '#ff2d55', bg: 'rgba(255,45,85,0.08)', border: 'rgba(255,45,85,0.25)' },
  HIGH:     { color: '#ff9500', bg: 'rgba(255,149,0,0.08)', border: 'rgba(255,149,0,0.25)' },
  MEDIUM:   { color: '#ffd60a', bg: 'rgba(255,214,10,0.08)', border: 'rgba(255,214,10,0.25)' },
  LOW:      { color: '#30d158', bg: 'rgba(48,209,88,0.08)',  border: 'rgba(48,209,88,0.25)' },
  INFO:     { color: 'var(--t3)', bg: 'transparent',          border: 'var(--border)' },
}

const ATTACK_ICON = {
  Normal: '◉', DoS: '⚡', Exploits: '💀', Reconnaissance: '👁',
  Generic: '⚠', Fuzzers: '🔀', Backdoor: '🚪', Analysis: '🔬',
  Shellcode: '💉', Worms: '🪱',
}

// ── ML Prediction Row ────────────────────────────────────
function PredictionRow({ p }) {
  const [open, setOpen] = useState(false)
  const isNormal = p.attack_type === 'Normal'
  const cfg = MITRE_COLOR[p.severity] || MITRE_COLOR.INFO
  const pct = Math.round((p.confidence || 0) * 100)

  return (
    <div
      onClick={() => setOpen(o => !o)}
      style={{
        borderBottom: '1px solid var(--border)',
        cursor: 'pointer',
        background: open ? cfg.bg : 'transparent',
        transition: 'background 0.15s',
      }}
    >
      {/* Main row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 16px' }}>

        {/* Attack icon + type */}
        <span style={{ fontSize: 15, width: 20, textAlign: 'center', flexShrink: 0 }}>
          {ATTACK_ICON[p.attack_type] || '⚠'}
        </span>
        <span style={{
          fontFamily: 'IBM Plex Mono, monospace',
          fontSize: 12, fontWeight: 600,
          color: isNormal ? 'var(--t3)' : cfg.color,
          minWidth: 110,
        }}>
          {p.attack_type}
        </span>

        {/* Severity badge */}
        <span className={`sev sev-${p.severity}`} style={{ flexShrink: 0 }}>
          {p.severity}
        </span>

        {/* Confidence bar */}
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ flex: 1, height: 3, background: 'var(--surface2)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{
              width: `${pct}%`, height: '100%', borderRadius: 2,
              background: pct >= 70 ? '#ff2d55' : pct >= 50 ? '#ff9500' : 'var(--t3)',
              transition: 'width 0.4s',
            }} />
          </div>
          <span style={{ fontSize: 10, fontFamily: 'IBM Plex Mono, monospace', color: 'var(--t3)', minWidth: 32 }}>
            {pct}%
          </span>
        </div>

        {/* Source IP */}
        <span style={{
          fontSize: 11, fontFamily: 'IBM Plex Mono, monospace',
          color: p.source_ip !== 'unknown' ? 'var(--r)' : 'var(--t4)',
          minWidth: 120, textAlign: 'right', flexShrink: 0,
        }}>
          {p.source_ip !== 'unknown' ? p.source_ip : '—'}
        </span>

        {/* Time */}
        <span style={{ fontSize: 10, color: 'var(--t4)', fontFamily: 'IBM Plex Mono, monospace', minWidth: 55, textAlign: 'right' }}>
          {p.timestamp ? String(p.timestamp).slice(11, 19) : '—'}
        </span>

        <span style={{ color: 'var(--t4)', fontSize: 10 }}>{open ? '▲' : '▼'}</span>
      </div>

      {/* Expanded detail */}
      {open && (
        <div style={{ padding: '0 16px 12px 46px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 20px' }}>
          <Detail label="MITRE Technique" value={p.technique_id !== 'None' ? `[${p.technique_id}] ${p.mitre_technique}` : '—'} color={cfg.color} />
          <Detail label="Tactic"         value={p.mitre_tactic || '—'} />
          <Detail label="Hostname"       value={p.hostname || '—'} />
          <Detail label="Detail"         value={p.dest_ip !== 'unknown' ? p.dest_ip : '—'} />
          <Detail label="Event ID"       value={p.event_id || '—'} />
          <Detail label="Log Source"     value={p.log_source || '—'} />
          {p.description && p.description !== 'Normal network traffic — no threat detected.' && (
            <div style={{ gridColumn: 'span 2' }}>
              <div style={{
                background: cfg.bg, border: `1px solid ${cfg.border}`,
                borderRadius: 6, padding: '7px 10px',
                fontSize: 11, color: cfg.color, fontFamily: 'IBM Plex Mono, monospace', lineHeight: 1.6,
              }}>
                ⚠ {p.description}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Detail({ label, value, color }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: 'var(--t4)', letterSpacing: '0.1em', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 11, color: color || 'var(--t2)', fontFamily: 'IBM Plex Mono, monospace' }}>{value}</div>
    </div>
  )
}

// ── Main Dashboard ───────────────────────────────────────
export default function Dashboard() {
  const [data, setData]               = useState(null)
  const [loading, setLoading]         = useState(true)
  const [mlPredictions, setMlPredictions] = useState([])
  const [mlScanning, setMlScanning]   = useState(false)
  const [mlMeta, setMlMeta]           = useState(null)
  const [mlFilter, setMlFilter]       = useState('ALL')
  const [mlScanSuccess, setMlScanSuccess] = useState(false)
  const [mlLastScan, setMlLastScan]   = useState(null)
  const [timeRange, setTimeRange]     = useState(24)
  const [ipSeverity, setIpSeverity]   = useState('all')
  const [torStats, setTorStats]        = useState(null)
  const wsRef = useRef(null)
  const navigate = useNavigate()

  const exportData = (payload, filename) => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${filename}_${new Date().toISOString().split('T')[0]}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  const handleTimeChange = (e) => {
    const v = Number(e.target.value)
    setTimeRange(v)
  }

  // ── Fetch dashboard stats ────────────────────────────
  const fetchDashboard = async () => {
    try {
      // Always use current ref if set, else state. But React state closures in interval are tricky,
      // so we will pass timeRange directly over useEffect instead and clear interval.
      const d = await dashboardApi.get(timeRange, ipSeverity)
      setData(d)
    } catch (e) {
      console.error('Dashboard fetch error:', e)
    } finally {
      setLoading(false)
    }
  }

  // ── Fetch ML predictions ─────────────────────────────
  const runMlScan = async () => {
    setMlScanning(true)
    setMlScanSuccess(false)
    try {
      const json = await aiApi.scan()
      if (json.status === 'ok') {
        setMlPredictions(json.predictions || [])
        setMlMeta({ scanned: json.logs_scanned, threats: json.threats_found, total: json.total_predictions })
        setMlLastScan(new Date())
        
        // Show success flash
        setMlScanSuccess(true)
        setTimeout(() => setMlScanSuccess(false), 2000)
      }
    } catch (e) {
      console.error('ML scan error:', e)
    } finally {
      setMlScanning(false)
    }
  }

  // Separate useEffect for data fetching so it reflects timeRange
  useEffect(() => {
    fetchDashboard()
    const interval = setInterval(fetchDashboard, 30000)
    return () => clearInterval(interval)
  }, [timeRange, ipSeverity])

  // Fetch Tor stats
  useEffect(() => {
    const fetchTor = async () => {
      try { const t = await torApi.stats(24); setTorStats(t) } catch {}
    }
    fetchTor()
    const i = setInterval(fetchTor, 60000)
    return () => clearInterval(i)
  }, [])

  // Separate useEffect for ML scan and Websocket
  useEffect(() => {
    runMlScan()

    const ws = new WebSocket('ws://localhost:8000/ws')
    wsRef.current = ws
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'live_stats') {
          setData(prev => prev ? { ...prev, counts: { ...prev.counts, ...msg.data }, live: msg.data } : prev)
        }
        if (msg.type === 'anomaly_alert') {
          runMlScan()  // auto-refresh ML panel on anomaly
        }
      } catch {}
    }
    ws.onerror = () => {}

    const mlInterval = setInterval(runMlScan, 60000)  // ML scan every 60s
    return () => {
      clearInterval(mlInterval)
      ws.close()
    }
  }, [])

  const counts      = data?.counts || {}
  const recentAlerts = data?.recent_alerts || []
  const topIps      = data?.top_attacking_ips || []
  const hourlyLogs  = data?.hourly_logs || []
  const threatDist  = data?.threat_distribution || []

  const stats = [
    { label: 'Total Logs Today', num: counts.total_logs_today ?? '—', delta: `+${counts.logs_last_hour ?? 0}/hr`, up: true, color: 'var(--b)', bg: 'var(--b-dim)', icon: 'Activity', sub: 'last hour' },
    { label: 'Threat Events',    num: counts.threats_today ?? '—',    delta: counts.critical_alerts > 0 ? `${counts.critical_alerts} critical` : 'Clear', up: (counts.critical_alerts ?? 0) === 0, color: 'var(--r)', bg: 'var(--r-dim)', icon: 'Alert', sub: 'last 24h' },
    { label: 'Open Alerts',      num: counts.open_alerts ?? '—',      delta: `${counts.high_alerts ?? 0} high`, up: (counts.open_alerts ?? 0) === 0, color: 'var(--o)', bg: 'var(--o-dim)', icon: 'File', sub: 'require action' },
    { label: 'AI Detections',    num: mlMeta?.threats ?? '—',         delta: mlMeta ? `${mlMeta.scanned} scanned` : 'scanning…', up: (mlMeta?.threats ?? 0) === 0, color: 'var(--g)', bg: 'var(--g-dim)', icon: 'Server', sub: 'ML model' },
    { label: 'Tor Exit Nodes',   num: torStats?.tor_alerts_24h ?? 0,  delta: torStats?.node_count ? `${torStats.node_count.toLocaleString()} in feed` : 'feed loading…', up: (torStats?.tor_alerts_24h ?? 0) === 0, color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)', icon: 'Shield', sub: 'Tor detections' },
  ]

  // ML filter logic
  const mlFiltered = mlFilter === 'ALL'     ? mlPredictions
    : mlFilter === 'THREATS'                ? mlPredictions.filter(p => p.attack_type !== 'Normal')
    : mlPredictions.filter(p => p.severity === mlFilter)

  const mlThreats  = mlPredictions.filter(p => p.attack_type !== 'Normal')
  const mlCritical = mlPredictions.filter(p => p.severity === 'CRITICAL').length
  const mlHigh     = mlPredictions.filter(p => p.severity === 'HIGH').length

  const colors = ['#2db87a','#3b7de8','#8b5cf6','#d4a017','#e84646','var(--t4)']
  const donutSegs = threatDist.slice(0, 6).map((t, i) => ({ color: colors[i] || 'var(--t4)', label: t.type || 'unknown', pct: t.count }))
  const totalThreatCount = threatDist.reduce((a, t) => a + t.count, 0) || 0

  if (loading) return (
    <div className="page-content anim-fade">
      <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--t3)' }}>
        <div className="row" style={{ justifyContent: 'center', gap: 10 }}>
          <span className="live-dot" style={{ background: 'var(--b)' }} />
          Loading dashboard…
        </div>
      </div>
    </div>
  )

  return (
    <div className="page-content anim-fade">

      {/* Dashboard Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h2 style={{ fontSize: 22, color: 'var(--t1)', margin: 0, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
          Security Overview
        </h2>
        <button
          className="btn"
          onClick={() => {
            const panel = document.getElementById('ai-predictions-panel')
            if (panel) {
              panel.scrollIntoView({ behavior: 'smooth', block: 'start' })
            }
            runMlScan()
          }}
          disabled={mlScanning}
          style={{
            background: mlScanSuccess ? 'var(--g)' : 'var(--b)',
            color: '#fff',
            border: 'none',
            padding: '10px 18px',
            fontSize: 13,
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            boxShadow: mlScanSuccess ? '0 4px 12px rgba(48, 209, 88, 0.3)' : '0 4px 12px rgba(59, 125, 232, 0.3)',
            opacity: mlScanning ? 0.7 : 1,
            cursor: mlScanning ? 'default' : 'pointer',
            transition: 'all 0.2s'
          }}
        >
          {mlScanSuccess ? <Icon.Check style={{ width: 16, height: 16 }} /> : <Icon.Server style={{ width: 16, height: 16 }} />}
          {mlScanning ? 'Running AI Fast Scan...' : mlScanSuccess ? 'Scan Complete!' : 'Run Quick AI Detection'}
        </button>
      </div>

      {/* Stat Cards */}
      <div className="stat-grid">
        {stats.map(s => {
          const Ico = Icon[s.icon]
          return (
            <div className="stat-card" key={s.label}>
              <div className="stat-bar" style={{ background: s.color }} />
              <div className="stat-label">{s.label}</div>
              <div className="stat-num" style={{ color: s.up ? 'var(--t1)' : s.color }}>{s.num}</div>
              <div className="stat-sub">
                {s.up
                  ? <Icon.TrendUp style={{ width: 11, height: 11, color: 'var(--g)' }} />
                  : <Icon.TrendDn style={{ width: 11, height: 11, color: 'var(--r)' }} />
                }
                <span className={s.up ? 'delta-up' : 'delta-dn'}>{s.delta}</span>
                {s.sub}
              </div>
              <div className="stat-ico" style={{ background: s.bg }}>
                <Ico style={{ width: 15, height: 15, color: s.color }} />
              </div>
            </div>
          )
        })}
      </div>

      {/* Mid: Chart + Feed */}
      <div className="mid-grid">
        <div className="card">
          <div className="card-head">
            <div className="card-title">
              <Icon.Activity />
              Events over time
              <span className="live-tag" style={{ marginLeft: 6 }}>
                <span className="live-dot" />
                Live
              </span>
            </div>
            <div className="row">
              <select className="sel" value={timeRange} onChange={handleTimeChange}>
                <option value={12}>12 hr</option>
                <option value={24}>24 hr</option>
                <option value={72}>3 days</option>
                <option value={168}>7 days</option>
              </select>
              <button className="btn" onClick={() => exportData(hourlyLogs, 'event_metrics')}><Icon.Download />Export</button>
            </div>
          </div>
          <div className="chart-wrap">
            <Sparkline data={hourlyLogs} />
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <div className="card-title"><Icon.Lock />Live Threat Feed</div>
            <button className="card-action" onClick={() => navigate('/alerts')}>View all</button>
          </div>
          <div className="feed-list">
            {recentAlerts.length === 0 && (
              <div className="empty-state" style={{ padding: 24 }}>
                <Icon.Check style={{ width: 20, height: 20, color: 'var(--g)' }} />
                <p>No recent threats</p>
              </div>
            )}
            {recentAlerts.map((a, i) => {
              const sev = (a.severity || 'low')[0]
              return (
                <div className="feed-item" key={a.id || i}>
                  <div className="feed-dot" style={{
                    background: sevColor[a.severity] || 'var(--b)',
                    boxShadow: `0 0 6px ${sevColor[a.severity] || 'var(--b)'}`,
                    animation: a.severity === 'critical' ? 'blink 1.8s infinite' : 'none'
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="feed-rule">{a.title || a.rule_name || 'Alert'}</div>
                    <div className="feed-meta">
                      <span>{a.source_ip || '—'}</span>
                      <span>{a.severity?.toUpperCase()}</span>
                    </div>
                  </div>
                  <div className="feed-time">
                    {a.created_at ? new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* ── ML PREDICTIONS PANEL ─────────────────────── */}
      <div id="ai-predictions-panel" className="card" style={{ marginBottom: 0 }}>
        <div className="card-head">
          <div className="card-title">
            <Icon.Server />
            AI Threat Predictions
            <span className="live-tag" style={{ marginLeft: 6 }}>
              <span className="live-dot" style={{ background: mlScanning ? 'var(--y)' : 'var(--g)' }} />
              {mlScanning ? 'Scanning…' : mlLastScan ? `Updated ${mlLastScan.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'ML Model'}
            </span>
          </div>
          <div className="row" style={{ gap: 8 }}>
            {/* Quick stats */}
            <span style={{ fontSize: 11, color: 'var(--r)', fontFamily: 'IBM Plex Mono, monospace' }}>
              {mlCritical > 0 ? `⚡ ${mlCritical} critical` : ''}
            </span>
            <span style={{ fontSize: 11, color: 'var(--o)', fontFamily: 'IBM Plex Mono, monospace' }}>
              {mlHigh > 0 ? `${mlHigh} high` : ''}
            </span>
            <button
              className="btn"
              onClick={runMlScan}
              disabled={mlScanning}
              style={{ opacity: mlScanning ? 0.5 : 1 }}
            >
              {mlScanning ? '⟳ Scanning…' : '⚡ Run AI Detection'}
            </button>
          </div>
        </div>

        {/* Filter tabs */}
        <div style={{ display: 'flex', gap: 4, padding: '0 16px 12px', flexWrap: 'wrap' }}>
          {[
            { key: 'ALL',     label: `All (${mlPredictions.length})` },
            { key: 'THREATS', label: `Threats (${mlThreats.length})` },
            { key: 'CRITICAL',label: 'Critical' },
            { key: 'HIGH',    label: 'High' },
            { key: 'MEDIUM',  label: 'Medium' },
            { key: 'INFO',    label: 'Info' },
          ].map(f => (
            <button
              key={f.key}
              onClick={() => setMlFilter(f.key)}
              style={{
                background: mlFilter === f.key ? 'var(--r)' : 'var(--surface2)',
                border: `1px solid ${mlFilter === f.key ? 'var(--r)' : 'var(--border)'}`,
                color: mlFilter === f.key ? '#fff' : 'var(--t3)',
                borderRadius: 5, padding: '4px 10px', fontSize: 11,
                fontFamily: 'IBM Plex Mono, monospace', cursor: 'pointer',
                fontWeight: mlFilter === f.key ? 700 : 400,
              }}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Table header */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '20px 110px 80px 1fr 120px 55px 16px',
          gap: 10, padding: '6px 16px',
          borderTop: '1px solid var(--border)',
          borderBottom: '1px solid var(--border)',
          background: 'var(--surface2)',
        }}>
          {['', 'ATTACK TYPE', 'SEVERITY', 'CONFIDENCE', 'SOURCE IP', 'TIME', ''].map((h, i) => (
            <div key={i} style={{ fontSize: 9, color: 'var(--t4)', letterSpacing: '0.1em', fontFamily: 'IBM Plex Mono, monospace' }}>{h}</div>
          ))}
        </div>

        {/* Prediction rows */}
        <div style={{ maxHeight: 400, overflowY: 'auto' }}>
          {mlScanning && mlPredictions.length === 0 ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)', fontSize: 13 }}>
              <span className="live-dot" style={{ background: 'var(--y)', display: 'inline-block', marginRight: 8 }} />
              Running AI scan on latest logs…
            </div>
          ) : mlFiltered.length === 0 ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)', fontSize: 13 }}>
              <Icon.Check style={{ width: 18, height: 18, color: 'var(--g)', display: 'block', margin: '0 auto 8px' }} />
              No predictions match this filter
            </div>
          ) : (
            mlFiltered.map((p, i) => <PredictionRow key={i} p={p} />)
          )}
        </div>

        {/* Footer */}
        {mlMeta && (
          <div style={{
            padding: '8px 16px', borderTop: '1px solid var(--border)',
            display: 'flex', gap: 20, background: 'var(--surface2)',
          }}>
            {[
              { label: 'Logs scanned', val: mlMeta.scanned },
              { label: 'Total predictions', val: mlMeta.total },
              { label: 'Threats found', val: mlMeta.threats, color: mlMeta.threats > 0 ? 'var(--r)' : 'var(--g)' },
              { label: 'Model', val: 'Random Forest · UNSW-NB15' },
              { label: 'MITRE', val: 'ATT&CK v14' },
            ].map(s => (
              <div key={s.label}>
                <span style={{ fontSize: 9, color: 'var(--t4)', letterSpacing: '0.08em' }}>{s.label}: </span>
                <span style={{ fontSize: 10, color: s.color || 'var(--t2)', fontFamily: 'IBM Plex Mono, monospace', fontWeight: 600 }}>{s.val}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Bottom: Table + Donut */}
      <div className="bot-grid" style={{ marginTop: 16 }}>
        <div className="card" style={{ gridColumn: 'span 2' }}>
          <div className="card-head">
            <div className="card-title"><Icon.List />Top Attacking IPs</div>
            <div className="row">
              <select className="sel" value={ipSeverity} onChange={e => setIpSeverity(e.target.value)}>
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div className="tbl-scroll">
            <table className="siem-table">
              <thead>
                <tr>
                  <th>Source IP</th><th>Severity</th><th>Count</th>
                  <th style={{ textAlign: 'right' }}>Events</th>
                </tr>
              </thead>
              <tbody>
                {topIps.length === 0 ? (
                  <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--t3)', padding: 24 }}>No threat data in last 24h</td></tr>
                ) : topIps.map((r, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--r)', fontWeight: 600, fontFamily: 'IBM Plex Mono, monospace', fontSize: 12 }}>{r.ip}</td>
                    <td><span className={`sev sev-${(r.severity || 'low').toUpperCase()}`}>{(r.severity || 'LOW').toUpperCase()}</span></td>
                    <td><span className="mono" style={{ fontSize: 11, color: 'var(--t3)' }}>{r.count} events</span></td>
                    <td style={{ textAlign: 'right' }}><span className="mono" style={{ fontWeight: 500, color: 'var(--t1)' }}>{r.count}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <div className="card-title"><Icon.Clock />Threat Type Volume</div>
          </div>
          <div className="donut-wrap">
            <DonutChart segments={donutSegs} total={String(totalThreatCount)} label="threats" />
            <div className="donut-legend">
              {donutSegs.map(s => (
                <div className="legend-row" key={s.label}>
                  <div className="legend-dot" style={{ background: s.color }} />
                  {s.label}
                  <span className="legend-val">{s.pct}</span>
                </div>
              ))}
              {donutSegs.length === 0 && <div style={{ color: 'var(--t3)', fontSize: 12 }}>No threats detected</div>}
            </div>
          </div>
        </div>
      </div>

      {/* ── VM - Graphics (Grafana Inspired) ── */}
      <div style={{ marginTop: 24 }}>
        <div className="card-title" style={{ marginBottom: 12, fontSize: 15 }}>
          <Icon.Server /> VM - Graphics
        </div>
        <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
          <div className="stat-card" style={{ padding: '16px' }}>
            <div className="stat-bar" style={{ background: '#2db87a' }} />
            <div className="stat-label">CPU utilization</div>
            <div className="stat-num" style={{ color: '#2db87a', fontSize: 28 }}>11.8%</div>
            <div className="stat-sub">Current Load</div>
          </div>
          <div className="stat-card" style={{ padding: '16px' }}>
            <div className="stat-bar" style={{ background: '#d4a017' }} />
            <div className="stat-label">Memory RAM</div>
            <div className="stat-num" style={{ color: '#d4a017', fontSize: 28 }}>64.8%</div>
            <div className="stat-sub">Allocated</div>
          </div>
          <div className="stat-card" style={{ padding: '16px' }}>
            <div className="stat-bar" style={{ background: '#2db87a' }} />
            <div className="stat-label">Disk Usage</div>
            <div className="stat-num" style={{ color: '#2db87a', fontSize: 28 }}>76.4%</div>
            <div className="stat-sub">94.3 GiB Free</div>
          </div>
          <div className="stat-card" style={{ padding: '16px' }}>
            <div className="stat-bar" style={{ background: '#3b7de8' }} />
            <div className="stat-label">Number Process</div>
            <div className="stat-num" style={{ color: '#3b7de8', fontSize: 28 }}>140</div>
            <div className="stat-sub">Active instances</div>
          </div>
        </div>
      </div>

      {/* ── Compliance and Frameworks (Grafana Inspired) ── */}
      <div style={{ marginTop: 24, marginBottom: 24 }}>
        <div className="card-title" style={{ marginBottom: 12, fontSize: 15 }}>
          <Icon.Shield /> Compliance and Frameworks
        </div>
        <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
          <div className="card">
            <div className="card-head" style={{ borderBottom: 'none', paddingBottom: 0 }}><div className="card-title">Mitre Tactic</div></div>
            <div className="donut-wrap" style={{ flexDirection: 'column', padding: '10px 16px' }}>
              <DonutChart segments={donutSegs} total={String(totalThreatCount)} label="Tactics" />
            </div>
          </div>
          <div className="card">
            <div className="card-head" style={{ borderBottom: 'none', paddingBottom: 0 }}><div className="card-title">GDPR</div></div>
            <div className="donut-wrap" style={{ flexDirection: 'column', padding: '10px 16px' }}>
              <DonutChart segments={[
                {color: '#2db87a', label: 'Compliant', pct: 63},
                {color: '#d4a017', label: 'Review', pct: 35},
                {color: '#e84646', label: 'Risk', pct: 2}
              ]} total="100%" label="Score" />
            </div>
          </div>
          <div className="card">
            <div className="card-head" style={{ borderBottom: 'none', paddingBottom: 0 }}><div className="card-title">Rules Groups</div></div>
            <div className="donut-wrap" style={{ flexDirection: 'column', padding: '10px 16px' }}>
              <DonutChart segments={[
                {color: '#e8823a', label: 'windows', pct: 48},
                {color: '#3b7de8', label: 'syslog', pct: 24},
                {color: '#d4a017', label: 'application', pct: 22},
                {color: '#8b5cf6', label: 'security', pct: 6}
              ]} total="1,432" label="Rules" />
            </div>
          </div>
          <div className="card">
            <div className="card-head" style={{ borderBottom: 'none', paddingBottom: 0 }}><div className="card-title">NIST 800.53</div></div>
            <div className="donut-wrap" style={{ flexDirection: 'column', padding: '10px 16px' }}>
              <DonutChart segments={[
                {color: '#8b5cf6', label: 'AU.14', pct: 48},
                {color: '#e84646', label: 'AC.7', pct: 20},
                {color: '#3b7de8', label: 'SI.4', pct: 32}
              ]} total="89" label="Agents" />
            </div>
          </div>
        </div>
      </div>

    </div>
  )
}
