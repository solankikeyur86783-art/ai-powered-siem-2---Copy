import { useState, useEffect, useRef } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useTheme } from '../hooks/ThemeContext.jsx'
import { useAuth } from '../hooks/AuthContext.jsx'
import Icon from './Icons.jsx'

const titles = {
  '/': 'Dashboard', '/alerts': 'Alerts', '/logs': 'Log Search',
  '/hunt': 'Threat Hunt', '/threat-map': 'Threat Map', '/ai-insights': 'AI Insights',
  '/agents': 'Agents', '/honeypot': 'Honeypot', '/forensics': 'Forensics',
  '/tor': 'Tor Detection', '/rules': 'Rules', '/reports': 'Reports',
  '/notifications': 'Notifications',
}

const THREAT_LEVELS = [
  { label: 'LOW',      color: '#2db87a', bg: 'rgba(45,184,122,0.12)',  border: 'rgba(45,184,122,0.25)'  },
  { label: 'MEDIUM',   color: '#d4a017', bg: 'rgba(212,160,23,0.12)',  border: 'rgba(212,160,23,0.25)'  },
  { label: 'HIGH',     color: '#e8823a', bg: 'rgba(232,130,58,0.12)',  border: 'rgba(232,130,58,0.25)'  },
  { label: 'CRITICAL', color: '#e84646', bg: 'rgba(232,70,70,0.12)',   border: 'rgba(232,70,70,0.25)'   },
]

export default function Topbar() {
  const { theme, setTheme } = useTheme()
  const { user }          = useAuth()
  const location          = useLocation()
  const navigate          = useNavigate()
  const [clock, setClock]   = useState('')
  const [date, setDate]     = useState('')
  const [search, setSearch] = useState('')
  const [threatLevel, setThreatLevel] = useState(1)  // 0=LOW … 3=CRITICAL
  const inputRef = useRef()

  const handleSearch = (e) => {
    if (e.key === 'Enter' && search.trim()) navigate(`/logs?q=${encodeURIComponent(search.trim())}`)
  }

  // Clock
  useEffect(() => {
    const tick = () => {
      const now = new Date()
      setClock(now.toUTCString().split(' ')[4] + ' UTC')
      setDate(now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }))
    }
    tick(); const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  // Simulate threat level changes (in prod connect to backend)
  useEffect(() => {
    const id = setInterval(() => {
      setThreatLevel(Math.floor(Math.random() * 4))
    }, 15000)
    return () => clearInterval(id)
  }, [])

  const title  = titles[location.pathname] || 'CortexSIEM'
  const tl     = THREAT_LEVELS[threatLevel]

  return (
    <div className="topbar" style={{ borderBottom: '1px solid var(--ln)', gap: 8 }}>

      {/* Breadcrumb */}
      <div className="breadcrumb">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--t3)' }}><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        <span style={{ color: 'var(--t4)' }}>/</span>
        <strong style={{ fontWeight: 800 }}>{title}</strong>
      </div>

      {/* Search */}
      <div className="topbar-search">
        <Icon.Search className="search-icon" />
        <input
          ref={inputRef}
          className="search-input"
          type="text"
          placeholder="Search events, IPs, rules, hashes…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={handleSearch}
        />
        <div style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', fontSize: 9.5, color: 'var(--t3)', fontFamily: 'IBM Plex Mono, monospace', background: 'var(--bg3)', padding: '1px 5px', borderRadius: 4, border: '1px solid var(--ln)' }}>↵</div>
      </div>

      <div className="topbar-right">

        {/* Threat Level Indicator */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 10px', borderRadius: 8,
          background: tl.bg, border: `1px solid ${tl.border}`,
          cursor: 'default', transition: 'all 0.4s ease',
        }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: tl.color, boxShadow: `0 0 8px ${tl.color}`, animation: threatLevel >= 2 ? 'blink 1s infinite' : 'none' }} />
          <span style={{ fontSize: 9.5, fontWeight: 800, color: tl.color, letterSpacing: '0.12em', fontFamily: 'IBM Plex Mono, monospace' }}>
            {tl.label}
          </span>
        </div>

        {/* Clock */}
        <div className="time-badge mono" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', lineHeight: 1.2 }}>
          <span>{clock}</span>
          <span style={{ fontSize: 9, color: 'var(--t3)' }}>{date}</span>
        </div>



        {/* Notifications bell */}
        <div className="icon-btn" title="Notifications" onClick={() => navigate('/notifications')}>
          <div className="notif-dot" />
          <Icon.Bell />
        </div>

        {/* User avatar */}
        {user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }} title={`${user.username} (${user.role})`}>
            <div style={{
              width: 30, height: 30, borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--b), var(--p))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontWeight: 800, color: '#fff',
              boxShadow: '0 0 12px rgba(59,125,232,0.4)',
              border: '2px solid rgba(59,125,232,0.3)',
            }}>
              {(user.username || user.full_name || 'U')[0].toUpperCase()}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.2 }}>
              <span style={{ fontSize: 11, color: 'var(--t1)', fontWeight: 700 }}>{user.username}</span>
              <span style={{ fontSize: 9, color: 'var(--t3)', fontFamily: 'IBM Plex Mono, monospace', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{user.role || 'analyst'}</span>
            </div>
          </div>
        )}

        {/* Refresh */}
        <div className="icon-btn" title="Refresh" onClick={() => window.location.reload()}>
          <Icon.Refresh />
        </div>

        {/* Theme select */}
        <select className="sel" value={theme} onChange={e => setTheme(e.target.value)} style={{ textTransform: 'capitalize' }}>
          <option value="dark">Dark Theme</option>
          <option value="light">Light Theme</option>
          <option value="cyber">Cyberpunk</option>
          <option value="neon">Neon Wave</option>
          <option value="ocean">Ocean Deep</option>
          <option value="obsidian">Obsidian Dark</option>
          <option value="graphite">Graphite Slate</option>
        </select>
      </div>
    </div>
  )
}
