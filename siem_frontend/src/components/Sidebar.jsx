import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/AuthContext.jsx'
import Icon from './Icons.jsx'
import { useState, useEffect } from 'react'
import { alertsApi, torApi } from '../services/api.js'

const baseNavItems = [
  { section: 'Overview' },
  { to: '/', label: 'Dashboard', icon: 'Grid', end: true },
  { to: '/alerts', label: 'Alerts', icon: 'Alert', badgeKey: 'alerts' },
  { to: '/logs', label: 'Log Search', icon: 'File' },
  { section: 'Detection' },
  { to: '/hunt', label: 'Threat Hunt', icon: 'Search' },
  { to: '/threat-map', label: 'Threat Map', icon: 'Map' },
  { to: '/ai-insights', label: 'AI Insights', icon: 'Brain' },
  { to: '/tor', label: 'Tor Detection', icon: 'Shield', badgeKey: 'tor' },
  { section: 'Infrastructure' },
  { to: '/agents', label: 'Agents', icon: 'Server' },
  { to: '/honeypot', label: 'Honeypot', icon: 'Lock' },
  { to: '/forensics', label: 'Forensics', icon: 'Activity' },
  { section: 'Config' },
  { to: '/rules', label: 'Rules', icon: 'Star' },
  { to: '/reports', label: 'Reports', icon: 'Report' },
  { to: '/notifications', label: 'Notifications', icon: 'Bell' },
]

export default function Sidebar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [openAlerts, setOpenAlerts] = useState(null)
  const [torBadge, setTorBadge]     = useState(null)
  const [pulse, setPulse]           = useState(false)

  useEffect(() => {
    const fetchBadge = async () => {
      try {
        const data = await alertsApi.summary(24)
        setOpenAlerts(data.open ?? 0)
      } catch {}
    }
    fetchBadge()
    const interval = setInterval(fetchBadge, 30000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const fetchTor = async () => {
      try { const d = await torApi.stats(24); setTorBadge(d.tor_alerts_24h ?? 0) } catch {}
    }
    fetchTor()
    const i = setInterval(fetchTor, 60000)
    return () => clearInterval(i)
  }, [])

  // Pulse logo every 5s
  useEffect(() => {
    const id = setInterval(() => { setPulse(true); setTimeout(() => setPulse(false), 600) }, 5000)
    return () => clearInterval(id)
  }, [])

  const badges = { alerts: openAlerts, tor: torBadge }
  const handleLogout = () => { logout(); navigate('/login') }
  const initials = user
    ? (user.full_name || user.username || 'U').split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase()
    : 'AD'

  return (
    <aside className="sidebar" style={{ position: 'relative', overflow: 'hidden' }}>

      {/* Subtle top glow line */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: 'linear-gradient(90deg, transparent, rgba(59,125,232,0.5), transparent)', zIndex: 10 }} />

      {/* Logo */}
      <div className="sidebar-logo">
        <div className="logo-mark" style={{
          transition: 'box-shadow 0.3s, transform 0.3s',
          boxShadow: pulse ? '0 0 24px rgba(232,70,70,0.8), 0 0 48px rgba(232,70,70,0.4)' : '0 0 16px rgba(232,70,70,0.4)',
          transform: pulse ? 'scale(1.1)' : 'scale(1)',
        }}>
          <Icon.Shield style={{ width: 17, height: 17, stroke: 'white' }} />
        </div>
        <div>
          <div className="logo-text">Cortex<span>SIEM</span></div>
          <div style={{ fontSize: 9, color: 'var(--t3)', letterSpacing: '0.1em', fontFamily: 'IBM Plex Mono, monospace', textTransform: 'uppercase' }}>v2.0 Enterprise</div>
        </div>
      </div>

      {/* ML Accuracy badge */}
      <div style={{
        margin: '8px 10px', padding: '7px 10px', borderRadius: 8,
        background: 'linear-gradient(135deg, rgba(45,184,122,0.08), rgba(0,132,255,0.08))',
        border: '1px solid rgba(45,184,122,0.18)',
        display: 'flex', alignItems: 'center', gap: 7,
      }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#2db87a', boxShadow: '0 0 6px #2db87a', animation: 'blink 3s infinite', flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--t2)', letterSpacing: '0.05em' }}>ML Model Active</div>
          <div style={{ fontSize: 8.5, color: '#2db87a', fontFamily: 'IBM Plex Mono, monospace', marginTop: 1 }}>Accuracy: 97.47% • 4 datasets</div>
        </div>
        <div style={{ fontSize: 11, fontFamily: 'IBM Plex Mono, monospace', color: '#2db87a', fontWeight: 700 }}>✓</div>
      </div>

      {/* Nav */}
      <nav className="sidebar-nav">
        {baseNavItems.map((item, i) => {
          if (item.section) {
            return (
              <div key={i} className="nav-section" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ flex: 1, height: 1, background: 'var(--ln)', opacity: 0.5 }} />
                <span>{item.section}</span>
                <div style={{ flex: 1, height: 1, background: 'var(--ln)', opacity: 0.5 }} />
              </div>
            )
          }
          const Ico = Icon[item.icon]
          const badge = item.badgeKey ? badges[item.badgeKey] : undefined
          return (
            <NavLink
              key={item.to} to={item.to} end={item.end}
              className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}
            >
              {Ico && <Ico />}
              {item.label}
              {badge != null && badge > 0 && (
                <span className="nav-badge" style={{ animation: badge > 5 ? 'blink 1.5s infinite' : 'none' }}>
                  {badge > 99 ? '99+' : badge}
                </span>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* College badge */}
      <div style={{
        margin: '0 10px 8px', padding: '8px 10px', borderRadius: 8,
        background: 'linear-gradient(135deg, rgba(59,125,232,0.06), rgba(139,92,246,0.06))',
        border: '1px solid rgba(59,125,232,0.12)',
      }}>
        <div style={{ fontSize: 12, color: 'var(--t2)', lineHeight: 1.5 }}>B.E. ICT & Cyber Security · Final Year</div>
        <div style={{ fontSize: 11, color: 'var(--t3)', fontFamily: 'IBM Plex Mono, monospace', marginTop: 3 }}>AI-Powered SIEM Platform</div>
        <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--b)', marginTop: 5, textTransform: 'uppercase' }}>By: Solanki Keyur</div>
      </div>

      {/* User row */}
      <div className="sidebar-bottom">
        <div className="user-row" onClick={handleLogout} title="Click to logout">
          <div className="user-avatar" style={{ boxShadow: '0 0 12px rgba(59,125,232,0.3)' }}>{initials}</div>
          <div>
            <div className="user-name">{user?.full_name || user?.username || 'Admin'}</div>
            <div className="user-role" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#2db87a', boxShadow: '0 0 4px #2db87a' }} />
              {user?.role || 'SOC Analyst'}
            </div>
          </div>
          <Icon.LogOut style={{ width: 14, height: 14, color: 'var(--t3)', marginLeft: 'auto' }} />
        </div>
      </div>
    </aside>
  )
}
