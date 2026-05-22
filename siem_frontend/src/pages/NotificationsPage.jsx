import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import Icon from '../components/Icons.jsx'
import { notificationsApi } from '../services/api.js'
import { fmtAgo } from '../services/timeUtils.js'

const typeStyle = {
  critical: { color: 'var(--r)', bg: 'var(--r-dim)' },
  high:     { color: 'var(--o)', bg: 'var(--o-dim)' },
  warn:     { color: 'var(--y)', bg: 'var(--y-dim)' },
  info:     { color: 'var(--b)', bg: 'var(--b-dim)' },
  success:  { color: 'var(--g)', bg: 'var(--g-dim)' },
}

function getTypeFromNotif(n) {
  const s = (n.severity || n.type || 'info').toLowerCase()
  if (s === 'critical') return 'critical'
  if (['high', 'error', 'failed'].some(x => s.includes(x))) return 'high'
  if (['warn', 'medium'].some(x => s.includes(x))) return 'warn'
  if (['success', 'delivered'].some(x => s.includes(x))) return 'success'
  return 'info'
}

// ✅ Fixed: uses fmtAgo from timeUtils — UTC timestamps correctly converted to local diff
function timeAgo(ts) { return fmtAgo(ts) }

export default function NotificationsPage() {
  const [notifs, setNotifs] = useState([])
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [testing, setTesting] = useState(false)
  const [settings, setSettings] = useState(null)
  const [showSettings, setShowSettings] = useState(false)
  const navigate = useNavigate()

  const fetchNotifs = async () => {
    try {
      const data = await notificationsApi.history(100, 24)
      setNotifs(data.notifications || [])
    } catch (e) {
      console.error('Notifications fetch error:', e)
    } finally {
      setLoading(false)
    }
  }

  const fetchSettings = async () => {
    try {
      const data = await notificationsApi.settings()
      setSettings(data)
    } catch (e) {
      console.error('Settings fetch error:', e)
    }
  }

  useEffect(() => {
    fetchNotifs()
    fetchSettings()
  }, [])

  const sendTest = async () => {
    setTesting(true)
    try {
      await notificationsApi.test('high')
      alert('✅ Test alert sent successfully to configured channels.')
      fetchNotifs()
    } catch (e) {
      console.error('Test error:', e)
      alert('❌ Failed to send test alert check Slack settings.')
    } finally {
      setTesting(false)
    }
  }

  const filtered = filter === 'all'
    ? notifs
    : filter === 'critical'
    ? notifs.filter(n => getTypeFromNotif(n) === 'critical')
    : filter === 'high'
    ? notifs.filter(n => getTypeFromNotif(n) === 'high')
    : filter === 'info'
    ? notifs.filter(n => getTypeFromNotif(n) === 'info')
    : notifs

  const unreadCount = notifs.filter(n => n.status === 'failed').length

  return (
    <div className="page-content anim-fade">
      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="card-title">
            <Icon.Bell />
            Notifications
            {unreadCount > 0 && (
              <span style={{ background: 'var(--r)', color: '#fff', fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 99 }}>{unreadCount}</span>
            )}
          </div>
          <div className="row">
            <select className="sel" value={filter} onChange={e => setFilter(e.target.value)}>
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="info">Info</option>
            </select>
            <button className="btn" onClick={() => setShowSettings(!showSettings)}>
              <Icon.Filter />{showSettings ? 'Hide Settings' : 'Settings'}
            </button>
            <button className="btn btn-primary" onClick={sendTest} disabled={testing}>
              <Icon.Zap />{testing ? 'Sending…' : 'Test Alert'}
            </button>
          </div>
        </div>

        {/* Settings panel */}
        {showSettings && settings && (
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--ln)', background: 'var(--bg2)', fontSize: 12 }}>
            <div style={{ fontWeight: 700, color: 'var(--t1)', marginBottom: 8 }}>Notification Settings</div>
            <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--t3)' }}>Slack:</span>
                <span className="tag" style={{
                  color: settings.slack?.enabled ? 'var(--g)' : 'var(--r)',
                  borderColor: 'currentColor', fontSize: 9
                }}>{settings.slack?.enabled ? 'ENABLED' : 'DISABLED'}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--t3)' }}>Min Severity:</span>
                <span style={{ color: 'var(--t1)', fontWeight: 600 }}>{(settings.min_severity || 'high').toUpperCase()}</span>
              </div>
              {settings.slack?.webhook_url && (
                <div style={{ color: 'var(--t3)' }}>
                  Webhook: <span className="mono" style={{ fontSize: 10 }}>{settings.slack.webhook_url.substring(0, 40)}…</span>
                </div>
              )}
            </div>
          </div>
        )}

        <div className="scroll-y" style={{ maxHeight: 'calc(100vh - 220px)' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--t3)' }}>
              <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading notifications…
            </div>
          ) : filtered.map((n, i) => {
            const type = getTypeFromNotif(n)
            const style = typeStyle[type] || typeStyle.info
            const failed = n.status === 'failed'
            return (
              <div 
                key={n.id || i} 
                className={`notif-item ${failed ? 'unread' : ''}`}
                onClick={() => {
                  if (n.alert_id) navigate(`/alerts`)
                  else if (n.case_id) navigate(`/forensics`)
                  else if (n.title?.toLowerCase().includes('agent')) navigate(`/agents`)
                }}
              >
                <div className="notif-ico" style={{ background: style.bg }}>
                  <Icon.Bell style={{ color: style.color }} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="row" style={{ marginBottom: 2 }}>
                    <div className="notif-title">{n.title || n.channel || 'Notification'}</div>
                    {failed && (
                      <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--r)', flexShrink: 0, marginLeft: 6 }} />
                    )}
                  </div>
                  <div className="notif-body">
                    {n.message || `Alert: ${n.alert_title || '—'} (${(n.severity || '').toUpperCase()})`}
                  </div>
                  <div className="notif-time">
                    {timeAgo(n.timestamp)} · {n.channel || 'slack'}
                    {n.status && (
                      <span className="tag" style={{
                        marginLeft: 8, fontSize: 8,
                        color: n.status === 'sent' ? 'var(--g)' : 'var(--r)',
                        borderColor: 'currentColor'
                      }}>{n.status.toUpperCase()}</span>
                    )}
                  </div>
                </div>
              </div>
            )
          })}

          {!loading && filtered.length === 0 && (
            <div className="empty-state">
              <Icon.Bell />
              <p>No notifications to show</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
