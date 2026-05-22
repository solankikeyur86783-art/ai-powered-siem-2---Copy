import { useState, useEffect, useRef } from 'react'
import { useAuth } from '../hooks/AuthContext.jsx'

/* ── Animated matrix rain canvas ─────────────────── */
function MatrixCanvas() {
  const ref = useRef()
  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight }
    resize()
    window.addEventListener('resize', resize)

    const cols = Math.floor(canvas.width / 16)
    const drops = Array(cols).fill(1)
    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ'

    const draw = () => {
      ctx.fillStyle = 'rgba(10,12,16,0.05)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.fillStyle = 'rgba(0,255,136,0.08)'
      ctx.font = '14px monospace'
      drops.forEach((y, i) => {
        const ch = chars[Math.floor(Math.random() * chars.length)]
        ctx.fillText(ch, i * 16, y * 16)
        if (y * 16 > canvas.height && Math.random() > 0.975) drops[i] = 0
        drops[i]++
      })
    }
    const id = setInterval(draw, 50)
    return () => { clearInterval(id); window.removeEventListener('resize', resize) }
  }, [])
  return <canvas ref={ref} style={{ position: 'fixed', inset: 0, zIndex: 0, opacity: 0.6 }} />
}

/* ── Animated threat stat pill ───────────────────── */
function StatPill({ label, value, color }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    const target = parseInt(value)
    const step = Math.ceil(target / 40)
    let cur = 0
    const id = setInterval(() => {
      cur = Math.min(cur + step, target)
      setDisplay(cur)
      if (cur >= target) clearInterval(id)
    }, 30)
    return () => clearInterval(id)
  }, [value])
  return (
    <div style={{
      flex: 1, background: 'rgba(255,255,255,0.03)', border: `1px solid ${color}33`,
      borderRadius: 10, padding: '10px 14px', textAlign: 'center',
    }}>
      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 22, fontWeight: 700, color, lineHeight: 1 }}>
        {display.toLocaleString()}
      </div>
      <div style={{ fontSize: 9, fontWeight: 700, color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 4 }}>
        {label}
      </div>
    </div>
  )
}

export default function LoginPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const [showPass, setShowPass] = useState(false)
  const [scanLine, setScanLine] = useState(0)

  // Scanning line animation
  useEffect(() => {
    const id = setInterval(() => setScanLine(p => (p + 1) % 100), 20)
    return () => clearInterval(id)
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true); setError('')
    const result = await login(username, password)
    if (!result.success) { setError(result.error || 'Authentication failed'); setLoading(false) }
  }

  return (
    <div style={{ position: 'relative', minHeight: '100vh', background: '#060810', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <MatrixCanvas />

      {/* Background glow orbs */}
      <div style={{ position: 'fixed', top: '15%', left: '10%', width: 600, height: 600, borderRadius: '50%', background: 'radial-gradient(circle, rgba(0,132,255,0.06) 0%, transparent 70%)', pointerEvents: 'none', zIndex: 1 }} />
      <div style={{ position: 'fixed', bottom: '10%', right: '5%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, rgba(139,92,246,0.06) 0%, transparent 70%)', pointerEvents: 'none', zIndex: 1 }} />
      <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 800, height: 800, borderRadius: '50%', background: 'radial-gradient(circle, rgba(232,70,70,0.03) 0%, transparent 65%)', pointerEvents: 'none', zIndex: 1 }} />

      {/* Main content */}
      <div style={{ position: 'relative', zIndex: 10, display: 'flex', gap: 0, width: '100%', maxWidth: 1000, margin: '0 auto', padding: '24px', alignItems: 'stretch', minHeight: '580px' }}>

        {/* LEFT PANEL — College branding */}
        <div style={{
          flex: 1, background: 'rgba(6,8,16,0.85)', border: '1px solid rgba(0,132,255,0.15)',
          borderRight: 'none', borderRadius: '20px 0 0 20px', padding: '44px 40px',
          display: 'flex', flexDirection: 'column', backdropFilter: 'blur(20px)',
          position: 'relative', overflow: 'hidden',
        }}>
          {/* Scanning line */}
          <div style={{
            position: 'absolute', left: 0, right: 0, height: 2,
            background: 'linear-gradient(90deg, transparent, rgba(0,132,255,0.4), transparent)',
            top: `${scanLine}%`, transition: 'top 0.02s linear', pointerEvents: 'none',
          }} />

          {/* Logo */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 36 }}>
            <div style={{
              width: 44, height: 44, borderRadius: 12,
              background: 'linear-gradient(135deg, #e84646, #ff6b35)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 24px rgba(232,70,70,0.5), 0 0 48px rgba(232,70,70,0.2)',
            }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: 20, fontWeight: 800, color: '#fff', letterSpacing: '-0.5px', fontFamily: 'Manrope, sans-serif' }}>
                Cortex<span style={{ color: '#e84646' }}>SIEM</span>
              </div>
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', letterSpacing: '0.15em', textTransform: 'uppercase', fontFamily: 'IBM Plex Mono, monospace' }}>v2.0 • Enterprise</div>
            </div>
          </div>

          {/* Main title */}
          <div style={{ marginBottom: 28 }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: '#fff', lineHeight: 1.2, letterSpacing: '-0.5px', fontFamily: 'Manrope, sans-serif', marginBottom: 10 }}>
              AI-Powered Security<br />
              <span style={{ background: 'linear-gradient(135deg, #0084ff, #8b5cf6)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                Operations Center
              </span>
            </div>
            <div style={{ fontSize: 12.5, color: 'rgba(255,255,255,0.45)', lineHeight: 1.7, fontFamily: 'Manrope, sans-serif' }}>
              Real-time threat detection, MITRE ATT&amp;CK mapping,<br />
              and autonomous incident response powered by ML.
            </div>
          </div>

          {/* Live stats */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 28 }}>
            <StatPill label="Threats Blocked" value="2847" color="#e84646" />
            <StatPill label="ML Accuracy" value="97" color="#0084ff" />
            <StatPill label="Agents Online" value="12" color="#2db87a" />
          </div>

          {/* Features */}
          {[
            { icon: '🧠', title: 'Multi-Dataset ML Engine', desc: 'NSL-KDD + UNSW-NB15 + CIC-IDS2017 + Darknet — 97.47% accuracy' },
            { icon: '🛡️', title: 'MITRE ATT&CK Framework', desc: 'Automatic TTP mapping with real-time threat intelligence' },
            { icon: '🤖', title: 'Autonomous Agents', desc: 'Auto-blocking, ticket creation & SOC team notifications' },
            { icon: '🌐', title: 'Tor & VPN Detection', desc: 'Anonymous traffic fingerprinting & behavioral analysis' },
          ].map((f, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 14, opacity: 0.85 }}>
              <div style={{ fontSize: 16, flexShrink: 0, marginTop: 1 }}>{f.icon}</div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#e8ecf4', fontFamily: 'Manrope, sans-serif' }}>{f.title}</div>
                <div style={{ fontSize: 10.5, color: 'rgba(255,255,255,0.38)', lineHeight: 1.5 }}>{f.desc}</div>
              </div>
            </div>
          ))}

          {/* College badge */}
          <div style={{ marginTop: 'auto', paddingTop: 20, borderTop: '1px solid rgba(255,255,255,0.07)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 36, height: 36, borderRadius: 10, background: 'linear-gradient(135deg, #0084ff, #8b5cf6)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, boxShadow: '0 0 16px rgba(0,132,255,0.3)' }}>🎓</div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'rgba(255,255,255,0.8)', fontFamily: 'Manrope, sans-serif' }}>Final Year Project — B.E. CSE / IT</div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', fontFamily: 'IBM Plex Mono, monospace' }}>Department of Computer Science &amp; Engineering</div>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT PANEL — Login form */}
        <div style={{
          width: 380, background: 'rgba(15,18,24,0.95)', border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '0 20px 20px 0', padding: '44px 36px',
          display: 'flex', flexDirection: 'column', backdropFilter: 'blur(20px)',
          boxShadow: '0 0 60px rgba(0,0,0,0.6)',
        }}>
          {/* System status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 32 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#2db87a', boxShadow: '0 0 8px #2db87a', animation: 'blink 2s infinite' }} />
            <span style={{ fontSize: 10, fontFamily: 'IBM Plex Mono, monospace', color: 'rgba(45,184,122,0.9)', fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
              All Systems Operational
            </span>
          </div>

          <div style={{ marginBottom: 28 }}>
            <h2 style={{ fontSize: 24, fontWeight: 800, color: '#e8ecf4', margin: 0, letterSpacing: '-0.5px', fontFamily: 'Manrope, sans-serif' }}>
              Secure Sign In
            </h2>
            <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.35)', marginTop: 6, fontFamily: 'Manrope, sans-serif' }}>
              Authenticate with your SOC credentials
            </p>
          </div>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16, flex: 1 }}>
            {/* Username */}
            <div>
              <label style={{ fontSize: 10.5, fontWeight: 700, color: 'rgba(255,255,255,0.45)', textTransform: 'uppercase', letterSpacing: '0.1em', display: 'block', marginBottom: 7, fontFamily: 'Manrope, sans-serif' }}>
                Username / Analyst ID
              </label>
              <div style={{ position: 'relative' }}>
                <svg style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'rgba(255,255,255,0.25)' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                <input
                  type="text" placeholder="admin"
                  value={username}
                  onChange={e => { setUsername(e.target.value); setError('') }}
                  autoFocus
                  style={{
                    width: '100%', background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10,
                    padding: '11px 12px 11px 34px', color: '#e8ecf4',
                    fontSize: 13, fontFamily: 'Manrope, sans-serif', outline: 'none',
                    transition: 'border-color 0.2s, box-shadow 0.2s', boxSizing: 'border-box',
                  }}
                  onFocus={e => { e.target.style.borderColor = 'rgba(0,132,255,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(0,132,255,0.1)' }}
                  onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.1)'; e.target.style.boxShadow = 'none' }}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label style={{ fontSize: 10.5, fontWeight: 700, color: 'rgba(255,255,255,0.45)', textTransform: 'uppercase', letterSpacing: '0.1em', display: 'block', marginBottom: 7, fontFamily: 'Manrope, sans-serif' }}>
                Password
              </label>
              <div style={{ position: 'relative' }}>
                <svg style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'rgba(255,255,255,0.25)' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <input
                  type={showPass ? 'text' : 'password'} placeholder="••••••••"
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError('') }}
                  style={{
                    width: '100%', background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10,
                    padding: '11px 36px 11px 34px', color: '#e8ecf4',
                    fontSize: 13, fontFamily: 'Manrope, sans-serif', outline: 'none',
                    transition: 'border-color 0.2s, box-shadow 0.2s', boxSizing: 'border-box',
                  }}
                  onFocus={e => { e.target.style.borderColor = 'rgba(0,132,255,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(0,132,255,0.1)' }}
                  onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.1)'; e.target.style.boxShadow = 'none' }}
                />
                <button type="button" onClick={() => setShowPass(p => !p)} style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.3)', padding: 2 }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    {showPass ? <><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></> : <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></>}
                  </svg>
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', background: 'rgba(232,70,70,0.1)', border: '1px solid rgba(232,70,70,0.25)', borderRadius: 8, fontSize: 12, color: '#ff6b6b' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || !username || !password}
              style={{
                width: '100%', padding: '13px', borderRadius: 10, border: 'none',
                background: loading ? 'rgba(0,132,255,0.5)' : 'linear-gradient(135deg, #0084ff, #5b6cf6)',
                color: '#fff', fontSize: 14, fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer',
                fontFamily: 'Manrope, sans-serif', letterSpacing: '0.02em',
                boxShadow: loading ? 'none' : '0 4px 24px rgba(0,132,255,0.35)',
                transition: 'all 0.2s', opacity: (!username || !password) ? 0.5 : 1,
              }}
            >
              {loading ? (
                <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ animation: 'spin 0.8s linear infinite' }}><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                  Authenticating…
                </span>
              ) : '🔐  Access SOC Dashboard'}
            </button>

            {/* Divider */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
              <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.07)' }} />
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.2)', fontFamily: 'IBM Plex Mono, monospace' }}>SECURITY NOTICE</span>
              <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.07)' }} />
            </div>

            {/* Security notice */}
            <div style={{ display: 'flex', gap: 8, padding: '10px 12px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8 }}>
              <span style={{ fontSize: 14 }}>🔒</span>
              <span style={{ fontSize: 10.5, color: 'rgba(255,255,255,0.3)', lineHeight: 1.6, fontFamily: 'Manrope, sans-serif' }}>
                All sessions are monitored and logged. Unauthorized access attempts are automatically reported to the security team.
              </span>
            </div>

            {/* ML badge */}
            <div style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '8px 0' }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#2db87a', boxShadow: '0 0 6px #2db87a' }} />
              <span style={{ fontSize: 10, fontFamily: 'IBM Plex Mono, monospace', color: 'rgba(255,255,255,0.3)' }}>
                ML Model Accuracy: <span style={{ color: '#2db87a', fontWeight: 700 }}>97.47%</span> • 4 Datasets • 160K samples
              </span>
            </div>
          </form>
        </div>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes blink { 0%,100%{opacity:1}50%{opacity:0.3} }
      `}</style>
    </div>
  )
}
