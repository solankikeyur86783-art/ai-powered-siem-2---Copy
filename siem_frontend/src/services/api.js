/**
 * Central API Service — AI-Powered SIEM Platform
 * All backend calls go through here. JWT token is auto-attached.
 */

const BASE_URL = 'http://localhost:8000'

function getToken() {
  return localStorage.getItem('siem-token') || ''
}

function headers(extra = {}) {
  const token = getToken()
  const h = { 'Content-Type': 'application/json', ...extra }
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

async function request(method, path, body = null, opts = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: headers(opts.headers || {}),
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || res.statusText)
  }
  return res.json()
}

const get  = (path, opts)      => request('GET',    path, null, opts)
const post = (path, body, opts) => request('POST',   path, body, opts)
const put  = (path, body, opts) => request('PUT',    path, body, opts)
const patch = (path, body, opts) => request('PATCH', path, body, opts)
const del  = (path, opts)      => request('DELETE',  path, null, opts)

// ── Auth ─────────────────────────────────────────────────────
export const authApi = {
  login:   (username, password) => post('/api/auth/login', { username, password }),
  me:      ()                   => get('/api/auth/me'),
  register:(data)               => post('/api/auth/register', data),
}

// ── Dashboard ─────────────────────────────────────────────────
export const dashboardApi = {
  get: (hours = 24, severity = 'all') => get(`/api/dashboard?hours=${hours}&severity=${severity}`),
}

// ── Alerts ────────────────────────────────────────────────────
export const alertsApi = {
  list:       (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return get(`/api/alerts/?${q}`)
  },
  summary:    (hours = 24)  => get(`/api/alerts/summary?hours=${hours}`),
  getOne:     (id)          => get(`/api/alerts/${id}`),
  update:     (id, data)    => patch(`/api/alerts/${id}`, data),
  investigate:(id)          => post(`/api/alerts/${id}/investigate`),
  delete:     (id)          => del(`/api/alerts/${id}`),
}

// ── Logs ──────────────────────────────────────────────────────
export const logsApi = {
  list:    (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return get(`/api/logs/?${q}`)
  },
  threats: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return get(`/api/logs/threats?${q}`)
  },
  stats:   (hours = 24)  => get(`/api/logs/stats?hours=${hours}`),
}

// ── Honeypot ──────────────────────────────────────────────────
export const honeypotApi = {
  status:   ()              => get('/api/honeypot/status'),
  captures: (hours = 24)   => get(`/api/honeypot/captures?hours=${hours}`),
  stats:    (hours = 24)   => get(`/api/honeypot/stats?hours=${hours}`),
  start:    (service, port) => post('/api/honeypot/start', { service, port }),
  stop:     (service)       => post('/api/honeypot/stop', { service }),
  stopAll:  ()              => post('/api/honeypot/stop-all'),
}

// ── Forensics ─────────────────────────────────────────────────
export const forensicsApi = {
  cases:          (limit = 20) => get(`/api/forensics/cases?limit=${limit}`),
  getCase:        (id)         => get(`/api/forensics/cases/${id}`),
  collect:        (alertId)    => post(`/api/forensics/collect/${alertId}`),
  addNote:        (id, note)   => post(`/api/forensics/cases/${id}/note`, { note }),
  addArtifact:    (id, data)   => post(`/api/forensics/cases/${id}/artifact`, data),
  exportCase:     (id)         => `${BASE_URL}/api/forensics/cases/${id}/export`,
  deleteCase:     (id)         => del(`/api/forensics/cases/${id}`),
  ipTimeline:     (ip, hours)  => post(`/api/forensics/timeline/${ip}`, { hours }),
}

// ── Threat Hunt ───────────────────────────────────────────────
export const huntApi = {
  templates:  ()           => get('/api/hunt/templates'),
  execute:    (data)       => post('/api/hunt/execute', data),
  nlQuery:    (query, hrs) => post('/api/hunt/nl-query', { query, hours: hrs }),
  saved:      ()           => get('/api/hunt/saved'),
  save:       (name, query)=> post('/api/hunt/saved', { name, query }),
  deleteSaved:(id)         => del(`/api/hunt/saved/${id}`),
}

// ── Rules ─────────────────────────────────────────────────────
export const rulesApi = {
  list:   ()       => get('/api/rules/'),
  create: (data)   => post('/api/rules/', data),
  update: (id, d)  => put(`/api/rules/${id}`, d),
  delete: (id)     => del(`/api/rules/${id}`),
  toggle: (id)     => post(`/api/rules/${id}/toggle`),
  test:   (data)   => post('/api/rules/test', data),
  importSigma: (yaml) => post('/api/rules/import', { yaml }),
}

// ── Reports ───────────────────────────────────────────────────
export const reportsApi = {
  list:     (limit = 20) => get(`/api/reports/?limit=${limit}`),
  get:      (id)         => get(`/api/reports/${id}`),
  generate: (data)       => post('/api/reports/generate', data),
  delete:   (id)         => del(`/api/reports/${id}`),
}

// ── Notifications ─────────────────────────────────────────────
export const notificationsApi = {
  history:        (limit = 50, hours = 24) => get(`/api/notifications/history?limit=${limit}&hours=${hours}`),
  settings:       ()                        => get('/api/notifications/settings'),
  updateSettings: (data)                    => put('/api/notifications/settings', data),
  test:           (severity = 'high')       => post('/api/notifications/test', { severity }),
}

// ── AI & ML ───────────────────────────────────────────────────
export const aiApi = {
  anomalies:    (hours = 24) => get(`/api/ai/anomalies?hours=${hours}`),
  scan:         ()           => post('/api/ai/anomalies/scan'),
  resolve:      (id)         => post(`/api/ai/anomalies/${id}/resolve`),
  dismiss:      (id)         => del(`/api/ai/anomalies/${id}`),
  modelStatus:  ()           => get('/api/ai/model/status'),
  retrain:      ()           => post('/api/ai/model/retrain'),
  deepAnalyze:  (alertId)   => post(`/api/ai/analyze/deep/${alertId}`),
  riskScores:   (hours = 24) => get(`/api/ai/risk-scores?hours=${hours}`),
}

// ── Agents ────────────────────────────────────────────────────
export const agentsApi = {
  status:     ()                   => get('/api/agents/status'),
  actions:    (params = {})        => {
    const q = new URLSearchParams(params).toString()
    return get(`/api/agents/actions?${q}`)
  },
  run:        (alertId)            => post(`/api/agents/run/${alertId}`),
  liveFeed:   (limit = 30, hours = 24) => get(`/api/agents/live-feed?limit=${limit}&hours=${hours}`),
  blockedIps: ()                   => get('/api/agents/blocked-ips'),
  unblock:    (ip)                 => post(`/api/agents/unblock/${ip}`),
}

// ── Threat Intel ──────────────────────────────────────────────
export const intelApi = {
  mapData:  (hours = 24) => get(`/api/intel/map-data?hours=${hours}`),
  lookupIp: (ip)         => get(`/api/intel/ip/${ip}`),
  geoip:    (ip)         => get(`/api/intel/geoip/${ip}`),
  abuse:    (ip)         => get(`/api/intel/abuse/${ip}`),
  enrich:   (alertId)    => post(`/api/intel/enrich/${alertId}`),
}

// ── Tor Detection ─────────────────────────────────────────────
export const torApi = {
  status:     ()                    => get('/api/tor/status'),
  stats:      (hours = 24)          => get(`/api/tor/stats?hours=${hours}`),
  checkIp:    (ip)                  => get(`/api/tor/check-ip/${ip}`),
  scan:       (hours = 24)          => post(`/api/tor/scan?hours=${hours}`),
  behavioral: (event)               => post('/api/tor/behavioral', event),
  triggerIR:  (ip, alertId = null)  => post(`/api/tor/ir/${ip}${alertId ? `?alert_id=${alertId}` : ''}`),
  refresh:    ()                    => post('/api/tor/refresh'),
  alerts:     (hours = 24)          => get(`/api/tor/alerts?hours=${hours}`),
  tickets:    ()                    => get('/api/tor/tickets'),
  blocked:    ()                    => get('/api/tor/blocked'),
}
