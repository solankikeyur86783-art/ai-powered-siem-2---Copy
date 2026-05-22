/**
 * timeUtils.js — Centralised timestamp helpers for CortexSIEM
 * 
 * ROOT CAUSE of "5 hours ago" bug:
 *   Backend stores timestamps in UTC (e.g. "2026-04-27T10:00:00Z").
 *   .toISOString() always returns UTC — so IST users (UTC+5:30) see times
 *   that are 5.5 hours behind current local time.
 *
 * FIX: Use toLocaleString() / toLocaleTimeString() with the user's local
 *      locale — the browser automatically converts UTC → local timezone.
 */

const LOCALE = undefined  // undefined = browser's locale (auto IST for India)
const DATE_FMT = { day: '2-digit', month: 'short', year: 'numeric' }
const TIME_FMT = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }
const FULL_FMT = { ...DATE_FMT, ...TIME_FMT }

/**
 * Parse a raw timestamp string from the backend.
 * Handles: ISO strings with/without Z, space-separated datetime strings.
 */
function parseTs(ts) {
  if (!ts) return null
  if (ts instanceof Date) return ts
  let s = String(ts).trim()
  // If it looks like "2026-04-27 10:00:00" without timezone → treat as UTC
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) {
    s = s.replace(' ', 'T') + 'Z'
  }
  // If ISO without Z → treat as UTC
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(s)) {
    s = s + 'Z'
  }
  const d = new Date(s)
  return isNaN(d.getTime()) ? null : d
}

/**
 * Format: "27 Apr 2026, 16:32:15" (local time, auto-IST)
 */
export function fmtFull(ts) {
  const d = parseTs(ts)
  if (!d) return ts || '—'
  return d.toLocaleString(LOCALE, FULL_FMT)
}

/**
 * Format: "2026-04-27 16:32:15" — local time, no timezone suffix
 */
export function fmtLog(ts) {
  const d = parseTs(ts)
  if (!d) return ts || '—'
  // pad helper
  const p = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/**
 * Format: "16:32:15" — local time only
 */
export function fmtTime(ts) {
  const d = parseTs(ts)
  if (!d) return ts || '—'
  return d.toLocaleTimeString(LOCALE, TIME_FMT)
}

/**
 * Format: "16:32" — short local time
 */
export function fmtTimeShort(ts) {
  const d = parseTs(ts)
  if (!d) return ts || '—'
  return d.toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit', hour12: false })
}

/**
 * Format: "27 Apr 2026" — date only
 */
export function fmtDate(ts) {
  const d = parseTs(ts)
  if (!d) return ts || '—'
  return d.toLocaleDateString(LOCALE, DATE_FMT)
}

/**
 * Format: "YYYY-MM-DD" — for filenames / ISO date only
 */
export function fmtDateISO(ts) {
  const d = parseTs(ts)
  if (!d) return ts || '—'
  const p = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}`
}

/**
 * Relative time: "2 minutes ago", "5 hours ago", "just now"
 * Uses local time so "5 hours ago" bug is eliminated.
 */
export function fmtAgo(ts) {
  const d = parseTs(ts)
  if (!d) return ts || '—'
  const diff = Date.now() - d.getTime()
  const s = Math.floor(diff / 1000)
  const m = Math.floor(s / 60)
  const h = Math.floor(m / 60)
  const days = Math.floor(h / 24)
  if (s < 10)   return 'just now'
  if (s < 60)   return `${s}s ago`
  if (m < 60)   return `${m} min ago`
  if (h < 24)   return `${h}h ago`
  return `${days}d ago`
}

/**
 * Full datetime for alerts: "27 Apr 2026, 16:32:15"
 */
export function fmtAlert(ts) {
  return fmtFull(ts)
}
