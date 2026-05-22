/**
 * DonutChart — accepts segments with either `pct` (percentage) or `count` (raw number).
 * Auto-normalizes raw counts to percentages if `pct` is missing.
 */
export default function DonutChart({ segments, total, label = 'total', size = 110 }) {
  const r = 38
  const cx = size / 2
  const cy = size / 2
  const circ = 2 * Math.PI * r

  // Normalize: support both pct and count-based segments
  const normalized = (() => {
    if (!segments || segments.length === 0) return []
    const hasPct = segments.some(s => s.pct != null && s.pct > 0)
    if (hasPct) return segments

    const totalCount = segments.reduce((sum, s) => sum + (s.pct || s.count || 0), 0)
    if (totalCount === 0) return segments
    return segments.map(s => ({ ...s, pct: ((s.pct || s.count || 0) / totalCount) * 100 }))
  })()

  let offset = 0
  const slices = normalized.map(seg => {
    const dash = ((seg.pct || 0) / 100) * circ
    const gap = circ - dash
    const slice = { ...seg, dash, gap, offset }
    offset += dash
    return slice
  })

  const displayTotal = total ?? segments?.reduce((a, s) => a + (s.count || s.pct || 0), 0) ?? 0

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--ln)" strokeWidth="13" />
      {/* Segments */}
      {slices.map((s, i) => (
        <circle key={i}
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={s.color}
          strokeWidth="13"
          strokeDasharray={`${s.dash} ${s.gap}`}
          strokeDashoffset={-s.offset}
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      ))}
      {/* Inner */}
      <circle cx={cx} cy={cy} r={r - 8} fill="var(--bg1)" />
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize="15" fontWeight="700" fill="var(--t1)" fontFamily="IBM Plex Mono,monospace">{displayTotal}</text>
      <text x={cx} y={cy + 9} textAnchor="middle" fontSize="8" fill="var(--t3)" fontFamily="Manrope,sans-serif">{label}</text>
    </svg>
  )
}
