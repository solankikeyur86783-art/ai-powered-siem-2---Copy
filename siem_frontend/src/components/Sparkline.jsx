import { useMemo } from 'react'

function generateFallback(points = 48) {
  const data = []
  for (let i = 0; i < points; i++) {
    let v = 4 + Math.random() * 10
    if (i >= 44) v = 55 + Math.random() * 40
    data.push(v)
  }
  return data
}

/**
 * Sparkline chart — accepts optional `data` prop (array of {hour, count} or numbers).
 * Falls back to animated mock data if no real data provided.
 */
export default function Sparkline({ data: rawData, color = '#3b7de8', spikeColor = '#e84646', height = 150 }) {
  const data = useMemo(() => {
    if (rawData && rawData.length > 1) {
      // Accept array of {count} objects or plain numbers
      return rawData.map(d => (typeof d === 'number' ? d : d.count || 0))
    }
    return generateFallback(48)
  }, [rawData])

  const W = 660
  const H = height
  const max = Math.max(...data, 1)
  const pad = 8

  const px = (i) => pad + (i / (data.length - 1)) * (W - pad * 2)
  const py = (v) => H - pad - ((v / max) * (H - pad * 2))

  // Find spike index (highest value) for two-color rendering
  const spikeIdx = data.length > 1
    ? Math.max(data.length - 5, Math.floor(data.length * 0.88))
    : data.length - 1

  const mainPts = data.slice(0, spikeIdx + 1)
  const spikePts = data.slice(spikeIdx)

  const toPath = (pts, startIdx) =>
    pts.map((v, i) => `${i === 0 ? 'M' : 'L'}${px(startIdx + i).toFixed(1)},${py(v).toFixed(1)}`).join(' ')

  const mainLine = toPath(mainPts, 0)
  const mainArea = mainLine + ` L${px(spikeIdx).toFixed(1)},${H} L${pad},${H} Z`

  const spikeLine = spikePts.length > 1 ? toPath(spikePts, spikeIdx) : mainLine
  const spikeArea = spikePts.length > 1
    ? spikeLine + ` L${(W - pad).toFixed(1)},${H} L${px(spikeIdx).toFixed(1)},${H} Z`
    : ''

  // Build x-axis labels from real data hours or generate defaults
  const labels = useMemo(() => {
    if (rawData && rawData.length > 1 && rawData[0]?.hour) {
      const step = Math.max(1, Math.floor(rawData.length / 8))
      return rawData
        .filter((_, i) => i % step === 0)
        .slice(0, 8)
        .map(d => {
          if (!d.hour) return ''
          return d.hour.length >= 16 ? d.hour.substring(11, 16) : d.hour.substring(0, 5)
        })
    }
    return ['15:00', '18:00', '21:00', '00:00', '03:00', '06:00', '09:00', '12:00']
  }, [rawData])

  return (
    <svg viewBox={`0 0 ${W} ${H + 20}`} preserveAspectRatio="none" style={{ width: '100%', height: '100%' }}>
      <defs>
        <linearGradient id="mainGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.22" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
        <linearGradient id="spikeGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={spikeColor} stopOpacity="0.18" />
          <stop offset="100%" stopColor={spikeColor} stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* Grid lines */}
      {[0.25, 0.5, 0.75].map(r => (
        <line key={r} x1={pad} y1={pad + r * (H - pad * 2)} x2={W - pad} y2={pad + r * (H - pad * 2)}
          stroke="var(--ln)" strokeWidth="1" />
      ))}

      {/* Main area + line */}
      <path d={mainArea} fill="url(#mainGrad)" />
      <path d={mainLine} fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />

      {/* Spike area + line */}
      {spikeArea && <path d={spikeArea} fill="url(#spikeGrad)" />}
      {spikePts.length > 1 && <path d={spikeLine} fill="none" stroke={spikeColor} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />}

      {/* X labels */}
      {labels.map((lbl, i) => (
        <text key={i}
          x={pad + (i / (labels.length - 1)) * (W - pad * 2)}
          y={H + 16}
          fontSize="10" fill="var(--t3)"
          fontFamily="IBM Plex Mono, monospace"
          textAnchor="middle"
        >{lbl}</text>
      ))}
    </svg>
  )
}
