import { useState, useEffect, useRef, useCallback } from "react"
import Globe from "react-globe.gl"
import * as topojson from "topojson-client"
import * as d3 from "d3"
import { intelApi } from "../services/api.js"

const WIDTH = 800
const HEIGHT = 420
const TARGETS = [
  { lat: 32.0853, lon: 34.7818, name: "TLV-GW" },
  { lat: 40.7128, lon: -74.0060, name: "NYC-DC" },
  { lat: 51.5074, lon: -0.1278, name: "LON-GW" },
  { lat: 35.6762, lon: 139.6503, name: "TOK-DC" },
  { lat: -33.8688, lon: 151.2093, name: "SYD-GW" }
]

const ATTACK_TYPES = [
  "SYN FLOOD", "Trojan Horse", "DDoS", "DoS",
  "Cryptojacking", "MITM", "Ping Flood", "Teardrop", "Smurf",
  "IP Spoofing", "Replay Attack", "Password Spray", "SQL Injection",
  "Brute Force", "Ransomware", "Port Scan", "Phishing", "XSS",
  "Tor Hidden Service", "Tor Exit Node", "Tor Exfiltration", "Tor Brute Force",
  "Zero-Day Exploit", "Supply Chain Attack", "DNS Tunneling", "LDAP Injection",
  "Insider Threat", "Credential Stuffing", "Log4Shell", "Heartbleed",
  "ARP Poisoning", "BGP Hijack", "Botnet C2", "Rootkit Deployment",
]

const TOR_ATTACK_TYPES = [
  "Tor Exit Node", "Tor Hidden Service", "Tor Exfiltration", "Tor Brute Force"
]

const TOR_NODES = [
  { ip: "193.23.244.244", country: "Netherlands", label: "TOR-EXIT-NL" },
  { ip: "185.220.101.42", country: "Germany",     label: "TOR-EXIT-DE" },
  { ip: "199.87.154.255", country: "USA",          label: "TOR-RELAY-US" },
  { ip: "62.102.148.68",  country: "Sweden",       label: "TOR-EXIT-SE" },
  { ip: "176.10.104.240", country: "Austria",      label: "TOR-EXIT-AT" },
]

const COUNTRIES = [
  { name: "China",       code: "CN", lat: 35.86, lon: 104.19 },
  { name: "Russia",      code: "RU", lat: 61.52, lon: 105.31 },
  { name: "USA",         code: "US", lat: 37.09, lon: -95.71 },
  { name: "Brazil",      code: "BR", lat: -14.23, lon: -51.92 },
  { name: "Germany",     code: "DE", lat: 51.16, lon: 10.45 },
  { name: "India",       code: "IN", lat: 20.59, lon: 78.96 },
  { name: "Ukraine",     code: "UA", lat: 48.37, lon: 31.16 },
  { name: "Netherlands", code: "NL", lat: 52.13, lon: 5.29 },
  { name: "Iran",        code: "IR", lat: 32.42, lon: 53.68 },
  { name: "N. Korea",    code: "KP", lat: 40.33, lon: 127.51 },
  { name: "Vietnam",     code: "VN", lat: 14.05, lon: 108.27 },
  { name: "Nigeria",     code: "NG", lat: 9.08,  lon: 8.67  },
  { name: "Romania",     code: "RO", lat: 45.94, lon: 24.96 },
  { name: "Turkey",      code: "TR", lat: 38.96, lon: 35.24 },
  { name: "Pakistan",    code: "PK", lat: 30.37, lon: 69.34 },
]

const SEV_COLOR = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#22c55e" }

function randInt(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a }
function randFrom(arr) { return arr[randInt(0, arr.length - 1)] }
function randIp() { return randInt(1,254)+"."+randInt(0,255)+"."+randInt(0,255)+"."+randInt(1,254) }
function getSev() {
  const r = Math.random()
  if (r < 0.1) return "CRITICAL"
  if (r < 0.3) return "HIGH"
  if (r < 0.65) return "MEDIUM"
  return "LOW"
}

export default function ThreatMapPage() {
  const globeEl = useRef()
  const [logs, setLogs] = useState([])
  const [torEvents, setTorEvents] = useState([])
  const [stats, setStats] = useState({ active: 0, total: 0, countries: 0, blocked: 0, tor: 0 })
  const [filter, setFilter] = useState("ALL")
  const [paused, setPaused] = useState(false)
  const [theme, setTheme] = useState("color")
  
  const [countriesData, setCountriesData] = useState({ features: [] })
  const [countryLabels, setCountryLabels] = useState([])
  const [arcsData, setArcsData] = useState([])
  const [ringsData, setRingsData] = useState([])

  const pausedRef = useRef(false)
  const filterRef = useRef("ALL")
  const statsRef = useRef({ active: 0, total: 0, countries: new Set(), blocked: 0, tor: 0 })

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    filterRef.current = filter
  }, [filter])

  useEffect(() => {
    fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json")
      .then(r => r.json())
      .then(world => {
        const features = topojson.feature(world, world.objects.countries).features
        setCountriesData({ features })

        const labels = features.map(f => {
          const centroid = d3.geoCentroid(f)
          return {
            name: f.properties.name,
            lon: centroid[0],
            lat: centroid[1],
            isCountry: true
          }
        }).filter(l => l.name)
        
        setCountryLabels(labels)
      })
  }, [])

  const fireAttack = useCallback((forceTor = false) => {
    if (pausedRef.current) return

    const isTor = forceTor || Math.random() < 0.08
    const torNode = isTor ? randFrom(TOR_NODES) : null
    const src = isTor
      ? COUNTRIES.find(c => c.name === torNode.country) || randFrom(COUNTRIES)
      : randFrom(COUNTRIES)
    const type = isTor ? randFrom(TOR_ATTACK_TYPES) : randFrom(ATTACK_TYPES)
    if (!isTor && filterRef.current !== "ALL" && type !== filterRef.current) return

    const sev = isTor ? (Math.random() < 0.6 ? "CRITICAL" : "HIGH") : getSev()
    const color = isTor ? "#a855f7" : SEV_COLOR[sev]
    const ip = isTor ? torNode.ip : randIp()
    const port = randInt(1, 65535)
    const now = new Date().toTimeString().slice(0, 8)
    const target = randFrom(TARGETS)

    const id = Date.now() + Math.random()
    const duration = isTor ? 2000 : 1500

    const newArc = {
      id,
      startLat: src.lat,
      startLng: src.lon,
      endLat: target.lat,
      endLng: target.lon,
      color: [color, color],
      duration
    }
    
    const newRing = {
      id,
      lat: src.lat,
      lng: src.lon,
      color,
      maxR: isTor ? 5 : 3,
      duration
    }

    setArcsData(prev => [...prev, newArc])
    setRingsData(prev => [...prev, newRing])

    setTimeout(() => {
      setArcsData(prev => prev.filter(a => a.id !== id))
      setRingsData(prev => prev.filter(r => r.id !== id))
    }, duration + 500)

    const s = statsRef.current
    s.total++
    s.countries.add(src.name)
    if (sev === "LOW" || sev === "MEDIUM") s.blocked++
    if (isTor) s.tor++
    setStats({ active: arcsData.length + 1, total: s.total, countries: s.countries.size, blocked: s.blocked, tor: s.tor })

    if (isTor) {
      setTorEvents(prev => [{
        time: now, ip, label: torNode?.label || "TOR-NODE", country: src.name,
        type, sev, target: target.name, id
      }, ...prev].slice(0, 20))
    }

    setLogs(prev => [{
      time: now, ip, country: src.name, sev, type, port, isTor, id
    }, ...prev].slice(0, 60))
  }, [arcsData.length])

  useEffect(() => {
    let timeout
    function schedule() {
      const delay = 500 + Math.random() * 900
      timeout = setTimeout(() => {
        fireAttack()
        if (Math.random() < 0.25) setTimeout(fireAttack, 200)
        schedule()
      }, delay)
    }
    schedule()

    // Also try to load real data
    intelApi.mapData(24).then(data => {
      const threats = data.threats || []
      threats.slice(0, 10).forEach((t, i) => {
        setTimeout(() => {
          const lat = t.geo?.latitude || t.latitude
          const lon = t.geo?.longitude || t.longitude
          if (!lat || !lon) return
          
          const sev = getSev()
          const color = SEV_COLOR[sev]
          const target = randFrom(TARGETS)
          const id = Date.now() + Math.random()

          const newArc = {
            id, startLat: lat, startLng: lon, endLat: target.lat, endLng: target.lon, color: [color, color], duration: 1500
          }
          setArcsData(prev => [...prev, newArc])
          setTimeout(() => setArcsData(prev => prev.filter(a => a.id !== id)), 2000)
        }, i * 300)
      })
    }).catch(() => {})

    return () => clearTimeout(timeout)
  }, [fireAttack])

  const FILTERS = ["ALL", "DDoS", "Brute Force", "Ransomware", "SQL Injection", "Tor Exit Node", "Tor Brute Force", "Zero-Day Exploit", "Botnet C2", "DNS Tunneling", "Phishing"]

  const handleZoomIn = () => {
    if (!globeEl.current) return
    const alt = globeEl.current.pointOfView().altitude
    globeEl.current.pointOfView({ altitude: Math.max(0.2, alt - 0.4) }, 300)
  }
  
  const handleZoomOut = () => {
    if (!globeEl.current) return
    const alt = globeEl.current.pointOfView().altitude
    globeEl.current.pointOfView({ altitude: Math.min(4, alt + 0.4) }, 300)
  }

  const colors = theme === "bw" ? {
    ocean: "#050505", land: "#1a1a1a", border: "#333333", target: "#aaaaaa"
  } : {
    ocean: "rgba(10, 14, 26, 0.2)", land: "#1a2744", border: "#2a3f6f", target: "#3b82f6"
  }

  return (
    <div style={{display:"flex",flexDirection:"column",flex:1,overflowY:"auto",overflowX:"hidden",minHeight:0,animation:"fadeIn 0.4s ease"}}>
      {/* Header */}
      <div className="card" style={{padding:"10px 16px",display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:0,borderRadius:"10px 10px 0 0",borderBottom:"none",flexWrap:"wrap",gap:8}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <span style={{width:8,height:8,borderRadius:"50%",background:"#22c55e",display:"inline-block",animation:"blink 1.5s infinite"}} />
          <span style={{color:"var(--t1)",fontSize:15,fontWeight:500}}>Global Cyber Threat Map</span>
          <span style={{fontSize:11,color:"var(--t3)"}}>{new Date().toUTCString().slice(0,25)}</span>
        </div>
        <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
          {FILTERS.map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              fontSize:11,padding:"3px 10px",borderRadius:4,cursor:"pointer",
              border: filter===f ? "1px solid #2563eb" : "1px solid var(--ln)",
              background: filter===f ? "rgba(37,99,235,.15)" : "transparent",
              color: filter===f ? "#60a5fa" : "var(--t3)"
            }}>{f}</button>
          ))}
          <button onClick={() => setPaused(p => !p)} style={{
            fontSize:11,padding:"4px 12px",borderRadius:4,cursor:"pointer",
            border:"1px solid var(--ln)",background:"var(--bg2)",color:"var(--t2)"
          }}>{paused ? "▶ Resume" : "⏸ Pause"}</button>
          <button onClick={() => setTheme(t => t === "color" ? "bw" : "color")} style={{
            fontSize:11,padding:"4px 12px",borderRadius:4,cursor:"pointer",
            border:"1px solid var(--ln)",background:"var(--bg2)",color:"var(--t2)"
          }}>{theme === "color" ? "B&W Mode" : "Color Mode"}</button>
        </div>
      </div>

      {/* Stats */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",background:"var(--bg2)",border:"1px solid var(--ln)",borderTop:"none",borderBottom:"1px solid var(--ln)"}}>
        {[
          {label:"Active Threats",val:stats.active,color:"#f87171"},
          {label:"Total Events",val:stats.total,color:"var(--t1)"},
          {label:"Source Countries",val:stats.countries,color:"#60a5fa"},
          {label:"Blocked",val:stats.blocked,color:"#4ade80"},
          {label:"Tor Attacks",val:stats.tor||0,color:"#a855f7"},
        ].map(s => (
          <div key={s.label} style={{padding:"8px 16px",textAlign:"center",borderRight:"1px solid var(--ln)"}}>
            <div style={{fontSize:20,fontWeight:500,color:s.color}}>{s.val}</div>
            <div style={{fontSize:11,color:"var(--t3)",marginTop:2}}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Map */}
      <div style={{background: theme === "bw" ? "#050505" : "transparent", border:"1px solid var(--ln)", borderTop:"none", position:"relative", display:"flex", justifyContent:"center", alignItems:"center", overflow:"hidden", flex: 1}}>
        <Globe
          ref={globeEl}
          width={1200}
          height={600}
          backgroundColor={colors.ocean}
          showAtmosphere={theme !== "bw"}
          atmosphereColor="#3b82f6"
          atmosphereAltitude={0.15}
          globeImageUrl={theme === "bw" ? null : "//unpkg.com/three-globe/example/img/earth-dark.jpg"}
          polygonsData={countriesData.features}
          polygonAltitude={0.005}
          polygonCapColor={() => colors.land}
          polygonSideColor={() => "rgba(0, 0, 0, 0.1)"}
          polygonStrokeColor={() => colors.border}
          arcsData={arcsData}
          arcStartLat={d => d.startLat}
          arcStartLng={d => d.startLng}
          arcEndLat={d => d.endLat}
          arcEndLng={d => d.endLng}
          arcColor={d => d.color}
          arcDashLength={0.4}
          arcDashGap={1}
          arcDashInitialGap={() => 1}
          arcDashAnimateTime={d => d.duration}
          arcAltitudeAutoScale={0.3}
          ringsData={ringsData}
          ringColor={d => d.color}
          ringMaxRadius={d => d.maxR}
          ringPropagationSpeed={2}
          ringRepeatPeriod={800}
          labelsData={[...TARGETS, ...countryLabels]}
          labelLat={d => d.lat}
          labelLng={d => d.lon}
          labelText={d => d.name}
          labelSize={d => d.isCountry ? 1.5 : 2.5}
          labelDotRadius={d => d.isCountry ? 0.3 : 0.6}
          labelColor={d => d.isCountry ? (theme === "bw" ? "rgba(200,200,200,0.8)" : "rgba(147,197,253,0.8)") : colors.target}
          labelAltitude={0.02}
          labelResolution={2}
        />
        
        {/* Zoom Controls Overlay */}
        <div style={{ position: "absolute", bottom: 20, right: 20, display: "flex", flexDirection: "column", gap: 8 }}>
          <button onClick={handleZoomIn} style={{ width: 36, height: 36, background: "var(--bg1)", border: "1px solid var(--ln)", borderRadius: 8, color: "var(--t1)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, fontWeight: 300, backdropFilter: "blur(10px)" }}>+</button>
          <button onClick={handleZoomOut} style={{ width: 36, height: 36, background: "var(--bg1)", border: "1px solid var(--ln)", borderRadius: 8, color: "var(--t1)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, fontWeight: 300, backdropFilter: "blur(10px)" }}>−</button>
        </div>
      </div>

      {/* Bottom panels: Log + Tor Feed */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 340px",gap:0,borderTop:"none"}}>

        {/* Event Log */}
        <div style={{background:"var(--bg1)",border:"1px solid var(--ln)",borderTop:"none",borderRight:"none",borderRadius:"0 0 0 10px",overflow:"hidden",maxHeight:220}}>
          <div style={{padding:"6px 16px",fontSize:11,color:"var(--t3)",borderBottom:"1px solid var(--ln)",fontWeight:500,letterSpacing:".5px",textTransform:"uppercase",display:"grid",gridTemplateColumns:"70px 110px 90px 80px 1fr 55px",gap:6}}>
            <span>Time</span><span>Source IP</span><span>Country</span><span>Severity</span><span>Attack Type</span><span>Port</span>
          </div>
          <div style={{overflowY:"auto",maxHeight:180}}>
            {logs.map(l => (
              <div key={l.id} style={{display:"grid",gridTemplateColumns:"70px 110px 90px 80px 1fr 55px",gap:6,padding:"4px 16px",fontSize:11,borderBottom:"1px solid var(--ln)",alignItems:"center",color:"var(--t3)",background:l.isTor?"rgba(168,85,247,0.06)":"transparent"}}>
                <span>{l.time}</span>
                <span style={{color:l.isTor?"#c084fc":"#60a5fa",fontFamily:"monospace"}}>{l.ip}</span>
                <span style={{color:"var(--t2)"}}>{l.country}</span>
                <span style={{
                  padding:"2px 6px",borderRadius:3,fontSize:10,fontWeight:500,textAlign:"center",display:"inline-block",
                  background: l.sev==="CRITICAL"?"rgba(220,38,38,.2)":l.sev==="HIGH"?"rgba(234,88,12,.2)":l.sev==="MEDIUM"?"rgba(202,138,4,.2)":"rgba(34,197,94,.2)",
                  color: l.isTor?"#c084fc":SEV_COLOR[l.sev]
                }}>{l.isTor?"TOR":l.sev}</span>
                <span style={{color:l.isTor?"#c084fc":"inherit"}}>{l.type}</span>
                <span>:{l.port}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Tor Attack Feed */}
        <div style={{background:"rgba(88,28,135,0.08)",border:"1px solid rgba(168,85,247,0.3)",borderTop:"none",borderRadius:"0 0 10px 0",overflow:"hidden",maxHeight:220}}>
          <div style={{padding:"6px 14px",borderBottom:"1px solid rgba(168,85,247,0.3)",display:"flex",alignItems:"center",gap:8}}>
            <span style={{width:7,height:7,borderRadius:"50%",background:"#a855f7",display:"inline-block",animation:"blink 1s infinite"}} />
            <span style={{fontSize:11,color:"#c084fc",fontWeight:600,letterSpacing:".5px",textTransform:"uppercase"}}>Tor Attack Feed</span>
            <span style={{marginLeft:"auto",fontSize:10,background:"rgba(168,85,247,.2)",color:"#c084fc",borderRadius:3,padding:"1px 6px"}}>{torEvents.length} detected</span>
          </div>
          <div style={{overflowY:"auto",maxHeight:180}}>
            {torEvents.length === 0 && (
              <div style={{padding:"20px",textAlign:"center",color:"rgba(168,85,247,0.4)",fontSize:12}}>Monitoring Tor network...</div>
            )}
            {torEvents.map(e => (
              <div key={e.id} style={{padding:"6px 14px",borderBottom:"1px solid rgba(168,85,247,0.15)",fontSize:11}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:2}}>
                  <span style={{color:"#c084fc",fontFamily:"monospace",fontSize:10}}>{e.ip}</span>
                  <span style={{color:"rgba(168,85,247,0.6)",fontSize:10}}>{e.time}</span>
                </div>
                <div style={{color:"#e879f9",fontSize:11,fontWeight:500,marginBottom:1}}>{e.type}</div>
                <div style={{display:"flex",gap:8}}>
                  <span style={{fontSize:10,color:"rgba(255,255,255,0.4)"}}>{e.label}</span>
                  <span style={{fontSize:10,color:"rgba(255,255,255,0.4)"}}>→ {e.target}</span>
                  <span style={{marginLeft:"auto",fontSize:10,color:e.sev==="CRITICAL"?"#f87171":"#fb923c",fontWeight:600}}>{e.sev}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      <style>{`@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}} @keyframes fadeIn{from{opacity:0}to{opacity:1}}`}</style>
    </div>
  )
}
