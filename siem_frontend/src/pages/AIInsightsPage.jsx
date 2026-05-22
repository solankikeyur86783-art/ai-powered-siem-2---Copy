import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Icon from "../components/Icons.jsx";
import { aiApi } from "../services/api.js";


function normalizeAnomaly(a, index) {
  return {
    ...a,
    id: a.id || a._id || ("anomaly-" + index),
    anomaly_type: a.anomaly_type || a.type || "ANOMALY",
    confidence_score: a.confidence_score != null ? a.confidence_score : (a.score != null ? a.score : 0.90),
    severity: (a.severity || "medium").toUpperCase(),
    title: a.title || a.description || "Anomaly Detected",
    detected_at: a.detected_at || a.timestamp || new Date().toISOString(),
  };
}

function WaveIcon({ size = 16, color = "var(--b)" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

function BoltIcon({ size = 16, color = "white" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill={color}>
      <path d="M13 2L4.5 13.5H11L10 22L19.5 10.5H13L13 2Z" />
    </svg>
  );
}

function ChevronIcon({ open }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--t3)"
      strokeWidth="2"
      style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.25s" }}
    >
      <polyline points="18 15 12 9 6 15" />
    </svg>
  );
}

const statusColors = {
  danger: "var(--r)",
  warn: "var(--y)",
  ok: "var(--g)",
  info: "var(--b)"
};

function ConfidenceBar({ value }) {
  const color = value > 85 ? "var(--g)" : value > 60 ? "var(--y)" : "var(--r)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <span style={{ color: "var(--t3)", fontSize: 11 }}>CONFIDENCE</span>
      <div style={{ width: 80, height: 5, background: "var(--ln)", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${value}%`, height: "100%", background: color, borderRadius: 3 }} />
      </div>
      <span style={{ color: color, fontSize: 11, fontWeight: 500 }}>{value}%</span>
    </div>
  );
}

function RatePill({ label, value }) {
  return (
    <div
      style={{
        background: "var(--bg3)",
        border: "1px solid var(--ln)",
        borderRadius: 5,
        padding: "4px 10px",
        fontSize: 11,
        display: "flex",
        gap: 4,
      }}
    >
      <span style={{ color: "var(--t3)" }}>{label}</span>
      <span style={{ color: "var(--t1)", fontWeight: 500 }}>{value}</span>
    </div>
  );
}

function getTypeFromAnomaly(a) {
  const t = (a.anomaly_type || a.type || "").toUpperCase();
  if (t.includes("ANOMAL")) return "ANOMALY";
  if (t.includes("CORREL")) return "CORRELATION";
  if (t.includes("BEHAV")) return "BEHAVIORAL";
  if (t.includes("PREDICT")) return "PREDICTION";
  return "ANOMALY";
}

function timeAgo(ts) {
  if (!ts) return "—";
  try {
    const diff = Date.now() - new Date(ts).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return "just now";
    if (m < 60) return `${m} minutes ago`;
    return `${Math.floor(m / 60)} hours ago`;
  } catch {
    return ts;
  }
}

function AIAnalytics({ data }) {
  const confidence = Math.round((data.confidence_score ?? data.score ?? 0.90) * 100);
  const riskColor = confidence > 80 ? "var(--r)" : "var(--y)";
  const riskLabel = confidence > 80 ? "HIGH" : "MEDIUM";

  let logic = data.description || "Advanced pattern matching detected behavioral traces consistent with known TTPs.";
  if (data.type === 'threat_rate_spike') logic = "The system identified a significant surge in the ratio of malicious indicator hits relative to the baseline.";
  if (data.type === 'unusual_events') logic = "Detection of operational events that have zero historical frequency in the current environment's training set.";
  if (data.type === 'new_source_ips') logic = "Traffic observed from previously unseen infrastructure endpoints.";
  if (data.type === 'volume_spike') logic = "Aggregated log volume has exceeded standard deviations from the moving average.";

  const markers = [];
  if (data.metric !== undefined) markers.push({ name: "Primary Metric", value: String(data.metric), status: "info" });
  if (data.z_score !== undefined) markers.push({ name: "Z-Score Variant", value: data.z_score.toFixed(2), status: Math.abs(data.z_score) > 3 ? "danger" : "warn" });
  if (data.baseline_avg !== undefined) markers.push({ name: "Baseline Expected", value: data.baseline_avg, status: "info" });
  if (data.current_value !== undefined) markers.push({ name: "Current Value (1h)", value: data.current_value, status: "danger" });

  const agent = data.hostname || "unknown";
  const service = data.service || "unknown";

  return (
    <div style={{ padding: "0 16px 16px" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
        <div style={boxStyle}>
          <div style={boxTitleStyle}>Detection Logic</div>
          <div style={{ color: "var(--t2)", fontSize: 12, lineHeight: 1.6 }}>{logic}</div>
        </div>
        <div style={boxStyle}>
          <div style={boxTitleStyle}>Affected Assets</div>
          <div style={{ color: "var(--t2)", fontSize: 12, lineHeight: 1.8 }}>
            <div>Agent / Host: {agent}</div>
            {data.new_ips && <div>Target IPs: {data.new_ips.slice(0, 3).join(', ')}</div>}
            {data.new_event_ids && <div>Event IDs: {data.new_event_ids.join(', ')}</div>}
            <div>Service: {service}</div>
          </div>
        </div>
      </div>

      <div style={boxStyle}>
        <div style={boxTitleStyle}>Technical Markers</div>
        {markers.map((m, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "5px 0",
              borderBottom: i < markers.length - 1 ? "1px solid var(--ln)" : "none",
            }}
          >
            <span style={{ color: "var(--t3)", fontSize: 11 }}>{m.name}</span>
            <span style={{ color: statusColors[m.status] || statusColors.info, fontSize: 11, fontWeight: 500 }}>{m.value}</span>
          </div>
        ))}
        {markers.length === 0 && <div style={{ color: "var(--t3)", fontSize: 11, padding: "5px 0" }}>Standard anomaly behavior matched.</div>}
        <div style={{ marginTop: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--t3)", marginBottom: 4 }}>
            <span>Overall Risk Score</span>
            <span style={{ color: riskColor, fontWeight: 500 }}>{riskLabel} — {confidence}</span>
          </div>
          <div style={{ height: 6, background: "var(--ln)", borderRadius: 3, overflow: "hidden" }}>
            <div style={{ width: `${confidence}%`, height: "100%", background: riskColor, borderRadius: 3 }} />
          </div>
        </div>
      </div>
    </div>
  );
}

const boxStyle = {
  background: "var(--bg2)",
  border: "1px solid var(--ln)",
  borderRadius: 8,
  padding: "10px 12px",
  marginBottom: 0,
};

const boxTitleStyle = {
  color: "var(--t3)",
  fontSize: 10,
  letterSpacing: "0.5px",
  textTransform: "uppercase",
  marginBottom: 6,
};

function AlertCard({ alert, defaultOpen = false, onResolve, onDismiss, resolving }) {
  const [open, setOpen] = useState(defaultOpen);
  const type = getTypeFromAnomaly(alert);
  const confidence = Math.round((alert.confidence_score ?? alert.score ?? 0.90) * 100);
  const sev = (alert.severity || "MEDIUM").toUpperCase();

  const typeBadgeCol = type === 'PREDICTION' ? 'var(--p)' : 'var(--r)';
  const sevBadgeCol = sev === 'CRITICAL' ? 'var(--r)' : sev === 'HIGH' ? 'var(--y)' : 'var(--g)';

  const navigate = useNavigate();
  const investigate = () => {
    if (alert.type?.includes("ips") || alert.new_ips) {
      navigate(`/logs?q=${(alert.new_ips || [])[0] || ""}`);
    } else if (alert.new_event_ids) {
      navigate(`/logs?q=event_id:${alert.new_event_ids[0]}`);
    } else {
      navigate("/logs");
    }
  };

  return (
    <div
      style={{
        background: "var(--bg2)",
        border: `1px solid ${open ? "var(--b)" : "var(--ln)"}`,
        borderRadius: 10,
        overflow: "hidden",
        transition: "border-color 0.2s",
      }}
    >
      <div style={{ padding: "14px 16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div style={{ display: "flex", gap: 6 }}>
            <span style={{ ...badgeBase, borderColor: typeBadgeCol, color: typeBadgeCol, background: `transparent` }}>{type}</span>
            <span style={{ ...badgeBase, borderColor: sevBadgeCol, color: sevBadgeCol, background: `transparent` }}>{sev}</span>
          </div>
          <ConfidenceBar value={confidence} />
        </div>

        <div style={{ color: "var(--t1)", fontSize: 13, marginBottom: 10, fontWeight: 500 }}>
          {alert.title || alert.description || "Anomaly Detected"}
        </div>

        <div style={{ color: "var(--t2)", fontSize: 12, marginBottom: 10 }}>
          {alert.description}
        </div>

        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          {alert.current_rate !== undefined && <RatePill label="DETECTION RATE:" value={`${alert.current_rate}%`} />}
          {alert.baseline_rate !== undefined && <RatePill label="BASELINE RATE:" value={`${alert.baseline_rate}%`} />}
          {alert.z_score !== undefined && <RatePill label="Z-SCORE:" value={alert.z_score.toFixed(2)} />}
        </div>

        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <button style={investigateBtn} onClick={investigate}>Investigate</button>
          <button style={resolveBtn} disabled={resolving} onClick={() => onResolve(alert.id)}>
            {resolving ? "Resolving..." : "✓ Resolve"}
          </button>
          <button style={dismissBtn} disabled={resolving} onClick={() => onDismiss(alert.id)}>
            ✕ Dismiss
          </button>
        </div>

        <div style={{ color: "var(--t3)", fontSize: 11 }}>
          Detected &nbsp;·&nbsp; {timeAgo(alert.detected_at || alert.timestamp)}
        </div>
      </div>

      <div style={{ borderTop: "1px solid var(--ln)", background: "var(--bg0)" }}>
        <button
          onClick={() => setOpen(!open)}
          style={{
            width: "100%",
            background: "transparent",
            border: "none",
            padding: "10px 16px",
            display: "flex",
            alignItems: "center",
            gap: 8,
            cursor: "pointer",
          }}
        >
          <WaveIcon />
          <span style={{ color: "var(--b)", fontSize: 12, fontWeight: 500, letterSpacing: "0.5px" }}>
            AI ANALYTICS &amp; REASONING
          </span>
          <span style={{ marginLeft: "auto" }}>
            <ChevronIcon open={open} />
          </span>
        </button>

        {open && <AIAnalytics data={alert} />}
      </div>
    </div>
  );
}

const badgeBase = {
  fontSize: 10,
  fontWeight: 500,
  padding: "2px 8px",
  borderRadius: 4,
  border: "1px solid",
  letterSpacing: "0.5px",
};

const investigateBtn = {
  background: "var(--b)",
  border: "none",
  borderRadius: 6,
  color: "white",
  fontSize: 12,
  padding: "6px 14px",
  cursor: "pointer",
};

const resolveBtn = {
  background: "transparent",
  border: "1px solid var(--ln)",
  borderRadius: 6,
  color: "var(--t3)",
  fontSize: 12,
  padding: "6px 14px",
  cursor: "pointer",
};

const dismissBtn = {
  background: "rgba(248,81,73,0.1)",
  border: "1px solid rgba(248,81,73,0.4)",
  borderRadius: 6,
  color: "var(--r)",
  fontSize: 12,
  padding: "6px 14px",
  cursor: "pointer",
};

export default function AIInsightsPage() {
  const [anomalies, setAnomalies] = useState([]);
  const [modelInfo, setModelInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [retraining, setRetraining] = useState(false);
  const [resolving, setResolving] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [anomData, modelData] = await Promise.all([
        aiApi.anomalies(24),
        aiApi.modelStatus().catch(() => ({ status: "unknown", current_model: null })),
      ]);
      setAnomalies((anomData.anomalies || []).map(normalizeAnomaly));
      setModelInfo(modelData);
    } catch (e) {
      console.error("AI Insights fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const runScan = async () => {
    setScanning(true);
    try {
      const res = await aiApi.scan();
      const anomRes = await aiApi.anomalies(24);

      const mlThreats = (res.predictions || [])
        .filter((p) => p.attack_type !== "Normal" && p.confidence >= 0.25)
        .map((p) => ({
          id: p.id || Math.random().toString(),
          type: "PREDICTION",
          severity: p.severity,
          score: p.confidence,
          title: `ML Detection: ${p.attack_type}`,
          description: p.description || p.message || `Detected signature of ${p.attack_type}`,
          metric: p.log_source || "live_scan",
          detected_at: p.timestamp || new Date().toISOString(),
          hostname: p.hostname,
          service: p.service,
        }));

      setAnomalies((anomRes.anomalies || []).map(normalizeAnomaly));
    } catch (e) {
      console.error("Scan error:", e);
    } finally {
      setScanning(false);
    }
  };

  const retrain = async () => {
    setRetraining(true);
    try {
      await aiApi.retrain();
      const modelData = await aiApi.modelStatus();
      setModelInfo(modelData);
    } catch (e) {
      console.error("Retrain error:", e);
    } finally {
      setRetraining(false);
    }
  };

  const resolve = async (id) => {
    setResolving(id);
    try {
      await aiApi.resolve(id);
      setAnomalies((a) => a.filter((x) => x.id !== id));
    } catch (e) {
      console.error("Resolve error:", e);
    } finally {
      setResolving(null);
    }
  };

  const dismiss = async (id) => {
    setResolving(id);
    try {
      await aiApi.dismiss(id);
      setAnomalies((a) => a.filter((x) => x.id !== id));
    } catch (e) {
      console.error("Dismiss error:", e);
    } finally {
      setResolving(null);
    }
  };

  return (
    <div className="page-content anim-fade">
      <div
        className="card"
        style={{
          padding: "12px 20px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "0",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              background: "var(--b)",
              borderRadius: 6,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <BoltIcon />
          </div>
          <span style={{ color: "var(--t1)", fontSize: 15, fontWeight: 500 }}>
            AI Security Insights
            {loading ? ' (Loading...)' : ` (${anomalies.length})`}
          </span>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <button style={resolveBtn} disabled={loading} onClick={fetchData}>
            ↺ Refresh
          </button>
          <button style={resolveBtn} disabled={scanning} onClick={runScan}>
            <Icon.Search style={{ width: 12, height: 12, marginRight: 4, display: 'inline' }} />
            {scanning ? "Scanning..." : "⚡ Run AI Detection"}
          </button>
          <button style={investigateBtn} disabled={retraining} onClick={retrain}>
            ⚡ {retraining ? "Training..." : "Retrain Model"}
          </button>
        </div>
      </div>

      <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 160px)', paddingBottom: 20 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {anomalies.length === 0 && !loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--t3)' }}>
              <Icon.Check style={{ width: 28, color: 'var(--g)', marginBottom: 10 }} />
              <p>No anomalies detected in the last 24 hours.</p>
            </div>
          ) : (
            anomalies.map((alert, i) => (
              <AlertCard
                key={alert.id}
                alert={alert}
                defaultOpen={i === 0}
                onResolve={resolve}
                onDismiss={dismiss}
                resolving={resolving === alert.id}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
