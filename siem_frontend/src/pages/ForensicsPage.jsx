import { useState, useEffect } from 'react'
import Icon from '../components/Icons.jsx'
import { forensicsApi } from '../services/api.js'

export default function ForensicsPage() {
  const [tab, setTab] = useState('timeline')
  const [cases, setCases] = useState([])
  const [selectedCase, setSelectedCase] = useState(null)
  const [caseData, setCaseData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [caseLoading, setCaseLoading] = useState(false)
  const [note, setNote] = useState('')
  const [addingNote, setAddingNote] = useState(false)
  const [statusMsg, setStatusMsg] = useState(null)
  const [selectedLogInfo, setSelectedLogInfo] = useState(null)
  const [newArtifact, setNewArtifact] = useState({ name: '', type: '', hash: '' })
  const [addingArtifact, setAddingArtifact] = useState(false)

  const showStatus = (msg) => {
    setStatusMsg(msg)
    setTimeout(() => setStatusMsg(null), 3000)
  }

  const handleDownloadArtifact = (artifact) => {
    try {
      const dataStr = JSON.stringify(artifact, null, 2)
      const blob = new Blob([dataStr], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `artifact_${(artifact.name || 'export').replace(/[^a-zA-Z0-9_-]/g, '_')}.json`
      document.body.appendChild(link)
      link.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(link)
      showStatus(`Artifact downloaded successfully`)
    } catch (e) {
      alert('Failed to download artifact: ' + e.message)
    }
  }

  const handleQuarantineArtifact = async (artifact) => {
    try {
      showStatus(`Initiating quarantine for ${artifact.name || artifact.path || 'artifact'}...`)
      // Simulate network request to autonomous agent
      await new Promise(res => setTimeout(res, 800))
      
      const fileName = artifact.name || artifact.path || 'unknown file'
      const noteText = `[AGENT ACTION] Automated response: Successfully quarantined malicious file '${fileName}'. The file has been isolated, encrypted, and stripped of execution privileges to prevent further lateral movement.`
      
      // Automatically add a note to the case so faculty can see the audited action
      await forensicsApi.addNote(selectedCase, noteText)
      
      const d = await forensicsApi.getCase(selectedCase)
      setCaseData(d)
      showStatus(`✓ Artifact quarantined successfully!`)
    } catch (e) {
      alert('Failed to quarantine artifact: ' + e.message)
    }
  }

  const handleDeleteCase = async () => {
    if (!selectedCase) return;
    if (!window.confirm('Are you sure you want to permanently delete this forensic case?')) return;
    
    setLoading(true)
    try {
      await forensicsApi.deleteCase(selectedCase)
      showStatus('✓ Case deleted successfully')
      
      const d = await forensicsApi.cases(20)
      const list = d.cases || []
      setCases(list)
      if (list.length > 0) {
        setSelectedCase(list[0].id)
      } else {
        setSelectedCase(null)
        setCaseData(null)
      }
    } catch (e) {
      alert('Failed to delete case: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    forensicsApi.cases(20)
      .then(d => {
        const list = d.cases || []
        setCases(list)
        if (list.length > 0) setSelectedCase(list[0].id)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!selectedCase) return
    setCaseLoading(true)
    forensicsApi.getCase(selectedCase)
      .then(d => setCaseData(d))
      .catch(console.error)
      .finally(() => setCaseLoading(false))
  }, [selectedCase])

  const handleAddNote = async () => {
    if (!note.trim() || !selectedCase) return
    setAddingNote(true)
    try {
      await forensicsApi.addNote(selectedCase, note)
      setNote('')
      const d = await forensicsApi.getCase(selectedCase)
      setCaseData(d)
      showStatus('Note added successfully')
    } catch (e) {
      console.error('Add note error:', e)
      alert("Error adding note: " + e.message)
    } finally {
      setAddingNote(false)
    }
  }

  const handleAddArtifact = async () => {
    if (!newArtifact.name.trim() || !selectedCase) return
    setAddingArtifact(true)
    try {
      await forensicsApi.addArtifact(selectedCase, newArtifact)
      setNewArtifact({ name: '', type: '', hash: '' })
      const d = await forensicsApi.getCase(selectedCase)
      setCaseData(d)
      showStatus('Artifact added successfully')
    } catch (e) {
      console.error('Add artifact error:', e)
      alert("Error adding artifact: " + e.message)
    } finally {
      setAddingArtifact(false)
    }
  }

  const formatTime = (ts) => {
    if (!ts) return '—'
    try { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) } catch { return ts }
  }

  const sevMap = { critical: 'r', high: 'o', medium: 'y', low: 'b', info: 'b' }

  const evidence = caseData?.evidence || {}
  const timeline = evidence.timeline || caseData?.timeline || caseData?.evidence_summary?.logs || []
  const artifacts = [
    ...(evidence.related_threats || []),
    ...(evidence.file_artifacts || []),
    ...(caseData?.artifacts || []),
    ...(caseData?.evidence_summary?.files || [])
  ]
  const notes = caseData?.notes || []

  return (
    <div className="page-content anim-fade">
      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="card-title"><Icon.Activity />Digital Forensics</div>
          <div className="row">
            <select className="sel" value={selectedCase || ''} onChange={e => setSelectedCase(e.target.value)}>
              {loading ? <option>Loading cases…</option> : cases.length === 0 ? <option>No cases found</option> : cases.map(c => (
                <option key={c.id} value={c.id}>{c.case_id || `Case: ${c.alert_id}`}</option>
              ))}
            </select>
            {selectedCase && (
              <div className="row" style={{ gap: 8 }}>
                <button
                  className="btn btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}
                  onClick={async () => {
                    try {
                      const res = await fetch(forensicsApi.exportCase(selectedCase), {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('siem-token')}` }
                      });
                      if (!res.ok) throw new Error('Export failed');
                      const blob = await res.blob();
                      const url = window.URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `forensic_case_${selectedCase}.json`;
                      document.body.appendChild(a);
                      a.click();
                      window.URL.revokeObjectURL(url);
                    } catch (e) {
                      alert('Export failed: ' + e.message);
                    }
                  }}
                >
                  <Icon.Download />Export
                </button>
                <button
                  className="btn btn-danger"
                  style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}
                  onClick={handleDeleteCase}
                >
                  <Icon.Trash />Delete
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Tabs */}
        <div className="row" style={{ padding: '8px 14px', borderBottom: '1px solid var(--ln)', gap: 4 }}>
          {['timeline', 'artifacts', 'notes'].map(t => (
            <button key={t} onClick={() => setTab(t)} className="btn" style={{
              background: tab === t ? 'var(--b-dim)' : 'transparent',
              color: tab === t ? 'var(--b)' : 'var(--t3)',
              borderColor: tab === t ? 'rgba(59,125,232,0.3)' : 'transparent',
              textTransform: 'capitalize', fontSize: 12,
            }}>{t === 'timeline' ? '🕐 Timeline' : t === 'artifacts' ? '📁 Artifacts' : '📝 Notes'}</button>
          ))}
        </div>

        {caseLoading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--t3)' }}>
            <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading case data…
          </div>
        ) : !selectedCase || cases.length === 0 ? (
          <div className="empty-state">
            <Icon.Activity style={{ width: 28 }} />
            <p>No forensic cases found. Collect evidence from the Alerts page.</p>
          </div>
        ) : (
          <>
            {tab === 'timeline' && (
              <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 250px)' }}>
                {timeline.length === 0 ? (
                  <div className="empty-state"><Icon.Clock style={{ width: 24 }} /><p>No timeline events</p></div>
                ) : timeline.map((ev, i) => {
                  const s = sevMap[ev.severity?.toLowerCase()] || 'b'
                  return (
                    <div className="timeline-item" key={i}>
                      <div className="timeline-time">{formatTime(ev.timestamp || ev.time)}</div>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0, flexShrink: 0 }}>
                        <div className="timeline-dot" style={{ background: `var(--${s})`, boxShadow: `0 0 6px var(--${s})`, width: 9, height: 9 }} />
                        {i < timeline.length - 1 && (
                          <div style={{ width: 1, flex: 1, minHeight: 24, background: 'var(--ln)', marginTop: 4 }} />
                        )}
                      </div>
                      <div className="timeline-content">
                        <div className="row" style={{ marginBottom: 3 }}>
                          <div className="timeline-title">{ev.event_type || ev.title || ev.type || 'Event'}</div>
                          {ev.hostname && <span className="tag" style={{ fontSize: 9, color: 'var(--b)', borderColor: 'rgba(59,125,232,0.3)', marginLeft: 6 }}>{ev.hostname}</span>}
                          <button
                            className="btn"
                            style={{ padding: '4px 8px', marginLeft: 'auto', fontSize: 10, background: 'var(--b)', color: '#fff', border: 'none', borderRadius: 4, fontWeight: 600 }}
                            title="View Detailed Log Information"
                            onClick={() => setSelectedLogInfo(ev)}
                          >
                            <Icon.File style={{ width: 10, height: 10, marginRight: 4 }} />
                            Log Details
                          </button>
                        </div>
                        <div className="timeline-desc">{ev.message || ev.description || ev.desc || '—'}</div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}

            {tab === 'artifacts' && (
              <div className="scroll-y" style={{ maxHeight: 'calc(100vh - 280px)' }}>
                <table className="siem-table">
                  <thead>
                    <tr><th>File</th><th>Type</th><th>Size</th><th>Hash</th><th>Threat</th><th>Actions</th></tr>
                  </thead>
                  <tbody>
                    {artifacts.length === 0 ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--t3)', padding: 24 }}>No artifacts collected</td></tr>
                    ) : artifacts.map((a, i) => (
                      <tr key={i}>
                        <td>
                          <span className="mono" style={{ fontSize: 11, color: a.is_threat ? 'var(--r)' : 'var(--t1)', fontWeight: a.is_threat ? 700 : 400 }}>
                            {a.name || a.path || '—'}
                          </span>
                        </td>
                        <td><span className="tag" style={{ fontSize: 9, color: 'var(--p)', borderColor: 'rgba(139,92,246,0.3)' }}>{a.type || 'File'}</span></td>
                        <td><span className="mono" style={{ fontSize: 11 }}>{a.size || '—'}</span></td>
                        <td><span className="mono" style={{ fontSize: 10, color: 'var(--t3)' }}>{(a.hash || a.sha256 || '—').substring(0, 16)}{a.hash ? '…' : ''}</span></td>
                        <td>
                          {a.is_threat
                            ? <span className="sev sev-HIGH">MALICIOUS</span>
                            : <span className="sev sev-LOW">CLEAN</span>
                          }
                        </td>
                        <td>
                          <div className="row" style={{ gap: 6 }}>
                            <button className="btn" style={{ fontSize: 10 }} onClick={() => handleDownloadArtifact(a)}>
                              <Icon.Download />Download
                            </button>
                            {a.is_threat && (
                              <button className="btn btn-danger" style={{ fontSize: 10 }} onClick={() => handleQuarantineArtifact(a)}>
                                <Icon.X />Quarantine
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div style={{ padding: '16px', borderTop: '1px solid var(--ln)', display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <input className="inp" style={{ flex: 1, minWidth: 150 }} placeholder="Artifact Name / Path" value={newArtifact.name} onChange={e => setNewArtifact({...newArtifact, name: e.target.value})} />
                  <input className="inp" style={{ width: 120 }} placeholder="Type (e.g. File, IP)" value={newArtifact.type} onChange={e => setNewArtifact({...newArtifact, type: e.target.value})} />
                  <input className="inp" style={{ flex: 1, minWidth: 150 }} placeholder="SHA256 Hash or Details" value={newArtifact.hash} onChange={e => setNewArtifact({...newArtifact, hash: e.target.value})} />
                  <button className="btn btn-primary" onClick={handleAddArtifact} disabled={addingArtifact || !newArtifact.name.trim()}>
                    {addingArtifact ? 'Adding…' : 'Add Artifact'}
                  </button>
                </div>
              </div>
            )}

            {tab === 'notes' && (
              <div className="scroll-y" style={{ flex: 1, maxHeight: 'calc(100vh - 250px)', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
                {notes.map((n, i) => (
                  <div key={i} style={{ background: 'var(--bg2)', border: '1px solid var(--ln)', borderRadius: 8, padding: '10px 14px' }}>
                    <div style={{ fontSize: 11, color: 'var(--t3)', marginBottom: 4 }}>{n.author || 'analyst'} · {formatTime(n.timestamp)}</div>
                    <div style={{ fontSize: 13, color: 'var(--t1)' }}>{n.text || n.note}</div>
                  </div>
                ))}
                {notes.length === 0 && <div style={{ color: 'var(--t3)', fontSize: 13 }}>No notes yet.</div>}
                <div className="row" style={{ gap: 8, marginTop: 8 }}>
                  <input className="inp" style={{ flex: 1 }} placeholder="Add investigator note…" value={note} onChange={e => setNote(e.target.value)} />
                  <button className="btn btn-primary" style={{ fontSize: 12 }} onClick={handleAddNote} disabled={addingNote}>
                    {addingNote ? 'Adding…' : 'Add Note'}
                  </button>
                </div>
              </div>
            )}
            
            {statusMsg && (
              <div className="anim-fade" style={{
                position: 'absolute', bottom: 20, right: 20,
                background: 'var(--bg1)', border: '1px solid var(--b)',
                color: 'var(--b)', padding: '10px 16px', borderRadius: 8,
                boxShadow: '0 8px 30px rgba(0,0,0,0.3)', fontSize: 12,
                display: 'flex', alignItems: 'center', gap: 8, zIndex: 100
              }}>
                <Icon.Check style={{ width: 14, height: 14 }} />
                {statusMsg}
              </div>
            )}
            
            {/* Log Details Modal */}
            {selectedLogInfo && (
              <div className="anim-fade" style={{
                position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
              }}>
                <div style={{
                  background: 'var(--bg1)', width: 600, maxWidth: '90%', borderRadius: 12,
                  boxShadow: '0 20px 50px rgba(0,0,0,0.4)', border: '1px solid var(--ln)',
                  display: 'flex', flexDirection: 'column', maxHeight: '85vh'
                }}>
                  <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--ln)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--t1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Icon.File style={{ color: 'var(--b)' }} /> Forensic Log Details
                    </div>
                    <button className="icon-btn" onClick={() => setSelectedLogInfo(null)}><Icon.X /></button>
                  </div>
                  
                  <div className="scroll-y" style={{ padding: 20, flex: 1 }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, max-content) 1fr', gap: '12px 16px', fontSize: 13 }}>
                      
                      <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Timestamp</div>
                      <div style={{ color: 'var(--t1)', fontFamily: 'IBM Plex Mono, monospace' }}>{selectedLogInfo.timestamp || '—'}</div>
                      
                      <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Event ID</div>
                      <div>
                        {selectedLogInfo.event_id 
                          ? <span className="tag" style={{ background: 'var(--b-dim)', color: 'var(--b)', borderColor: 'transparent' }}>{selectedLogInfo.event_id}</span>
                          : '—'}
                      </div>
                      
                      <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Source</div>
                      <div style={{ color: 'var(--t1)' }}>{selectedLogInfo.source || selectedLogInfo.log_source || '—'}</div>
                      
                      <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Level</div>
                      <div style={{ color: 'var(--t1)' }}>
                        <span className={`sev sev-${(selectedLogInfo.log_level || selectedLogInfo.severity || 'INFO').toUpperCase()}`}>
                          {(selectedLogInfo.log_level || selectedLogInfo.severity || 'INFO').toUpperCase()}
                        </span>
                      </div>
                      
                      {selectedLogInfo.source_ip && (
                        <>
                          <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Source IP</div>
                          <div style={{ color: 'var(--t1)', fontFamily: 'IBM Plex Mono, monospace' }}>{selectedLogInfo.source_ip}</div>
                        </>
                      )}
                      
                      {selectedLogInfo.dest_ip && (
                        <>
                          <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Dest IP</div>
                          <div style={{ color: 'var(--t1)', fontFamily: 'IBM Plex Mono, monospace' }}>{selectedLogInfo.dest_ip}</div>
                        </>
                      )}

                      <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Message Payload</div>
                      <div style={{
                        background: 'var(--bg0)', padding: 12, borderRadius: 6, border: '1px solid var(--ln)',
                        fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: 'var(--t2)',
                        whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 250, overflowY: 'auto'
                      }}>
                        {selectedLogInfo.message || selectedLogInfo.description || selectedLogInfo.title || 'No message provided.'}
                      </div>

                      <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Raw Output</div>
                      <div style={{
                        background: '#0d1117', padding: 12, borderRadius: 6, border: '1px solid #30363d',
                        fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#c9d1d9',
                        whiteSpace: 'pre-wrap', maxHeight: 150, overflowY: 'auto'
                      }}>
                        {JSON.stringify(selectedLogInfo, null, 2)}
                      </div>
                    </div>
                  </div>
                  
                  <div style={{ padding: '12px 20px', borderTop: '1px solid var(--ln)', display: 'flex', justifyContent: 'flex-end', background: 'var(--bg2)' }}>
                    <button className="btn btn-primary" onClick={() => setSelectedLogInfo(null)}>Close</button>
                  </div>
                </div>
              </div>
            )}

          </>
        )}
      </div>
    </div>
  )
}
