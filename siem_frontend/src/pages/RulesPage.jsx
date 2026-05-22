import { useState, useEffect } from 'react'
import Icon from '../components/Icons.jsx'
import { rulesApi } from '../services/api.js'

const sevColors = { CRITICAL: 'var(--r)', HIGH: 'var(--o)', MEDIUM: 'var(--y)', LOW: 'var(--g)', INFO: 'var(--b)' }

const EMPTY_RULE = { name: '', description: '', severity: 'medium', threat_type: 'unknown', conditions: [{ field: 'message', operator: 'contains', value: '' }], enabled: true }

export default function RulesPage() {
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [newRule, setNewRule] = useState(EMPTY_RULE)
  const [saving, setSaving] = useState(false)
  const [toggling, setToggling] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const [showImport, setShowImport] = useState(false)
  const [sigmaYaml, setSigmaYaml] = useState('')
  const [importing, setImporting] = useState(false)
  const [selectedRule, setSelectedRule] = useState(null)

  const fetchRules = async () => {
    try {
      const data = await rulesApi.list()
      setRules(data.rules || [])
    } catch (e) {
      console.error('Rules fetch error:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchRules() }, [])

  const toggle = async (id, isBuiltin) => {
    if (isBuiltin) return
    setToggling(id)
    try {
      await rulesApi.toggle(id)
      setRules(r => r.map(rule => rule.id === id ? { ...rule, enabled: !rule.enabled } : rule))
    } catch (e) {
      console.error('Toggle error:', e)
    } finally {
      setToggling(null)
    }
  }

  const deleteRule = async (id) => {
    setDeleting(id)
    try {
      await rulesApi.delete(id)
      setRules(r => r.filter(rule => rule.id !== id))
    } catch (e) {
      console.error('Delete error:', e)
    } finally {
      setDeleting(null)
    }
  }

  const createRule = async () => {
    if (!newRule.name.trim()) return
    setSaving(true)
    try {
      await rulesApi.create(newRule)
      setShowForm(false)
      setNewRule(EMPTY_RULE)
      fetchRules()
    } catch (e) {
      console.error('Create rule error:', e)
    } finally {
      setSaving(false)
    }
  }
  
  const handleImport = async () => {
    if (!sigmaYaml.trim()) return
    setImporting(true)
    try {
      await rulesApi.importSigma(sigmaYaml)
      setShowImport(false)
      setSigmaYaml('')
      fetchRules()
    } catch (e) {
      alert('Import failed: ' + e.message)
    } finally {
      setImporting(false)
    }
  }

  const updateCondition = (i, field, val) => {
    const conds = [...newRule.conditions]
    conds[i] = { ...conds[i], [field]: val }
    setNewRule(r => ({ ...r, conditions: conds }))
  }

  const addCondition = () => setNewRule(r => ({ ...r, conditions: [...r.conditions, { field: 'message', operator: 'contains', value: '' }] }))
  const removeCondition = (i) => setNewRule(r => ({ ...r, conditions: r.conditions.filter((_, idx) => idx !== i) }))

  const formatDate = (ts) => {
    if (!ts) return '—'
    try { return new Date(ts).toISOString().substring(0, 10) } catch { return ts }
  }

  return (
    <div className="page-content anim-fade">
      <div className="card" style={{ flex: 1 }}>
        <div className="card-head">
          <div className="card-title"><Icon.Star />Detection Rules</div>
          <div className="row">
            <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}><Icon.Plus />{showForm ? 'Cancel' : 'New Rule'}</button>
            <button className="btn" onClick={() => setShowImport(true)}><Icon.Download />Import SIGMA</button>
          </div>
        </div>

        {/* New Rule Form */}
        {showForm && (
          <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--ln)', background: 'var(--bg2)', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
              <input className="inp" style={{ flex: 2, minWidth: 180 }} placeholder="Rule name *" value={newRule.name} onChange={e => setNewRule(r => ({ ...r, name: e.target.value }))} />
              <select className="sel" value={newRule.severity} onChange={e => setNewRule(r => ({ ...r, severity: e.target.value }))}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <input className="inp" style={{ flex: 1, minWidth: 120 }} placeholder="Threat type" value={newRule.threat_type} onChange={e => setNewRule(r => ({ ...r, threat_type: e.target.value }))} />
            </div>
            <input className="inp" placeholder="Description" value={newRule.description} onChange={e => setNewRule(r => ({ ...r, description: e.target.value }))} />
            <div style={{ fontSize: 11, color: 'var(--t3)', fontWeight: 700, marginTop: 4 }}>CONDITIONS (all must match)</div>
            {newRule.conditions.map((cond, i) => (
              <div key={i} className="row" style={{ gap: 6 }}>
                <input className="inp" style={{ flex: 1 }} placeholder="field (e.g. message)" value={cond.field} onChange={e => updateCondition(i, 'field', e.target.value)} />
                <select className="sel" value={cond.operator} onChange={e => updateCondition(i, 'operator', e.target.value)}>
                  <option value="contains">contains</option>
                  <option value="equals">equals</option>
                  <option value="regex">regex</option>
                  <option value="gt">greater than</option>
                  <option value="lt">less than</option>
                </select>
                <input className="inp" style={{ flex: 2 }} placeholder="value" value={cond.value} onChange={e => updateCondition(i, 'value', e.target.value)} />
                {newRule.conditions.length > 1 && (
                  <button className="btn btn-danger" style={{ fontSize: 11, padding: '4px 8px' }} onClick={() => removeCondition(i)}><Icon.X /></button>
                )}
              </div>
            ))}
            <div className="row" style={{ gap: 8 }}>
              <button className="btn" style={{ fontSize: 11 }} onClick={addCondition}><Icon.Plus />Add Condition</button>
              <button className="btn btn-primary" style={{ fontSize: 11 }} onClick={createRule} disabled={saving}>
                {saving ? 'Saving…' : 'Create Rule'}
              </button>
            </div>
          </div>
        )}

        <div className="scroll-y" style={{ maxHeight: showForm ? 'calc(100vh - 430px)' : 'calc(100vh - 230px)' }}>
          {loading ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--t3)' }}>
              <span className="live-dot" style={{ background: 'var(--b)' }} /> Loading rules…
            </div>
          ) : rules.map(r => {
            const sev = (r.severity || 'medium').toUpperCase()
            return (
              <div className="rule-row" key={r.id}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="rule-name">{r.name}</div>
                  <div className="rule-meta">
                    {r.builtin ? '🔒 Built-in' : '✏️ Custom'} · {r.threat_type || r.category || 'General'}
                    {r.mitre_tactic && ` · ${r.mitre_tactic}`}
                    {r.updated_at && ` · Updated ${formatDate(r.updated_at)}`}
                  </div>
                </div>
                <span className={`sev sev-${sev}`}>{sev}</span>
                <span style={{ fontSize: 12, color: 'var(--t3)', fontFamily: 'IBM Plex Mono, monospace', minWidth: 60, textAlign: 'right' }}>{r.hit_count ?? 0} hits</span>
                <button className="btn" style={{ fontSize: 11 }} onClick={() => setSelectedRule(r)}><Icon.Eye />View</button>
                {!r.builtin && (
                  <button className="btn btn-danger" style={{ fontSize: 11 }} disabled={deleting === r.id} onClick={() => deleteRule(r.id)}>
                    <Icon.X />{deleting === r.id ? '…' : 'Del'}
                  </button>
                )}
                {/* Toggle */}
                <div
                  onClick={() => toggle(r.id, r.builtin)}
                  style={{
                    width: 40, height: 22, borderRadius: 11, cursor: r.builtin ? 'not-allowed' : 'pointer',
                    background: r.enabled ? 'var(--g)' : 'var(--bg4)',
                    position: 'relative', transition: 'background 0.2s', flexShrink: 0,
                    opacity: toggling === r.id ? 0.6 : 1,
                  }}
                >
                  <div style={{
                    position: 'absolute', top: 3, left: r.enabled ? 21 : 3,
                    width: 16, height: 16, borderRadius: '50%', background: 'white',
                    transition: 'left 0.2s',
                  }} />
                </div>
              </div>
            )
          })}
          {!loading && rules.length === 0 && (
            <div className="empty-state"><Icon.Star style={{ width: 24 }} /><p>No rules found</p></div>
          )}
        </div>
      </div>

      {showImport && (
        <div className="modal-overlay" onClick={() => setShowImport(false)}>
          <div className="modal-card anim-slide-up" onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div className="modal-title">Import SIGMA Rule (YAML)</div>
              <button className="btn-icon" onClick={() => setShowImport(false)}><Icon.X /></button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: 13, color: 'var(--t3)', marginBottom: 15 }}>
                Paste the contents of a standard SIGMA detection rule below. The system will automatically map the detection logic and severity levels.
              </p>
              <textarea 
                className="inp" 
                style={{ 
                  width: '100%', minHeight: 200, fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
                  padding: 12, lineHeight: 1.5, background: 'var(--bg1)'
                }}
                placeholder="title: Suspicious PowerShell Execution
logsource:
    product: windows
    service: security
detection:
    selection:
        event_id: 4688
        process_name: '*\powershell.exe'
    condition: selection
level: high"
                value={sigmaYaml}
                onChange={e => setSigmaYaml(e.target.value)}
              />
            </div>
            <div className="modal-foot">
              <button className="btn" onClick={() => setShowImport(false)}>Cancel</button>
              <button 
                className="btn btn-primary" 
                onClick={handleImport}
                disabled={importing || !sigmaYaml.trim()}
              >
                {importing ? 'Importing...' : 'Confirm Import'}
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedRule && (
        <div className="modal-overlay" onClick={() => setSelectedRule(null)}>
          <div className="modal-card anim-slide-up" onClick={e => e.stopPropagation()} style={{ maxWidth: 600 }}>
            <div className="modal-head">
              <div className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon.Shield style={{ color: 'var(--b)' }} /> Rule Details
              </div>
              <button className="btn-icon" onClick={() => setSelectedRule(null)}><Icon.X /></button>
            </div>
            <div className="modal-body scroll-y" style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--t1)' }}>{selectedRule.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontFamily: 'IBM Plex Mono, monospace' }}>{selectedRule.id}</span>
                    {selectedRule.builtin && <span className="tag" style={{ background: 'var(--bg3)', borderColor: 'var(--ln)' }}>Built-in</span>}
                  </div>
                </div>
                <span className={`sev sev-${(selectedRule.severity || 'medium').toUpperCase()}`} style={{ fontSize: 12 }}>
                  {(selectedRule.severity || 'medium').toUpperCase()}
                </span>
              </div>
              
              <div style={{ background: 'var(--bg2)', padding: 14, borderRadius: 8, border: '1px solid var(--ln)', fontSize: 13, color: 'var(--t2)', marginBottom: 20 }}>
                {selectedRule.description || 'No description provided.'}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, max-content) 1fr', gap: '12px 16px', fontSize: 13, marginBottom: 20 }}>
                <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Threat Type</div>
                <div style={{ color: 'var(--t1)' }}>{selectedRule.threat_type || selectedRule.category || '—'}</div>
                
                <div style={{ color: 'var(--t3)', fontWeight: 600 }}>MITRE Tactic</div>
                <div style={{ color: 'var(--t1)' }}>{selectedRule.mitre_tactic || '—'}</div>
                
                <div style={{ color: 'var(--t3)', fontWeight: 600 }}>MITRE Technique</div>
                <div style={{ color: 'var(--t1)' }}>{selectedRule.mitre_technique || '—'}</div>
                
                <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Total Hits</div>
                <div style={{ color: 'var(--t1)', fontFamily: 'IBM Plex Mono, monospace', fontWeight: 600 }}>{selectedRule.hit_count ?? 0} times triggered</div>
                
                <div style={{ color: 'var(--t3)', fontWeight: 600 }}>Status</div>
                <div style={{ color: selectedRule.enabled ? 'var(--g)' : 'var(--r)', fontWeight: 700 }}>
                  {selectedRule.enabled ? 'ACTIVE' : 'DISABLED'}
                </div>
              </div>

              {selectedRule.conditions && selectedRule.conditions.length > 0 && (
                <>
                  <div style={{ fontSize: 11, color: 'var(--t3)', fontWeight: 700, marginTop: 4, marginBottom: 8, letterSpacing: '0.06em' }}>DETECTION CONDITIONS</div>
                  <div style={{ background: 'var(--bg0)', padding: 12, borderRadius: 6, border: '1px solid var(--ln)' }}>
                    {selectedRule.conditions.map((c, i) => (
                      <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', marginBottom: 6 }}>
                        <span style={{ color: 'var(--b)' }}>{c.field}</span>
                        <span style={{ color: 'var(--t3)' }}>{c.operator}</span>
                        <span style={{ color: 'var(--o)' }}>"{c.value}"</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
            <div className="modal-foot">
              <button className="btn btn-primary" onClick={() => setSelectedRule(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
