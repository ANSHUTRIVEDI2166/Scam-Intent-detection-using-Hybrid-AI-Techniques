import { useState, useEffect, useCallback } from 'react'
import { RefreshCw, ChevronDown, ChevronRight, Download, AlertTriangle, Check } from 'lucide-react'

export default function SessionsView({ apiBase, apiKey, toast }) {
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState(null)

  const fetchSessions = useCallback(async () => {
    setLoading(true)
    try {
      const headers = {}
      if (apiKey) headers['x-api-key'] = apiKey
      const res = await fetch(`${apiBase}/api/sessions`, { headers })
      if (res.ok) {
        const data = await res.json()
        setSessions((data.sessions || []).reverse()) // newest first
      } else {
        toast('Failed to load sessions', 'error')
      }
    } catch (e) {
      toast(`Error: ${e.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }, [apiBase, apiKey, toast])

  useEffect(() => { fetchSessions() }, [fetchSessions])

  const totalScams = sessions.filter(s => s.scamDetected).length
  const totalItems = sessions.reduce((acc, s) => {
    const intel = s.extractedIntelligence || {}
    return acc + Object.values(intel).flat().length
  }, 0)
  const avgDuration = sessions.length
    ? Math.round(sessions.reduce((a, s) => a + (s.engagementDurationSeconds || 0), 0) / sessions.length)
    : 0

  const exportSession = (session) => {
    const blob = new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `session_${session.sessionId}_${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
    toast('Session exported', 'success')
  }

  const intelCount = (intel) =>
    Object.values(intel || {}).flat().filter(v => typeof v === 'string').length

  const INTEL_CATS = [
    { key: 'phoneNumbers', label: 'Phones', color: 'var(--yellow)' },
    { key: 'upiIds', label: 'UPI IDs', color: 'var(--green)' },
    { key: 'bankAccounts', label: 'Bank Accts', color: 'var(--accent)' },
    { key: 'phishingLinks', label: 'URLs', color: 'var(--accent)' },
    { key: 'emailAddresses', label: 'Emails', color: 'var(--purple)' },
  ]

  return (
    <div className="sessions-view">
      {/* Header */}
      <div className="sessions-header">
        <div>
          <div className="sessions-title">Session History</div>
          <div className="sessions-sub">All intelligence saved locally from scam interactions</div>
        </div>
        <button className="btn btn-ghost" onClick={fetchSessions} disabled={loading}>
          {loading ? <div className="spinner" /> : <RefreshCw size={13} />}
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="sessions-stats">
        <div className="stat-card">
          <div className="stat-value">{sessions.length}</div>
          <div className="stat-label">Total Sessions</div>
        </div>
        <div className="stat-card red">
          <div className="stat-value">{totalScams}</div>
          <div className="stat-label">Scams Detected</div>
        </div>
        <div className="stat-card green">
          <div className="stat-value">{totalItems}</div>
          <div className="stat-label">Intel Items</div>
        </div>
        <div className="stat-card yellow">
          <div className="stat-value">{avgDuration}s</div>
          <div className="stat-label">Avg Engagement</div>
        </div>
      </div>

      {/* Sessions list */}
      {sessions.length === 0 ? (
        <div className="sessions-empty">
          <div className="sessions-empty-icon">📂</div>
          <h3>No Sessions Yet</h3>
          <p>Send some scam messages from the Chat tab to create sessions. They'll be saved automatically to <code style={{fontFamily:'var(--font-mono)',color:'var(--accent)',fontSize:11}}>data/intelligence_log.json</code>.</p>
        </div>
      ) : (
        <div className="sessions-grid">
          {sessions.map((session) => {
            const isOpen = expanded === session.sessionId
            const intel = session.extractedIntelligence || {}
            const items = intelCount(intel)

            return (
              <div key={session.sessionId}>
                <div
                  className="session-row"
                  onClick={() => setExpanded(isOpen ? null : session.sessionId)}
                >
                  {/* ID + time */}
                  <div className="session-row-id">
                    <strong title={session.sessionId}>
                      {session.sessionId?.slice(0, 22)}…
                    </strong>
                    <span className="muted" style={{fontSize:11}}>
                      {session.savedAt ? new Date(session.savedAt).toLocaleString() : '—'}
                    </span>
                  </div>

                  {/* Scam badge */}
                  <span className={`chip ${session.scamDetected ? 'chip-red' : 'chip-green'}`}>
                    {session.scamDetected ? <><AlertTriangle size={10}/> Scam</> : <><Check size={10}/> Clean</>}
                  </span>

                  {/* Messages */}
                  <span className="chip chip-blue">{session.totalMessagesExchanged || 0} msgs</span>

                  {/* Intel count */}
                  <span className="chip chip-yellow">{items} items</span>

                  {/* Actions */}
                  <div style={{display:'flex',gap:4}} onClick={e => e.stopPropagation()}>
                    <button className="btn btn-ghost" style={{padding:'4px 8px'}} onClick={() => exportSession(session)} title="Export JSON">
                      <Download size={12} />
                    </button>
                    {isOpen ? <ChevronDown size={14} style={{color:'var(--text-muted)',margin:'auto'}} /> : <ChevronRight size={14} style={{color:'var(--text-muted)',margin:'auto'}} />}
                  </div>
                </div>

                {/* Expanded detail */}
                {isOpen && (
                  <div className="session-detail-panel" style={{margin:'0 0 8px'}}>
                    {INTEL_CATS.map(({ key, label, color }) => {
                      const vals = intel[key] || []
                      return (
                        <div className="session-detail-section" key={key}>
                          <div className="session-detail-title" style={{color}}>{label}</div>
                          {vals.length === 0 ? (
                            <span style={{fontSize:11,color:'var(--text-muted)'}}>None found</span>
                          ) : (
                            vals.map((v, i) => (
                              <div key={i} className="detail-item" style={{color,background:`${color}10`,border:`1px solid ${color}22`,fontSize:11}}>
                                {v}
                              </div>
                            ))
                          )}
                        </div>
                      )
                    })}
                    <div className="session-detail-section">
                      <div className="session-detail-title" style={{color:'var(--text-secondary)'}}>Engagement</div>
                      <div style={{fontSize:12,color:'var(--text-secondary)'}}>
                        <div>⏱ {session.engagementDurationSeconds || 0}s duration</div>
                        <div>💬 {session.totalMessagesExchanged || 0} messages</div>
                        <div>📊 Status: <span style={{color:'var(--green)'}}>{session.status}</span></div>
                      </div>
                      {session.agentNotes && (
                        <div style={{fontSize:11,color:'var(--text-muted)',marginTop:4,lineHeight:1.5}}>
                          <em>{session.agentNotes.slice(0, 120)}{session.agentNotes.length > 120 ? '…' : ''}</em>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
