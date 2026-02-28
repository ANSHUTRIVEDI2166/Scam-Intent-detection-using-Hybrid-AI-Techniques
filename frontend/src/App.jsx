import { useState, useRef, useEffect, useCallback } from 'react'
import Chat from './components/Chat.jsx'
import IntelPanel from './components/IntelPanel.jsx'
import Sidebar from './components/Sidebar.jsx'
import SessionsView from './components/SessionsView.jsx'
import ToastContainer from './components/Toast.jsx'
import { ShieldAlert, MessageSquare, Database } from 'lucide-react'

export default function App() {
  const [tab, setTab] = useState('chat')          // 'chat' | 'sessions'
  const [serverStatus, setServerStatus] = useState('checking') // 'online'|'offline'|'checking'
  const [apiBase, setApiBase] = useState('http://localhost:8000')
  const [apiKey, setApiKey] = useState('')
  const [sessionId, setSessionId] = useState(generateSessionId())
  const [messages, setMessages] = useState([])
  const [intelligence, setIntelligence] = useState(null)
  const [scamInfo, setScamInfo] = useState(null)
  const [isTyping, setIsTyping] = useState(false)
  const [toasts, setToasts] = useState([])
  const [msgCount, setMsgCount] = useState(0)

  // ── Toast helpers ─────────────────────────────────
  const toast = useCallback((msg, type = 'info') => {
    const id = Date.now()
    setToasts(t => [...t, { id, msg, type }])
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 3500)
  }, [])

  // ── Check server health ───────────────────────────
  const checkServer = useCallback(async () => {
    setServerStatus('checking')
    try {
      const res = await fetch(`${apiBase}/health`, { signal: AbortSignal.timeout(4000) })
      if (res.ok) {
        setServerStatus('online')
        toast('Server is online', 'success')
      } else {
        setServerStatus('offline')
        toast('Server returned an error', 'error')
      }
    } catch {
      setServerStatus('offline')
      toast('Cannot reach server', 'error')
    }
  }, [apiBase, toast])

  // Check on mount
  useEffect(() => { checkServer() }, []) // eslint-disable-line

  // ── New session ───────────────────────────────────
  const newSession = () => {
    setSessionId(generateSessionId())
    setMessages([])
    setIntelligence(null)
    setScamInfo(null)
    setMsgCount(0)
    toast('New session started', 'info')
  }

  // ── Send message ──────────────────────────────────
  const sendMessage = async (text, sender) => {
    if (!text.trim()) return

    const userMsg = { role: sender, content: text, ts: new Date().toISOString() }
    setMessages(prev => [...prev, userMsg])
    setIsTyping(true)

    try {
      const headers = { 'Content-Type': 'application/json' }
      if (apiKey) headers['x-api-key'] = apiKey

      const body = {
        sessionId,
        message: { sender, text, timestamp: Date.now() },
        conversationHistory: [],
        metadata: { channel: 'SMS', language: 'English', locale: 'IN' },
      }

      const res = await fetch(`${apiBase}/api/message`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30000),
      })

      const data = await res.json()

      if (data.status === 'success' && data.reply) {
        const agentMsg = { role: 'assistant', content: data.reply, ts: new Date().toISOString() }
        setMessages(prev => [...prev, agentMsg])
        setMsgCount(c => c + 2)
      } else {
        toast(data.error || 'No reply received', 'error')
      }

      // fetch latest intelligence
      await refreshIntel()
    } catch (err) {
      toast(`Error: ${err.message}`, 'error')
    } finally {
      setIsTyping(false)
    }
  }

  // ── Refresh intelligence from saved session ───────
  const refreshIntel = async () => {
    try {
      const res = await fetch(`${apiBase}/api/sessions/${sessionId}/intelligence`)
      if (res.ok) {
        const data = await res.json()
        if (data.data) {
          setIntelligence(data.data.extractedIntelligence || null)
          setScamInfo({
            detected: data.data.scamDetected,
            confidence: data.data.scamConfidenceScore,
          })
        }
      }
    } catch {
      // silent — may not exist yet
    }
  }

  // ── Also pull from in-memory sessions endpoint ────
  const getSessionState = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/api/session/${sessionId}`)
      if (res.ok) {
        const data = await res.json()
        setIntelligence(data.extractedIntelligence || null)
        setScamInfo({ detected: data.scamDetected, confidence: data.scamConfidence })
        setMsgCount(data.totalMessages || 0)
      }
    } catch { /* silent */ }
  }, [apiBase, sessionId])

  return (
    <div className="layout">
      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="topbar-logo">
          <ShieldAlert size={22} />
          ScamShield
          <span className="tag">AI Honeypot</span>
        </div>

        <div className="topbar-spacer" />

        <div className="topbar-tabs">
          <button
            className={`topbar-tab ${tab === 'chat' ? 'active' : ''}`}
            onClick={() => setTab('chat')}
          >
            <MessageSquare size={14} />
            Chat
            {msgCount > 0 && <span className="badge">{msgCount}</span>}
          </button>
          <button
            className={`topbar-tab ${tab === 'sessions' ? 'active' : ''}`}
            onClick={() => setTab('sessions')}
          >
            <Database size={14} />
            Sessions
          </button>
        </div>

        <div className="topbar-server">
          <div className={`status-dot ${serverStatus}`} />
          <span>{serverStatus === 'online' ? 'Online' : serverStatus === 'checking' ? 'Checking…' : 'Offline'}</span>
        </div>
      </header>

      {/* ── Sidebar ── */}
      <Sidebar
        apiBase={apiBase}
        setApiBase={setApiBase}
        apiKey={apiKey}
        setApiKey={setApiKey}
        sessionId={sessionId}
        msgCount={msgCount}
        scamInfo={scamInfo}
        onConnect={checkServer}
        onNewSession={newSession}
        onGetState={getSessionState}
        serverStatus={serverStatus}
      />

      {/* ── Main area ── */}
      <main className="main-area">
        {tab === 'chat' ? (
          <Chat
            messages={messages}
            isTyping={isTyping}
            scamInfo={scamInfo}
            onSend={sendMessage}
            disabled={serverStatus !== 'online'}
          />
        ) : (
          <SessionsView apiBase={apiBase} apiKey={apiKey} toast={toast} />
        )}
      </main>

      {/* ── Intel Panel ── */}
      <IntelPanel intelligence={intelligence} scamInfo={scamInfo} />

      {/* ── Toasts ── */}
      <ToastContainer toasts={toasts} />
    </div>
  )
}

function generateSessionId() {
  return 'sess_' + Math.random().toString(36).slice(2, 10) + '_' + Date.now()
}
