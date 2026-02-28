import { useState, useRef, useEffect } from 'react'
import { Send, ShieldAlert, Shield } from 'lucide-react'

export default function Chat({ messages, isTyping, scamInfo, onSend, disabled }) {
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('scammer')
  const bottomRef = useRef(null)
  const textareaRef = useRef(null)

  // Auto-scroll to bottom
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isTyping])

  // Listen for sample messages from sidebar
  useEffect(() => {
    const handler = (e) => {
      setInput(e.detail)
      setSender('scammer')
      textareaRef.current?.focus()
    }
    window.addEventListener('scamshield:sample', handler)
    return () => window.removeEventListener('scamshield:sample', handler)
  }, [])

  // Auto-resize textarea
  useEffect(() => {
    const el = textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = Math.min(el.scrollHeight, 120) + 'px'
  }, [input])

  const handleSend = () => {
    if (!input.trim() || disabled) return
    onSend(input.trim(), sender)
    setInput('')
    if (textareaRef.current) textareaRef.current.style.height = 'auto'
  }

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const formatTime = (ts) => {
    try {
      return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    } catch { return '' }
  }

  return (
    <div className="chat-view">
      {/* Scam alert banner */}
      {scamInfo?.detected && (
        <div className="scam-alert" style={{margin:'12px 20px 0'}}>
          <ShieldAlert size={14} />
          SCAM DETECTED — AI Honeypot engaged. Extracting intelligence…
        </div>
      )}

      {/* Messages */}
      <div className="chat-messages">
        {messages.length === 0 && !isTyping ? (
          <div className="chat-empty">
            <div className="chat-empty-icon">🛡️</div>
            <h3>Ready to Detect Scams</h3>
            <p>Send a suspicious message to trigger the AI honeypot agent. Use the quick test buttons in the sidebar to get started.</p>
          </div>
        ) : (
          messages.map((msg, i) => (
            <div
              key={i}
              className={`message-wrapper ${msg.role === 'assistant' ? 'assistant' : 'scammer'}`}
            >
              <div className={`message-avatar ${msg.role === 'assistant' ? 'assistant-av' : 'scammer-av'}`}>
                {msg.role === 'assistant' ? '🛡️' : '🦹'}
              </div>
              <div className="message-body">
                <div className="message-meta">
                  <strong>{msg.role === 'assistant' ? 'ScamShield Agent' : msg.role === 'scammer' ? 'Scammer' : 'User'}</strong>
                  <span>{formatTime(msg.ts)}</span>
                </div>
                <div className={`message-bubble ${msg.role === 'assistant' ? 'bubble-assistant' : 'bubble-scammer'}`}>
                  {msg.content}
                </div>
              </div>
            </div>
          ))
        )}

        {isTyping && (
          <div className="message-wrapper assistant">
            <div className="message-avatar assistant-av">🛡️</div>
            <div className="message-body">
              <div className="message-meta"><strong>ScamShield Agent</strong></div>
              <div className="message-bubble bubble-assistant message-typing">
                <span className="typing-dot" />
                <span className="typing-dot" />
                <span className="typing-dot" />
              </div>
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="chat-input-area">
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          <div style={{fontSize:11,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase',letterSpacing:'0.8px'}}>Sender:</div>
          <div className="sender-toggle">
            <button
              className={`sender-btn ${sender === 'scammer' ? 'active-scammer' : ''}`}
              onClick={() => setSender('scammer')}
            >
              🦹 Scammer
            </button>
            <button
              className={`sender-btn ${sender === 'user' ? 'active-user' : ''}`}
              onClick={() => setSender('user')}
            >
              👤 User
            </button>
          </div>
          {disabled && (
            <span style={{fontSize:11,color:'var(--red)',marginLeft:'auto'}}>
              ⚠ Server offline — start backend first
            </span>
          )}
        </div>

        <div className="chat-input-row">
          <div className="input-wrap">
            <textarea
              ref={textareaRef}
              className="chat-textarea"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder={disabled ? 'Server is offline…' : 'Type a message to test scam detection… (Enter to send)'}
              rows={1}
              disabled={disabled}
            />
          </div>
          <button
            className="btn-send"
            onClick={handleSend}
            disabled={!input.trim() || disabled}
            title="Send (Enter)"
          >
            {isTyping ? <div className="spinner" style={{width:16,height:16,borderWidth:2}} /> : <Send size={18} />}
          </button>
        </div>
      </div>
    </div>
  )
}
