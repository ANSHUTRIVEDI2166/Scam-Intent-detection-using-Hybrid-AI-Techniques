import { Globe, Key, Wifi, RefreshCw, Plus, Info } from 'lucide-react'

export default function Sidebar({
  apiBase, setApiBase,
  apiKey, setApiKey,
  sessionId, msgCount, scamInfo,
  onConnect, onNewSession, onGetState,
  serverStatus,
}) {
  const samples = [
    { label: '🏦 Bank Scam', msg: 'URGENT! Your SBI account has been blocked. Verify your KYC immediately or your account will be permanently suspended. Click here: http://sbi-kyc-verify.xyz and share your OTP to our agent at 9876543210.' },
    { label: '🎉 Lottery Scam', msg: 'Congratulations! You have won ₹50,00,000 in the India Government Lucky Draw 2025. To claim your prize, you must pay a processing fee of ₹5,000 to account 1234567890123456. Contact winner@luckydraw-india.com' },
    { label: '👮 KYC Scam', msg: 'Dear Customer, your Paytm KYC is expiring today. Send ₹1 to UPI ID kyc.verify@paytm to complete verification. For help call 8800123456 or visit http://paytm-kyc-update.in' },
    { label: '💰 Investment Scam', msg: 'Hi! I am Priya from StockGuru. We have a guaranteed 300% return investment scheme. Already 5000+ investors earning daily. WhatsApp 7700889900 or visit http://stockguru-profits.com to join. Limited slots!' },
    { label: '📦 Delivery Scam', msg: 'Your package is held at customs. Pay customs fee ₹2,500 via UPI to release@customs.in or call 9988776655. Ref: PKG-2025-988766. Visit http://india-customs-release.com' },
    { label: '✅ Normal Message', msg: 'Hi! How are you doing? What are your plans for the weekend?' },
  ]

  return (
    <aside className="sidebar">
      {/* Server Config */}
      <div className="sidebar-section">
        <div className="sidebar-label"><Globe size={10} style={{display:'inline',marginRight:4}}/>Backend Server</div>
        <div className="sidebar-input-group">
          <input
            className="sidebar-input"
            value={apiBase}
            onChange={e => setApiBase(e.target.value)}
            placeholder="http://localhost:8000"
          />
          <input
            className="sidebar-input"
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder="API Key (optional)"
          />
          <button className="btn btn-primary" onClick={onConnect}>
            <Wifi size={13} />
            Connect
          </button>
        </div>
      </div>

      <div className="sidebar-divider" />

      {/* Session Info */}
      <div className="sidebar-section">
        <div className="sidebar-label"><Info size={10} style={{display:'inline',marginRight:4}}/>Current Session</div>
        <div className="session-card">
          <div className="session-card-row">
            <span className="session-card-label">Session ID</span>
            <span className="session-card-value mono" title={sessionId}>{sessionId.slice(0, 18)}…</span>
          </div>
          <div className="session-card-row">
            <span className="session-card-label">Messages</span>
            <span className="session-card-value">{msgCount}</span>
          </div>
          {scamInfo && (
            <>
              <div className="session-card-row">
                <span className="session-card-label">Scam Detected</span>
                <span className={`chip ${scamInfo.detected ? 'chip-red' : 'chip-green'}`}>
                  {scamInfo.detected ? '⚠ YES' : '✓ No'}
                </span>
              </div>
              {typeof scamInfo.confidence === 'number' && (
                <div style={{marginTop:4}}>
                  <div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4,fontWeight:600,textTransform:'uppercase',letterSpacing:'0.8px'}}>Confidence</div>
                  <div className="confidence-bar-wrap">
                    <div className="confidence-bar-track">
                      <div
                        className={`confidence-bar-fill ${
                          scamInfo.confidence > 0.65 ? 'conf-high' :
                          scamInfo.confidence > 0.35 ? 'conf-med' : 'conf-low'
                        }`}
                        style={{ width: `${Math.round(scamInfo.confidence * 100)}%` }}
                      />
                    </div>
                    <span className="confidence-val">{Math.round((scamInfo.confidence || 0) * 100)}%</span>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
        <div style={{display:'flex',gap:6}}>
          <button className="btn btn-primary" style={{flex:1}} onClick={onNewSession}>
            <Plus size={13} /> New Session
          </button>
          <button className="btn btn-ghost" onClick={onGetState} title="Refresh state">
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      <div className="sidebar-divider" />

      {/* Quick Samples */}
      <div className="sidebar-section" style={{flex:1,overflow:'hidden',display:'flex',flexDirection:'column'}}>
        <div className="sidebar-label">Quick Test Messages</div>
        <div className="samples-list" style={{overflowY:'auto',flex:1}}>
          {samples.map(s => (
            <button
              key={s.label}
              className="sample-btn"
              onClick={() => {
                // Place sample in chat -- dispatch a custom event
                window.dispatchEvent(new CustomEvent('scamshield:sample', { detail: s.msg }))
              }}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>
    </aside>
  )
}
