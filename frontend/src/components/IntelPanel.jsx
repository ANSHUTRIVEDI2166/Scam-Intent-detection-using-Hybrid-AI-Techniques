import { Brain, Phone, CreditCard, Link2, Mail, Tag, Shield } from 'lucide-react'

const CATEGORIES = [
  { key: 'phoneNumbers',    label: 'Phone Numbers',    icon: Phone,        cls: 'intel-item-phone' },
  { key: 'upiIds',          label: 'UPI IDs',          icon: CreditCard,   cls: '' },
  { key: 'bankAccounts',    label: 'Bank Accounts',    icon: CreditCard,   cls: '' },
  { key: 'phishingLinks',   label: 'Phishing Links',   icon: Link2,        cls: 'intel-item-url' },
  { key: 'emailAddresses',  label: 'Email Addresses',  icon: Mail,         cls: 'intel-item-email' },
  { key: 'suspiciousKeywords', label: 'Keywords',      icon: Tag,          cls: 'intel-item-keyword' },
]

export default function IntelPanel({ intelligence, scamInfo }) {
  const hasAnyIntel = intelligence &&
    CATEGORIES.some(c => (intelligence[c.key] || []).length > 0)

  const totalItems = intelligence
    ? CATEGORIES.reduce((s, c) => s + (intelligence[c.key] || []).length, 0)
    : 0

  return (
    <aside className="intel-panel">
      <div className="intel-header">
        <Brain size={15} />
        Extracted Intelligence
        {totalItems > 0 && (
          <span style={{marginLeft:'auto',fontSize:11,background:'var(--accent-glow)',border:'1px solid var(--border-bright)',color:'var(--accent)',padding:'1px 8px',borderRadius:99,fontWeight:700}}>
            {totalItems} item{totalItems !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      <div className="intel-body">
        {!hasAnyIntel ? (
          <div className="intel-empty">
            <Shield size={32} style={{opacity:0.3}} />
            <p>No intelligence extracted yet.<br/>Send a scam message to begin.</p>
          </div>
        ) : (
          CATEGORIES.map(({ key, label, icon: Icon, cls }) => {
            const items = intelligence?.[key] || []
            if (!items.length && key !== 'suspiciousKeywords') return null
            if (key === 'suspiciousKeywords' && items.length === 0) return null
            return (
              <div className="intel-category" key={key}>
                <div className="intel-cat-header">
                  <div className="intel-cat-title" style={{color:'var(--text-secondary)'}}>
                    <Icon size={11} />
                    {label}
                  </div>
                  <span className="intel-cat-count">{items.length}</span>
                </div>
                <div className="intel-items">
                  {items.slice(0, key === 'suspiciousKeywords' ? 8 : 999).map((item, i) => (
                    <div key={i} className={`intel-item ${cls}`} title={item}>
                      {key === 'phishingLinks'
                        ? (item.length > 45 ? item.slice(0, 45) + '…' : item)
                        : item
                      }
                    </div>
                  ))}
                  {key === 'suspiciousKeywords' && items.length > 8 && (
                    <div style={{fontSize:10,color:'var(--text-muted)',textAlign:'center',paddingTop:2}}>
                      +{items.length - 8} more keywords
                    </div>
                  )}
                </div>
              </div>
            )
          })
        )}

        {/* Scam Score Summary */}
        {scamInfo && (
          <div className="intel-category" style={{marginTop:4}}>
            <div className="intel-cat-header">
              <div className="intel-cat-title" style={{color: scamInfo.detected ? 'var(--red)' : 'var(--green)'}}>
                <Shield size={11} />
                Scam Analysis
              </div>
            </div>
            <div className="intel-items" style={{gap:8}}>
              <div style={{fontSize:12,fontWeight:600}}>
                Status:&nbsp;
                <span style={{color: scamInfo.detected ? 'var(--red)' : 'var(--green)'}}>
                  {scamInfo.detected ? '⚠ SCAM DETECTED' : '✓ No scam detected'}
                </span>
              </div>
              {typeof scamInfo.confidence === 'number' && (
                <div>
                  <div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4,fontWeight:600,textTransform:'uppercase',letterSpacing:'0.8px'}}>Confidence Level</div>
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
            </div>
          </div>
        )}
      </div>
    </aside>
  )
}
