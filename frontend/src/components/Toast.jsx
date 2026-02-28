import { CheckCircle, XCircle, Info } from 'lucide-react'

export default function ToastContainer({ toasts }) {
  return (
    <div className="toast-container">
      {toasts.map(({ id, msg, type }) => (
        <div key={id} className={`toast toast-${type}`}>
          {type === 'success' && <CheckCircle size={15} />}
          {type === 'error' && <XCircle size={15} />}
          {type === 'info' && <Info size={15} />}
          {msg}
        </div>
      ))}
    </div>
  )
}
