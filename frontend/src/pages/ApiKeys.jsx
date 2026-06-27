import { useState, useEffect } from "react"
import axios from "axios"
import { useAuth } from "../context/AuthContext"

export default function ApiKeys() {
  const { authHeader, API } = useAuth()
  const [keys, setKeys]     = useState([])
  const [label, setLabel]   = useState("")
  const [newKey, setNewKey] = useState(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied]   = useState(false)

  const fetchKeys = async () => {
    const res = await axios.get(`${API}/auth/apikey`, { headers: authHeader() })
    setKeys(res.data)
  }

  useEffect(() => { fetchKeys() }, [])

  const generate = async () => {
    if (!label.trim()) return
    setLoading(true)
    try {
      const res = await axios.post(`${API}/auth/apikey`, { label }, { headers: authHeader() })
      setNewKey(res.data.key)
      setLabel("")
      fetchKeys()
    } finally { setLoading(false) }
  }

  const revoke = async (id) => {
    await axios.delete(`${API}/auth/apikey/${id}`, { headers: authHeader() })
    fetchKeys()
  }

  const copy = () => {
    navigator.clipboard.writeText(newKey)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="p-8 max-w-3xl">
      <h1 className="text-xl font-semibold text-offwhite mb-1">API Keys</h1>
      <p className="text-steel text-sm mb-8">Keys are shown once at creation. Store them securely.</p>

      {/* Generate */}
      <div className="card mb-6">
        <h2 className="text-sm font-medium text-offwhite mb-3">Generate new key</h2>
        <div className="flex gap-3">
          <input className="input" placeholder="Key label (e.g. production)"
            value={label} onChange={e => setLabel(e.target.value)}
            onKeyDown={e => e.key === "Enter" && generate()} />
          <button onClick={generate} disabled={loading || !label.trim()} className="btn-primary whitespace-nowrap">
            {loading ? "Creating…" : "Generate"}
          </button>
        </div>
      </div>

      {/* New key reveal */}
      {newKey && (
        <div className="card border-blue/30 bg-blue/5 mb-6">
          <div className="flex items-start justify-between mb-2">
            <p className="text-sm font-medium text-blue">New key generated — copy it now</p>
            <button onClick={() => setNewKey(null)} className="text-steel hover:text-offwhite text-lg leading-none">×</button>
          </div>
          <div className="flex items-center gap-3 bg-navy rounded-md px-3 py-2">
            <code className="font-mono text-sm text-offwhite flex-1 break-all">{newKey}</code>
            <button onClick={copy} className="text-xs text-blue hover:text-offwhite transition-colors whitespace-nowrap">
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
        </div>
      )}

      {/* Keys table */}
      <div className="card">
        <h2 className="text-sm font-medium text-offwhite mb-4">Active keys</h2>
        {keys.length === 0 ? (
          <p className="text-steel text-sm">No active keys. Previously generated keys cannot be retrieved — generate a new one above.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-steel text-xs border-b border-steel/20">
                <th className="text-left pb-2">Label</th>
                <th className="text-left pb-2">Created</th>
                <th className="text-right pb-2">Action</th>
              </tr>
            </thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id} className="border-b border-steel/10 last:border-0">
                  <td className="py-3 font-mono text-offwhite">{k.label}</td>
                  <td className="py-3 text-steel">{new Date(k.created_at).toLocaleDateString()}</td>
                  <td className="py-3 text-right">
                    <button onClick={() => revoke(k.id)}
                      className="text-xs text-steel hover:text-crimson transition-colors">
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
