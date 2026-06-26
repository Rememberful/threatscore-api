import { useState, useEffect, useRef } from "react"
import axios from "axios"
import { useAuth } from "../context/AuthContext"

const VERDICT_STYLES = {
  "SAFE":       "verdict-safe",
  "SUSPICIOUS": "verdict-suspicious",
  "HIGH RISK":  "verdict-high",
  "CRITICAL":   "verdict-critical",
}

const VERDICT_ROW = {
  "SAFE":       "border-l-2 border-emerald-400/30",
  "SUSPICIOUS": "border-l-2 border-amber/30",
  "HIGH RISK":  "border-l-2 border-orange-400/30",
  "CRITICAL":   "border-l-2 border-crimson/30",
}

function VerdictBadge({ verdict }) {
  const cls = VERDICT_STYLES[verdict] || "text-steel bg-steel/10"
  return (
    <span className={`inline-block text-xs font-mono font-medium px-2 py-0.5 rounded ${cls}`}>
      {verdict}
    </span>
  )
}

export default function Feed() {
  const { authHeader, API } = useAuth()
  const [logs, setLogs]     = useState([])
  const [expanded, setExpanded] = useState(null)
  const intervalRef = useRef(null)

  const fetchFeed = async () => {
    try {
      const res = await axios.get(`${API}/dashboard/feed`, { headers: authHeader() })
      setLogs(res.data)
    } catch {}
  }

  useEffect(() => {
    fetchFeed()
    intervalRef.current = setInterval(fetchFeed, 5000)
    return () => clearInterval(intervalRef.current)
  }, [])

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-offwhite mb-1">Live Threat Feed</h1>
          <p className="text-steel text-sm">Refreshes every 5 seconds</p>
        </div>
        <span className="flex items-center gap-2 text-xs text-emerald-400 font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          LIVE
        </span>
      </div>

      {logs.length === 0 ? (
        <div className="card text-center py-16">
          <p className="text-steel text-sm">No requests scored yet.</p>
          <p className="text-steel/60 text-xs mt-1">Send a request to POST /api/score to see it here.</p>
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-steel text-xs border-b border-steel/20 bg-navy/40">
                <th className="text-left px-4 py-3">Time</th>
                <th className="text-left px-4 py-3">Source IP</th>
                <th className="text-left px-4 py-3">Proto</th>
                <th className="text-left px-4 py-3">Service</th>
                <th className="text-left px-4 py-3">Score</th>
                <th className="text-left px-4 py-3">Verdict</th>
                <th className="text-left px-4 py-3">Profile</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <>
                  <tr
                    key={log.id}
                    onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                    className={`border-b border-steel/10 cursor-pointer hover:bg-white/5 transition-colors ${VERDICT_ROW[log.verdict] || ""}`}
                  >
                    <td className="px-4 py-3 font-mono text-steel text-xs">
                      {new Date(log.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 font-mono text-offwhite">{log.srcip}</td>
                    <td className="px-4 py-3 text-steel uppercase text-xs">{log.proto}</td>
                    <td className="px-4 py-3 text-steel text-xs">{log.service}</td>
                    <td className="px-4 py-3">
                      <span className="font-mono font-semibold text-offwhite">{log.threat_score}</span>
                      <span className="text-steel text-xs">/100</span>
                    </td>
                    <td className="px-4 py-3"><VerdictBadge verdict={log.verdict} /></td>
                    <td className="px-4 py-3 text-steel text-xs">{log.closest_attack_profile}</td>
                  </tr>
                  {expanded === log.id && (
                    <tr key={`${log.id}-exp`} className="bg-navy/60">
                      <td colSpan={7} className="px-6 py-4">
                        <p className="text-xs text-steel font-mono uppercase mb-2">Flags</p>
                        <ul className="space-y-1">
                          {(log.flags || []).map((f, i) => (
                            <li key={i} className="text-xs text-offwhite/80 flex items-start gap-2">
                              <span className="text-amber mt-0.5">▸</span>{f}
                            </li>
                          ))}
                        </ul>
                        <p className="text-xs text-steel mt-3">
                          Recommendation: <span className="text-offwhite font-medium">{log.recommendation}</span>
                        </p>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
