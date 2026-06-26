import { useState, useEffect } from "react"
import axios from "axios"
import { useAuth } from "../context/AuthContext"
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  BarChart, Bar
} from "recharts"

const PIE_COLORS = {
  "SAFE":       "#34d399",
  "SUSPICIOUS": "#F77F00",
  "HIGH RISK":  "#fb923c",
  "CRITICAL":   "#D90429",
}

function StatCard({ label, value, sub, color }) {
  return (
    <div className="card">
      <p className="text-steel text-xs mb-1">{label}</p>
      <p className={`text-3xl font-bold font-mono ${color || "text-offwhite"}`}>{value}</p>
      {sub && <p className="text-steel text-xs mt-1">{sub}</p>}
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate border border-steel/30 rounded-md px-3 py-2 text-xs">
      <p className="text-steel mb-1">{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

export default function Analytics() {
  const { authHeader, API } = useAuth()
  const [stats, setStats]   = useState(null)
  const [threats, setThreats] = useState([])

  useEffect(() => {
    const load = async () => {
      const [s, t] = await Promise.all([
        axios.get(`${API}/dashboard/stats`,   { headers: authHeader() }),
        axios.get(`${API}/dashboard/threats`, { headers: authHeader() }),
      ])
      setStats(s.data)
      setThreats(t.data)
    }
    load()
  }, [])

  if (!stats) return (
    <div className="p-8 text-steel text-sm">Loading analytics…</div>
  )

  const verdictData = Object.entries(stats.verdicts || {}).map(([name, value]) => ({ name, value }))
  const criticalCount = stats.verdicts?.["CRITICAL"] || 0

  return (
    <div className="p-8 max-w-5xl">
      <h1 className="text-xl font-semibold text-offwhite mb-1">Analytics</h1>
      <p className="text-steel text-sm mb-8">Aggregated across all your API keys</p>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        <StatCard label="Total Requests" value={stats.total.toLocaleString()} />
        <StatCard label="Avg Threat Score" value={stats.avg_score}
          color={stats.avg_score > 60 ? "text-crimson" : stats.avg_score > 30 ? "text-amber" : "text-emerald-400"} />
        <StatCard label="Critical Alerts" value={criticalCount}
          color={criticalCount > 0 ? "text-crimson" : "text-offwhite"}
          sub={criticalCount > 0 ? "Immediate review recommended" : "None detected"} />
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Verdict breakdown pie */}
        <div className="card">
          <h2 className="text-sm font-medium text-offwhite mb-4">Verdict Breakdown</h2>
          {verdictData.length === 0 ? (
            <p className="text-steel text-xs">No data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={verdictData} dataKey="value" nameKey="name"
                  cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                  labelLine={false}
                >
                  {verdictData.map(entry => (
                    <Cell key={entry.name} fill={PIE_COLORS[entry.name] || "#5C6B73"} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Top threat IPs bar */}
        <div className="card">
          <h2 className="text-sm font-medium text-offwhite mb-4">Top Threat Sources</h2>
          {threats.length === 0 ? (
            <p className="text-steel text-xs">No data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={threats} layout="vertical"
                margin={{ left: 10, right: 16, top: 0, bottom: 0 }}>
                <XAxis type="number" tick={{ fill: "#5C6B73", fontSize: 11 }} />
                <YAxis type="category" dataKey="srcip" width={100}
                  tick={{ fill: "#5C6B73", fontSize: 10, fontFamily: "JetBrains Mono" }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="hits" name="Hits" fill="#3A86FF" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Avg score per IP */}
      {threats.length > 0 && (
        <div className="card">
          <h2 className="text-sm font-medium text-offwhite mb-4">Avg Threat Score by Source IP</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={threats} margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
              <XAxis dataKey="srcip"
                tick={{ fill: "#5C6B73", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <YAxis domain={[0, 100]} tick={{ fill: "#5C6B73", fontSize: 11 }} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="avg_score" name="Avg Score" radius={[3, 3, 0, 0]}
                fill="#D90429" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
