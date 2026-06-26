const snippets = {
  node: `const response = await fetch("https://threatscore.onrender.com/api/score", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "ts_your_key_here"
  },
  body: JSON.stringify({
    srcip:   req.ip,
    sport:   req.socket.remotePort,
    proto:   "tcp",
    service: "http",
    sbytes:  parseInt(req.headers["content-length"] || 0),
    dbytes:  0,
    dur:     responseTime,
    sttl:    64
  })
})
const { threat_score, verdict, flags, recommendation } = await response.json()
if (recommendation === "block") return res.status(403).json({ error: "Blocked" })`,

  python: `import httpx

resp = httpx.post(
    "https://threatscore.onrender.com/api/score",
    headers={"X-API-Key": "ts_your_key_here"},
    json={
        "srcip":   request.client.host,
        "proto":   "tcp",
        "service": "http",
        "sbytes":  int(request.headers.get("content-length", 0)),
        "dbytes":  0,
        "dur":     0.3,
        "sttl":    64,
    }
)
data = resp.json()
if data["recommendation"] == "block":
    raise HTTPException(status_code=403, detail="Blocked by ThreatScore")`,

  curl: `curl -X POST https://threatscore.onrender.com/api/score \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ts_your_key_here" \\
  -d '{
    "srcip": "1.2.3.4",
    "proto": "tcp",
    "service": "http",
    "sbytes": 4800,
    "dbytes": 200,
    "dur": 0.4,
    "sttl": 64
  }'`,

  response: `{
  "threat_score": 82,
  "verdict": "CRITICAL",
  "flags": [
    "TTL value (32) consistent with known attack fingerprint",
    "Byte ratio (src/dst) anomalous — possible data exfiltration",
    "High connection count from this source to service — possible scan"
  ],
  "closest_attack_profile": "Reconnaissance",
  "confidence": 0.79,
  "recommendation": "block"
}`,
}

const fields = [
  ["srcip",   "string", "Source IP address", "0.0.0.0"],
  ["sport",   "int",    "Source port number", "0"],
  ["proto",   "string", "Protocol: tcp / udp / icmp", "tcp"],
  ["service", "string", "Service: http / ftp / ssh / dns / -", "-"],
  ["sbytes",  "int",    "Bytes sent by source", "0"],
  ["dbytes",  "int",    "Bytes sent by destination", "0"],
  ["dur",     "float",  "Connection duration in seconds", "0.0"],
  ["sttl",    "int",    "IP time-to-live value", "64"],
  ["sinpkt",  "float",  "Source inter-packet arrival time (ms)", "0.0"],
]

function CodeBlock({ code, lang }) {
  const copy = () => navigator.clipboard.writeText(code)
  return (
    <div className="bg-navy rounded-lg border border-steel/20 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-steel/20 bg-slate/40">
        <span className="text-steel text-xs font-mono">{lang}</span>
        <button onClick={copy} className="text-xs text-steel hover:text-blue transition-colors">Copy</button>
      </div>
      <pre className="p-4 text-xs font-mono text-offwhite/80 overflow-x-auto leading-relaxed">{code}</pre>
    </div>
  )
}

export default function Docs() {
  return (
    <div className="p-8 max-w-3xl">
      <h1 className="text-xl font-semibold text-offwhite mb-1">Integration Docs</h1>
      <p className="text-steel text-sm mb-10">Everything you need to add ThreatScore to your backend in minutes.</p>

      {/* Endpoint */}
      <section className="mb-10">
        <h2 className="text-sm font-mono text-blue uppercase tracking-widest mb-4">Endpoint</h2>
        <div className="card font-mono text-sm">
          <span className="text-emerald-400">POST</span>
          <span className="text-offwhite ml-3">https://threatscore.onrender.com/api/score</span>
        </div>
        <p className="text-steel text-xs mt-2">Requires header: <code className="text-offwhite">X-API-Key: ts_your_key</code></p>
      </section>

      {/* Request fields */}
      <section className="mb-10">
        <h2 className="text-sm font-mono text-blue uppercase tracking-widest mb-4">Request Fields</h2>
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-steel text-xs border-b border-steel/20 bg-navy/40">
                <th className="text-left px-4 py-3">Field</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">Description</th>
                <th className="text-left px-4 py-3">Default</th>
              </tr>
            </thead>
            <tbody>
              {fields.map(([f, t, d, def]) => (
                <tr key={f} className="border-b border-steel/10 last:border-0">
                  <td className="px-4 py-3 font-mono text-blue text-xs">{f}</td>
                  <td className="px-4 py-3 text-steel text-xs">{t}</td>
                  <td className="px-4 py-3 text-offwhite/70 text-xs">{d}</td>
                  <td className="px-4 py-3 font-mono text-steel text-xs">{def}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Response */}
      <section className="mb-10">
        <h2 className="text-sm font-mono text-blue uppercase tracking-widest mb-4">Response</h2>
        <CodeBlock code={snippets.response} lang="json" />
        <div className="mt-3 space-y-1">
          {[
            ["0–30",  "SAFE",       "allow",     "text-emerald-400"],
            ["31–60", "SUSPICIOUS", "monitor",   "text-amber"],
            ["61–80", "HIGH RISK",  "challenge", "text-orange-400"],
            ["81–100","CRITICAL",   "block",     "text-crimson"],
          ].map(([range, verdict, rec, color]) => (
            <div key={range} className="flex items-center gap-4 text-xs font-mono">
              <span className="text-steel w-12">{range}</span>
              <span className={`w-20 ${color}`}>{verdict}</span>
              <span className="text-steel">{rec}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Code examples */}
      <section className="mb-10">
        <h2 className="text-sm font-mono text-blue uppercase tracking-widest mb-4">Node.js / Express</h2>
        <CodeBlock code={snippets.node} lang="javascript" />
      </section>

      <section className="mb-10">
        <h2 className="text-sm font-mono text-blue uppercase tracking-widest mb-4">Python / FastAPI</h2>
        <CodeBlock code={snippets.python} lang="python" />
      </section>

      <section>
        <h2 className="text-sm font-mono text-blue uppercase tracking-widest mb-4">curl</h2>
        <CodeBlock code={snippets.curl} lang="bash" />
      </section>
    </div>
  )
}
