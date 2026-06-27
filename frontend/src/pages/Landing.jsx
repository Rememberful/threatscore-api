import { Link } from "react-router-dom"
import Footer from "../components/Footer"

const snippet = `const res = await fetch("https://threatscore.onrender.com/api/score", {
  method: "POST",
  headers: { "X-API-Key": "ts_your_key_here" },
  body: JSON.stringify({
    srcip: req.ip, proto: "tcp",
    service: "http", sbytes: 4800,
    dbytes: 200, dur: 0.4, sttl: 64
  })
})
const { threat_score, verdict, flags } = await res.json()
// threat_score: 82 | verdict: "HIGH RISK" | flags: [...]`

const features = [
  { icon: "⚡", title: "Single HTTP call", desc: "Drop into any stack — Node, Python, Go, curl. No SDK required." },
  { icon: "🧠", title: "ML-powered scoring", desc: "LightGBM trained on 80K+ UNSW-NB15 network flows. F1 0.93, AUC 0.98." },
  { icon: "🔍", title: "SHAP explainability", desc: "Every score ships with 3 human-readable flags explaining why." },
  { icon: "🗂️", title: "Attack profiling", desc: "Identifies closest attack category: Exploits, DoS, Recon, and 7 more." },
]

export default function Landing() {
  return (
    <div className="min-h-screen bg-navy text-offwhite">
      {/* Nav */}
      <header className="flex items-center justify-between px-8 py-5 border-b border-steel/20">
        <span className="font-mono font-semibold text-blue tracking-widest text-sm">THREATSCORE</span>
        <div className="flex gap-3">
          <Link to="/login"    className="btn-ghost">Sign in</Link>
          <Link to="/register" className="btn-primary">Get started free</Link>
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-5xl mx-auto px-8 pt-20 pb-16">
        <div className="inline-flex items-center gap-2 bg-blue/10 border border-blue/20 rounded-full px-3 py-1 mb-6">
          <span className="w-2 h-2 rounded-full bg-blue animate-pulse"></span>
          <span className="text-blue text-xs font-mono">ML-powered threat intelligence API</span>
        </div>

        <h1 className="text-5xl font-bold leading-tight mb-5 tracking-tight">
          One API call.<br />
          <span className="text-blue">Any project.</span><br />
          Instant threat score.
        </h1>
        <p className="text-steel text-lg max-w-xl mb-8 leading-relaxed">
          Send basic request metadata — IP, bytes, protocol, duration.
          Get back a 0–100 threat score, verdict, SHAP-derived flags, and the closest attack profile.
        </p>

        <div className="flex gap-3 mb-14">
          <Link to="/register" className="btn-primary px-6 py-3 text-base">Get your API key</Link>
          <a href="#how" className="btn-ghost px-6 py-3 text-base">See how it works</a>
        </div>

        {/* Code block */}
        <div className="bg-slate rounded-xl border border-steel/20 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-steel/20 bg-navy/40">
            <span className="w-3 h-3 rounded-full bg-crimson/60"></span>
            <span className="w-3 h-3 rounded-full bg-amber/60"></span>
            <span className="w-3 h-3 rounded-full bg-emerald-500/60"></span>
            <span className="text-steel text-xs font-mono ml-2">integration.js</span>
          </div>
          <pre className="p-5 text-sm font-mono text-offwhite/80 overflow-x-auto leading-relaxed">
            {snippet}
          </pre>
        </div>
      </section>

      {/* Features */}
      <section id="how" className="max-w-5xl mx-auto px-8 pb-20">
        <p className="text-steel text-xs font-mono tracking-widest uppercase mb-8">What you get</p>
        <div className="grid grid-cols-2 gap-4">
          {features.map(({ icon, title, desc }) => (
            <div key={title} className="card hover:border-steel/40 transition-colors">
              <div className="text-2xl mb-3">{icon}</div>
              <h3 className="font-semibold text-offwhite mb-1">{title}</h3>
              <p className="text-steel text-sm leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-steel/20 py-16 text-center">
        <h2 className="text-2xl font-bold mb-3">Start scoring traffic in 5 minutes.</h2>
        <p className="text-steel mb-6">Free tier. No credit card.</p>
        <Link to="/register" className="btn-primary px-8 py-3 text-base">Create free account</Link>
      </section>
      <Footer />
    </div>
  )
}
