import { Outlet, NavLink, useNavigate } from "react-router-dom"
import { useAuth } from "../context/AuthContext"
import Footer from "./Footer"
const nav = [
  { to: "/feed",      label: "Live Feed",  icon: "⚡" },
  { to: "/analytics", label: "Analytics",  icon: "📊" },
  { to: "/keys",      label: "API Keys",   icon: "🔑" },
  { to: "/docs",      label: "Docs",       icon: "📄" },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => { logout(); navigate("/") }

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 bg-slate border-r border-steel/20 flex flex-col shrink-0">
        <div className="px-5 py-5 border-b border-steel/20">
          <span className="font-mono font-semibold text-blue text-sm tracking-widest">THREATSCORE</span>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {nav.map(({ to, label, icon }) => (
            <NavLink
              key={to} to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? "bg-blue/15 text-blue font-medium"
                    : "text-steel hover:text-offwhite hover:bg-white/5"
                }`
              }
            >
              <span>{icon}</span>{label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-4 border-t border-steel/20">
          <p className="text-xs text-steel truncate mb-2">{user}</p>
          <button onClick={handleLogout} className="text-xs text-steel hover:text-crimson transition-colors">
            Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto bg-navy">
        <Outlet />
        <main className="flex-1 overflow-y-auto bg-navy flex flex-col">
  <div className="flex-1">
    <Outlet />
  </div>
  <Footer />
</main>
      </main>
    </div>
  )
}
