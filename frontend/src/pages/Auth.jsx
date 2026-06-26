import { useState } from "react"
import { Link, useNavigate } from "react-router-dom"
import { useAuth } from "../context/AuthContext"

function AuthForm({ mode }) {
  const [email, setEmail]       = useState("")
  const [password, setPassword] = useState("")
  const [error, setError]       = useState("")
  const [loading, setLoading]   = useState(false)
  const { login, register }     = useAuth()
  const navigate                = useNavigate()

  const submit = async (e) => {
    e.preventDefault()
    setError(""); setLoading(true)
    try {
      if (mode === "register") {
        await register(email, password)
        await login(email, password)
      } else {
        await login(email, password)
      }
      navigate("/feed")
    } catch (err) {
      setError(err.response?.data?.detail || "Something went wrong")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-navy flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <Link to="/" className="font-mono font-semibold text-blue tracking-widest text-sm">THREATSCORE</Link>
          <h1 className="text-xl font-semibold text-offwhite mt-4">
            {mode === "login" ? "Sign in to your account" : "Create your account"}
          </h1>
        </div>

        <div className="card">
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="text-xs text-steel mb-1 block">Email</label>
              <input className="input" type="email" value={email}
                onChange={e => setEmail(e.target.value)} required autoFocus />
            </div>
            <div>
              <label className="text-xs text-steel mb-1 block">Password</label>
              <input className="input" type="password" value={password}
                onChange={e => setPassword(e.target.value)} required />
            </div>
            {error && <p className="text-crimson text-xs">{error}</p>}
            <button type="submit" disabled={loading} className="btn-primary w-full py-2.5">
              {loading ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
            </button>
          </form>
        </div>

        <p className="text-center text-steel text-sm mt-5">
          {mode === "login"
            ? <>No account? <Link to="/register" className="text-blue hover:underline">Sign up free</Link></>
            : <>Have an account? <Link to="/login" className="text-blue hover:underline">Sign in</Link></>
          }
        </p>
      </div>
    </div>
  )
}

export function Login()    { return <AuthForm mode="login" /> }
export function Register() { return <AuthForm mode="register" /> }
