import { createContext, useContext, useState } from "react"
import axios from "axios"

const API = import.meta.env.VITE_API_URL || "http://localhost:8000"

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [token, setToken] = useState(null)
  const [user, setUser]   = useState(null)

  const login = async (email, password) => {
    const res = await axios.post(`${API}/auth/login`, { email, password })
    setToken(res.data.token)
    setUser(email)
    return res.data.token
  }

  const register = async (email, password) => {
    await axios.post(`${API}/auth/register`, { email, password })
  }

  const logout = () => { setToken(null); setUser(null) }

  const authHeader = () => ({ Authorization: `Bearer ${token}` })

  return (
    <AuthContext.Provider value={{ token, user, login, register, logout, authHeader, API }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
