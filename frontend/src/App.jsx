import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { AuthProvider, useAuth } from "./context/AuthContext"
import Landing  from "./pages/Landing"
import Login    from "./pages/Login"
import Register from "./pages/Register"
import ApiKeys  from "./pages/ApiKeys"
import Feed     from "./pages/Feed"
import Analytics from "./pages/Analytics"
import Docs     from "./pages/Docs"
import Layout   from "./components/Layout"

function Protected({ children }) {
  const { token } = useAuth()
  return token ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/"         element={<Landing />} />
          <Route path="/login"    element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route element={<Protected><Layout /></Protected>}>
            <Route path="/keys"      element={<ApiKeys />} />
            <Route path="/feed"      element={<Feed />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/docs"      element={<Docs />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
