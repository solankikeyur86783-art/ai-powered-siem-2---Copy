import { createContext, useContext, useState, useEffect } from 'react'
import { authApi } from '../services/api.js'

const AuthContext = createContext()

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // Restore session on mount
  useEffect(() => {
    const token = localStorage.getItem('siem-token')
    const saved = localStorage.getItem('siem-user')
    if (token && saved) {
      try {
        setUser(JSON.parse(saved))
      } catch { /* ignore */ }
      // Verify token is still valid
      authApi.me()
        .then(data => {
          if (data?.user) setUser(data.user)
        })
        .catch(() => {
          localStorage.removeItem('siem-token')
          localStorage.removeItem('siem-user')
          setUser(null)
        })
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [])

  const login = async (username, password) => {
    try {
      const data = await authApi.login(username, password)
      if (data.token && data.user) {
        localStorage.setItem('siem-token', data.token)
        localStorage.setItem('siem-user', JSON.stringify(data.user))
        setUser(data.user)
        return { success: true }
      }
      return { success: false, error: 'Invalid response from server' }
    } catch (err) {
      return { success: false, error: err.message }
    }
  }

  const logout = () => {
    setUser(null)
    localStorage.removeItem('siem-token')
    localStorage.removeItem('siem-user')
  }

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
