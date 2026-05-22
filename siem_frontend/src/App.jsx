import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/AuthContext.jsx'
import { ThemeProvider } from './hooks/ThemeContext.jsx'
import Layout from './components/Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import AlertsPage from './pages/AlertsPage.jsx'
import LogsPage from './pages/LogsPage.jsx'
import AgentsPage from './pages/AgentsPage.jsx'
import ThreatHuntPage from './pages/ThreatHuntPage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import ThreatMapPage from './pages/ThreatMapPage.jsx'
import NotificationsPage from './pages/NotificationsPage.jsx'
import ReportsPage from './pages/ReportsPage.jsx'
import RulesPage from './pages/RulesPage.jsx'
import AIInsightsPage from './pages/AIInsightsPage.jsx'
import HoneypotPage from './pages/HoneypotPage.jsx'
import ForensicsPage from './pages/ForensicsPage.jsx'
import TorDetectionPage from './pages/TorDetectionPage.jsx'

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', color: 'var(--t3)', fontFamily: 'Manrope, sans-serif', background: 'var(--bg0)' }}>
      Authenticating…
    </div>
  )
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return children
}

function AppRoutes() {
  const { isAuthenticated } = useAuth()
  return (
    <Routes>
      <Route path="/login" element={isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="agents" element={<AgentsPage />} />
        <Route path="hunt" element={<ThreatHuntPage />} />
        <Route path="threat-map" element={<ThreatMapPage />} />
        <Route path="ai-insights" element={<AIInsightsPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="honeypot" element={<HoneypotPage />} />
        <Route path="forensics" element={<ForensicsPage />} />
        <Route path="tor" element={<TorDetectionPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </ThemeProvider>
  )
}
