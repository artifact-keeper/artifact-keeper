import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ConfigProvider, Layout, Spin } from 'antd'
import { useAuth, ThemeProvider, useTheme } from './contexts'
import { antdTheme, antdDarkTheme } from './styles/theme'
import ErrorBoundary from './components/ErrorBoundary'
import { AppShell } from './components/layout/AppShell'
import AppHeader from './components/layout/Header'
import AppSidebar from './components/layout/Sidebar'
import Dashboard from './pages/Dashboard'
import Repositories from './pages/Repositories'
import RepositoryDetail from './pages/RepositoryDetail'
import Artifacts from './pages/Artifacts'
import EdgeNodes from './pages/EdgeNodes'
import Backups from './pages/Backups'
import Plugins from './pages/Plugins'
import Users from './pages/Users'
import Settings from './pages/Settings'
import Login from './pages/Login'
import ChangePassword from './pages/ChangePassword'
import Profile from './pages/Profile'
import Search from './pages/Search'
import Groups from './pages/admin/Groups'
import Permissions from './pages/admin/Permissions'
import Migration from './pages/admin/Migration'
import Packages from './pages/Packages'
import Builds from './pages/Builds'
import SetupWizards from './pages/SetupWizards'
import Webhooks from './pages/Webhooks'
import SecurityDashboard from './pages/SecurityDashboard'
import SecurityScans from './pages/SecurityScans'
import SecurityScanDetail from './pages/SecurityScanDetail'
import SecurityPolicies from './pages/SecurityPolicies'
import ReplicationDashboard from './pages/ReplicationDashboard'
import NotFound from './pages/NotFound'
import { ServerError, Forbidden } from './pages/errors'

const { Content } = Layout

function DemoBanner() {
  const [demoMode, setDemoMode] = useState(false)

  useEffect(() => {
    fetch('/health')
      .then(res => res.json())
      .then(data => setDemoMode(data.demo_mode === true))
      .catch(() => {})
  }, [])

  if (!demoMode) return null
  return (
    <div style={{
      background: '#fffbe6',
      borderBottom: '1px solid #ffe58f',
      padding: '8px 16px',
      textAlign: 'center',
      fontSize: 14,
      color: '#614700',
      position: 'sticky',
      top: 0,
      zIndex: 1100,
    }}>
      This is a read-only demo — logged in as admin.{' '}
      <a href="https://artifactkeeper.com" style={{ fontWeight: 600 }}>
        Deploy your own instance &rarr;
      </a>
    </div>
  )
}

/** Wrapper that redirects to /login when the user is not authenticated */
function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

/** Wrapper that redirects to /login when the user is not an admin */
function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, user } = useAuth()
  if (!isAuthenticated) return <Navigate to="/login" replace />
  if (!user?.is_admin) return <Navigate to="/error/403" replace />
  return <>{children}</>
}

function AppContent() {
  const { isAuthenticated, isLoading, mustChangePassword } = useAuth()

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" tip="Loading..." />
      </div>
    )
  }

  // If user must change password, show only the password change screen
  if (isAuthenticated && mustChangePassword) {
    return (
      <Routes>
        <Route path="*" element={<ChangePassword />} />
      </Routes>
    )
  }

  return (
    <AppShell>
      <AppSidebar />
      <Layout>
        <AppHeader />
        <Content style={{ margin: '24px 16px', padding: 24, background: '#fff' }}>
          <Routes>
            {/* Public routes — anyone can browse */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/repositories" element={<Repositories />} />
            <Route path="/repositories/:key" element={<RepositoryDetail />} />
            <Route path="/repositories/:key/artifacts/:artifactId" element={<RepositoryDetail />} />
            <Route path="/artifacts" element={<Artifacts />} />
            <Route path="/packages" element={<Packages />} />
            <Route path="/builds" element={<Builds />} />
            <Route path="/search" element={<Search />} />
            <Route path="/login" element={isAuthenticated ? <Navigate to="/" replace /> : <Login />} />

            {/* Authenticated user routes */}
            <Route path="/setup" element={<RequireAuth><SetupWizards /></RequireAuth>} />
            <Route path="/profile" element={<RequireAuth><Profile /></RequireAuth>} />
            <Route path="/edge-nodes" element={<RequireAuth><EdgeNodes /></RequireAuth>} />
            <Route path="/replication" element={<RequireAuth><ReplicationDashboard /></RequireAuth>} />
            <Route path="/plugins" element={<RequireAuth><Plugins /></RequireAuth>} />
            <Route path="/webhooks" element={<RequireAuth><Webhooks /></RequireAuth>} />

            {/* Admin-only routes */}
            <Route path="/security" element={<RequireAdmin><SecurityDashboard /></RequireAdmin>} />
            <Route path="/security/scans" element={<RequireAdmin><SecurityScans /></RequireAdmin>} />
            <Route path="/security/scans/:id" element={<RequireAdmin><SecurityScanDetail /></RequireAdmin>} />
            <Route path="/security/policies" element={<RequireAdmin><SecurityPolicies /></RequireAdmin>} />
            <Route path="/backups" element={<RequireAdmin><Backups /></RequireAdmin>} />
            <Route path="/users" element={<RequireAdmin><Users /></RequireAdmin>} />
            <Route path="/groups" element={<RequireAdmin><Groups /></RequireAdmin>} />
            <Route path="/permissions" element={<RequireAdmin><Permissions /></RequireAdmin>} />
            <Route path="/migration" element={<RequireAdmin><Migration /></RequireAdmin>} />
            <Route path="/settings" element={<RequireAdmin><Settings /></RequireAdmin>} />

            <Route path="/error/500" element={<ServerError />} />
            <Route path="/error/403" element={<Forbidden />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Content>
      </Layout>
    </AppShell>
  )
}

function ThemedApp() {
  const { mode } = useTheme()
  const theme = mode === 'dark' ? antdDarkTheme : antdTheme

  return (
    <ConfigProvider theme={theme}>
      <BrowserRouter>
        <DemoBanner />
        <AppContent />
      </BrowserRouter>
    </ConfigProvider>
  )
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <ThemedApp />
      </ThemeProvider>
    </ErrorBoundary>
  )
}

export default App
