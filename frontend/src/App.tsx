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
import NotFound from './pages/NotFound'
import { ServerError, Forbidden } from './pages/errors'

const { Content } = Layout

function AppContent() {
  const { isAuthenticated, isLoading, mustChangePassword } = useAuth()

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" tip="Loading..." />
      </div>
    )
  }

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  // If user must change password, show only the password change screen
  if (mustChangePassword) {
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
            <Route path="/" element={<Dashboard />} />
            <Route path="/repositories" element={<Repositories />} />
            <Route path="/repositories/:key" element={<RepositoryDetail />} />
            <Route path="/artifacts" element={<Artifacts />} />
            <Route path="/packages" element={<Packages />} />
            <Route path="/builds" element={<Builds />} />
            <Route path="/setup" element={<SetupWizards />} />
            <Route path="/edge-nodes" element={<EdgeNodes />} />
            <Route path="/backups" element={<Backups />} />
            <Route path="/plugins" element={<Plugins />} />
            <Route path="/users" element={<Users />} />
            <Route path="/groups" element={<Groups />} />
            <Route path="/permissions" element={<Permissions />} />
            <Route path="/migration" element={<Migration />} />
            <Route path="/webhooks" element={<Webhooks />} />
            <Route path="/security" element={<SecurityDashboard />} />
            <Route path="/security/scans" element={<SecurityScans />} />
            <Route path="/security/scans/:id" element={<SecurityScanDetail />} />
            <Route path="/security/policies" element={<SecurityPolicies />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/search" element={<Search />} />
            <Route path="/login" element={<Navigate to="/" replace />} />
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
