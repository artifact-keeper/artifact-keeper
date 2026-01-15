import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from 'antd'
import AppHeader from './components/layout/Header'
import AppSidebar from './components/layout/Sidebar'
import Dashboard from './pages/Dashboard'
import Repositories from './pages/Repositories'
import Users from './pages/Users'
import Settings from './pages/Settings'
import Login from './pages/Login'

const { Content } = Layout

function App() {
  // TODO: Implement proper auth state management
  const isAuthenticated = true

  if (!isAuthenticated) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    )
  }

  return (
    <BrowserRouter>
      <Layout style={{ minHeight: '100vh' }}>
        <AppSidebar />
        <Layout>
          <AppHeader />
          <Content style={{ margin: '24px 16px', padding: 24, background: '#fff' }}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/repositories" element={<Repositories />} />
              <Route path="/users" element={<Users />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/login" element={<Navigate to="/" replace />} />
            </Routes>
          </Content>
        </Layout>
      </Layout>
    </BrowserRouter>
  )
}

export default App
