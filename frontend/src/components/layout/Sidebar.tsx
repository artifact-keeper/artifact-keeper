import { Layout, Menu, Typography } from 'antd'
import { Link, useLocation } from 'react-router-dom'
import {
  DashboardOutlined,
  DatabaseOutlined,
  FileOutlined,
  CloudServerOutlined,
  CloudUploadOutlined,
  UserOutlined,
  SettingOutlined,
  ApiOutlined,
} from '@ant-design/icons'
import type { MenuProps } from 'antd'
import { useAuth } from '../../contexts'

const { Sider } = Layout
const { Text } = Typography

const APP_VERSION = '1.0.0'

const AppSidebar = () => {
  const location = useLocation()
  const { user } = useAuth()

  const items: MenuProps['items'] = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: <Link to="/">Dashboard</Link>,
    },
    {
      key: '/repositories',
      icon: <DatabaseOutlined />,
      label: <Link to="/repositories">Repositories</Link>,
    },
    {
      key: '/artifacts',
      icon: <FileOutlined />,
      label: <Link to="/artifacts">Artifacts</Link>,
    },
    ...(user?.is_admin ? [
      {
        key: '/edge-nodes',
        icon: <CloudServerOutlined />,
        label: <Link to="/edge-nodes">Edge Nodes</Link>,
      },
      {
        key: '/backups',
        icon: <CloudUploadOutlined />,
        label: <Link to="/backups">Backups</Link>,
      },
      {
        key: '/plugins',
        icon: <ApiOutlined />,
        label: <Link to="/plugins">Plugins</Link>,
      },
      {
        key: '/users',
        icon: <UserOutlined />,
        label: <Link to="/users">Users</Link>,
      },
      {
        key: '/settings',
        icon: <SettingOutlined />,
        label: <Link to="/settings">Settings</Link>,
      },
    ] : []),
  ]

  return (
    <Sider
      width={200}
      theme="dark"
      style={{ display: 'flex', flexDirection: 'column' }}
    >
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ height: 32, margin: 16, color: '#fff', fontSize: 18, fontWeight: 'bold', textAlign: 'center' }}>
          Artifact Keeper
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={items}
          style={{ flex: 1 }}
        />
        <div style={{
          padding: '12px 16px',
          borderTop: '1px solid rgba(255,255,255,0.1)',
          textAlign: 'center'
        }}>
          <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>
            v{APP_VERSION}
          </Text>
        </div>
      </div>
    </Sider>
  )
}

export default AppSidebar
