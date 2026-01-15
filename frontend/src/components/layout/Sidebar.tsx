import { Layout, Menu } from 'antd'
import { Link, useLocation } from 'react-router-dom'
import {
  DashboardOutlined,
  DatabaseOutlined,
  UserOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import type { MenuProps } from 'antd'
import { useAuth } from '../../contexts'

const { Sider } = Layout

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
    ...(user?.is_admin ? [
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
    <Sider width={200} theme="dark">
      <div style={{ height: 32, margin: 16, color: '#fff', fontSize: 18, fontWeight: 'bold', textAlign: 'center' }}>
        Artifact Keeper
      </div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[location.pathname]}
        items={items}
      />
    </Sider>
  )
}

export default AppSidebar
