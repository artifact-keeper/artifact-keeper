import { Layout, Menu } from 'antd'
import { Link, useLocation } from 'react-router-dom'
import {
  DashboardOutlined,
  DatabaseOutlined,
  UserOutlined,
  SettingOutlined,
  CloudServerOutlined,
  AppstoreOutlined,
  SaveOutlined,
} from '@ant-design/icons'
import type { MenuProps } from 'antd'

const { Sider } = Layout

const AppSidebar = () => {
  const location = useLocation()

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
      key: '/users',
      icon: <UserOutlined />,
      label: <Link to="/users">Users</Link>,
    },
    {
      key: '/edge-nodes',
      icon: <CloudServerOutlined />,
      label: <Link to="/edge-nodes">Edge Nodes</Link>,
    },
    {
      key: '/backups',
      icon: <SaveOutlined />,
      label: <Link to="/backups">Backups</Link>,
    },
    {
      key: '/plugins',
      icon: <AppstoreOutlined />,
      label: <Link to="/plugins">Plugins</Link>,
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: <Link to="/settings">Settings</Link>,
    },
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
