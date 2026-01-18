import { Layout, Menu, Typography, Button, Drawer } from 'antd'
import { Link, useLocation } from 'react-router-dom'
import {
  DashboardOutlined,
  DatabaseOutlined,
  FileOutlined,
  AppstoreOutlined,
  BuildOutlined,
  ToolOutlined,
  CloudServerOutlined,
  CloudUploadOutlined,
  UserOutlined,
  TeamOutlined,
  LockOutlined,
  SettingOutlined,
  ApiOutlined,
  SwapOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
} from '@ant-design/icons'
import type { MenuProps } from 'antd'
import { useAuth } from '../../contexts'
import { useAppShell } from './AppShell'
import { colors, sidebar, animation } from '../../styles/tokens'

const { Sider } = Layout
const { Text } = Typography

const APP_VERSION = '1.0.0'

const AppSidebar = () => {
  const location = useLocation()
  const { user } = useAuth()
  const {
    collapsed,
    toggleCollapsed,
    sidebarVisible,
    setSidebarVisible,
    isMobile
  } = useAppShell()

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
    {
      key: '/packages',
      icon: <AppstoreOutlined />,
      label: <Link to="/packages">Packages</Link>,
    },
    {
      key: '/builds',
      icon: <BuildOutlined />,
      label: <Link to="/builds">Builds</Link>,
    },
    {
      key: '/setup',
      icon: <ToolOutlined />,
      label: <Link to="/setup">Set Me Up</Link>,
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
        key: '/groups',
        icon: <TeamOutlined />,
        label: <Link to="/groups">Groups</Link>,
      },
      {
        key: '/permissions',
        icon: <LockOutlined />,
        label: <Link to="/permissions">Permissions</Link>,
      },
      {
        key: '/migration',
        icon: <SwapOutlined />,
        label: <Link to="/migration">Migration</Link>,
      },
      {
        key: '/settings',
        icon: <SettingOutlined />,
        label: <Link to="/settings">Settings</Link>,
      },
    ] : []),
  ]

  const handleMenuClick = () => {
    if (isMobile) {
      setSidebarVisible(false)
    }
  }

  const siderStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    background: colors.siderBg,
    transition: `all ${animation.slow} ease`,
    overflow: 'hidden',
  }

  const logoStyle: React.CSSProperties = {
    height: 32,
    margin: 16,
    color: colors.siderText,
    fontSize: collapsed ? 14 : 18,
    fontWeight: 'bold',
    textAlign: 'center',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    transition: `all ${animation.normal} ease`,
  }

  const toggleButtonStyle: React.CSSProperties = {
    position: 'absolute',
    top: 16,
    right: collapsed ? 'calc(50% - 16px)' : 8,
    zIndex: 1,
    color: colors.siderTextSecondary,
    transition: `all ${animation.normal} ease`,
  }

  const versionStyle: React.CSSProperties = {
    padding: '12px 16px',
    borderTop: `1px solid ${colors.siderBorder}`,
    textAlign: 'center',
  }

  const sidebarContent = (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', position: 'relative' }}>
      {!isMobile && (
        <Button
          type="text"
          icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
          onClick={toggleCollapsed}
          style={toggleButtonStyle}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        />
      )}
      <div style={logoStyle}>
        {collapsed ? 'AK' : 'Artifact Keeper'}
      </div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[location.pathname]}
        items={items}
        style={{ flex: 1, background: colors.siderBg }}
        onClick={handleMenuClick}
        inlineCollapsed={collapsed && !isMobile}
      />
      {!collapsed && (
        <div style={versionStyle}>
          <Text style={{ color: colors.siderTextMuted, fontSize: 12 }}>
            v{APP_VERSION}
          </Text>
        </div>
      )}
    </div>
  )

  // Mobile: Use Drawer for sidebar
  if (isMobile) {
    return (
      <Drawer
        placement="left"
        open={sidebarVisible}
        onClose={() => setSidebarVisible(false)}
        width={sidebar.width}
        styles={{
          body: {
            padding: 0,
            background: colors.siderBg,
            display: 'flex',
            flexDirection: 'column',
            height: '100%',
          },
          header: {
            display: 'none',
          },
        }}
      >
        {sidebarContent}
      </Drawer>
    )
  }

  // Desktop/Tablet: Use Sider
  return (
    <Sider
      collapsible
      collapsed={collapsed}
      onCollapse={toggleCollapsed}
      trigger={null}
      width={sidebar.width}
      collapsedWidth={sidebar.collapsedWidth}
      theme="dark"
      style={siderStyle}
    >
      {sidebarContent}
    </Sider>
  )
}

export default AppSidebar
