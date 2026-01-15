import { Layout, Avatar, Dropdown, Space, message } from 'antd'
import { UserOutlined, LogoutOutlined } from '@ant-design/icons'
import type { MenuProps } from 'antd'
import { useAuth } from '../../contexts'

const { Header } = Layout

const AppHeader = () => {
  const { user, logout } = useAuth()

  const handleMenuClick: MenuProps['onClick'] = async ({ key }) => {
    if (key === 'logout') {
      try {
        await logout()
        message.success('Logged out successfully')
      } catch {
        message.error('Failed to logout')
      }
    }
  }

  const items: MenuProps['items'] = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: user?.email || 'Profile',
      disabled: true,
    },
    {
      type: 'divider',
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: 'Logout',
      danger: true,
    },
  ]

  return (
    <Header style={{ background: '#fff', padding: '0 24px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
      <Dropdown menu={{ items, onClick: handleMenuClick }} placement="bottomRight">
        <Space style={{ cursor: 'pointer' }}>
          <Avatar icon={<UserOutlined />} />
          <span>{user?.display_name || user?.username || 'User'}</span>
        </Space>
      </Dropdown>
    </Header>
  )
}

export default AppHeader
