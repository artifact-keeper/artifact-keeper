import { useState } from 'react'
import { Layout, Avatar, Dropdown, Space, message, Button, Modal, Typography, Divider } from 'antd'
import { UserOutlined, LogoutOutlined, QuestionCircleOutlined, GithubOutlined } from '@ant-design/icons'
import type { MenuProps } from 'antd'
import { useAuth } from '../../contexts'

const { Header } = Layout
const { Title, Text, Paragraph } = Typography

const APP_VERSION = '1.0.0'

const AppHeader = () => {
  const { user, logout } = useAuth()
  const [helpModalOpen, setHelpModalOpen] = useState(false)

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
    <>
      <Header style={{ background: '#fff', padding: '0 24px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 16 }}>
        <Button
          type="text"
          icon={<QuestionCircleOutlined />}
          onClick={() => setHelpModalOpen(true)}
        />
        <Dropdown menu={{ items, onClick: handleMenuClick }} placement="bottomRight">
          <Space style={{ cursor: 'pointer' }}>
            <Avatar icon={<UserOutlined />} />
            <span>{user?.display_name || user?.username || 'User'}</span>
          </Space>
        </Dropdown>
      </Header>

      <Modal
        title={
          <Space>
            <QuestionCircleOutlined />
            <span>About Artifact Keeper</span>
          </Space>
        }
        open={helpModalOpen}
        onCancel={() => setHelpModalOpen(false)}
        footer={[
          <Button key="close" type="primary" onClick={() => setHelpModalOpen(false)}>
            Close
          </Button>
        ]}
        width={500}
      >
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <Title level={3} style={{ margin: 0 }}>Artifact Keeper</Title>
          <Text type="secondary">Version {APP_VERSION}</Text>
        </div>

        <Paragraph>
          Artifact Keeper is an enterprise artifact registry for managing software packages
          across multiple formats including Maven, PyPI, NPM, Docker, Helm, and more.
        </Paragraph>

        <Divider />

        <Title level={5}>Supported Formats</Title>
        <Paragraph>
          <ul style={{ columns: 2, columnGap: 24 }}>
            <li>Maven (Java)</li>
            <li>PyPI (Python)</li>
            <li>NPM (Node.js)</li>
            <li>Docker (Containers)</li>
            <li>Helm (Kubernetes)</li>
            <li>RPM (Red Hat)</li>
            <li>Debian (Ubuntu)</li>
            <li>Go Modules</li>
            <li>NuGet (.NET)</li>
            <li>Cargo (Rust)</li>
            <li>Generic (Any)</li>
          </ul>
        </Paragraph>

        <Divider />

        <Title level={5}>Quick Tips</Title>
        <Paragraph>
          <ul>
            <li>Click repository names to view artifacts</li>
            <li>Use the search bar to find specific artifacts</li>
            <li>Click the refresh button to update data</li>
            <li>Copy artifact URLs and checksums with one click</li>
          </ul>
        </Paragraph>

        <Divider />

        <div style={{ textAlign: 'center' }}>
          <Space>
            <GithubOutlined />
            <Text type="secondary">Built with React, TypeScript & Ant Design</Text>
          </Space>
        </div>
      </Modal>
    </>
  )
}

export default AppHeader
