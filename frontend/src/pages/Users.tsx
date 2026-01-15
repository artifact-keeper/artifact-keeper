import { Table, Button, Space, Tag } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'

interface User {
  id: string
  username: string
  email: string
  authProvider: string
  isActive: boolean
  isAdmin: boolean
}

const Users = () => {
  // TODO: Fetch from API
  const users: User[] = []

  const columns: ColumnsType<User> = [
    {
      title: 'Username',
      dataIndex: 'username',
      key: 'username',
    },
    {
      title: 'Email',
      dataIndex: 'email',
      key: 'email',
    },
    {
      title: 'Auth Provider',
      dataIndex: 'authProvider',
      key: 'authProvider',
      render: (provider: string) => <Tag>{provider}</Tag>,
    },
    {
      title: 'Status',
      dataIndex: 'isActive',
      key: 'isActive',
      render: (isActive: boolean) => (
        <Tag color={isActive ? 'green' : 'red'}>
          {isActive ? 'Active' : 'Inactive'}
        </Tag>
      ),
    },
    {
      title: 'Admin',
      dataIndex: 'isAdmin',
      key: 'isAdmin',
      render: (isAdmin: boolean) => isAdmin ? <Tag color="gold">Admin</Tag> : null,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: () => (
        <Space>
          <Button type="link">Edit</Button>
          <Button type="link" danger>Disable</Button>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Users</h1>
        <Button type="primary" icon={<PlusOutlined />}>
          Create User
        </Button>
      </div>
      <Table columns={columns} dataSource={users} rowKey="id" />
    </div>
  )
}

export default Users
