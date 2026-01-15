import { Table, Button, Space, Tag, Alert, Spin } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { useQuery } from '@tanstack/react-query'
import { adminApi } from '../api'
import { useAuth } from '../contexts'
import { useDocumentTitle } from '../hooks'
import type { User } from '../types'

const Users = () => {
  useDocumentTitle('Users')
  const { user: currentUser } = useAuth()

  const { data: users, isLoading, error } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => adminApi.listUsers(),
    enabled: currentUser?.is_admin,
  })

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
      title: 'Display Name',
      dataIndex: 'display_name',
      key: 'display_name',
      render: (name: string) => name || '-',
    },
    {
      title: 'Admin',
      dataIndex: 'is_admin',
      key: 'is_admin',
      render: (isAdmin: boolean) => isAdmin ? <Tag color="gold">Admin</Tag> : <Tag>User</Tag>,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button type="link" disabled>Edit</Button>
          {record.id !== currentUser?.id && (
            <Button type="link" danger disabled>Disable</Button>
          )}
        </Space>
      ),
    },
  ]

  if (!currentUser?.is_admin) {
    return (
      <div>
        <h1>Users</h1>
        <Alert
          message="Access Denied"
          description="You must be an administrator to view this page."
          type="error"
          showIcon
        />
      </div>
    )
  }

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 50 }}>
        <Spin size="large" tip="Loading users..." />
      </div>
    )
  }

  if (error) {
    return (
      <div>
        <h1>Users</h1>
        <Alert
          message="Error loading users"
          description="Failed to fetch user list from the server."
          type="error"
          showIcon
        />
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Users</h1>
        <Button type="primary" icon={<PlusOutlined />} disabled>
          Create User
        </Button>
      </div>
      <Table columns={columns} dataSource={users || []} rowKey="id" />
    </div>
  )
}

export default Users
