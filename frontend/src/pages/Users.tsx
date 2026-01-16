import { useState } from 'react'
import { Table, Button, Space, Tag, Alert, Spin, Modal, Form, Input, Switch, message, Typography } from 'antd'
import { PlusOutlined, EditOutlined, StopOutlined, CheckOutlined, CopyOutlined, KeyOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '../api'
import apiClient from '../api/client'
import { useAuth } from '../contexts'
import { useDocumentTitle } from '../hooks'
import type { User, CreateUserResponse } from '../types'

const { Text } = Typography

interface CreateUserForm {
  username: string
  email: string
  display_name?: string
  is_admin: boolean
}

interface EditUserForm {
  email?: string
  display_name?: string
  is_admin: boolean
}

const Users = () => {
  useDocumentTitle('Users')
  const { user: currentUser } = useAuth()
  const queryClient = useQueryClient()

  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [passwordModalOpen, setPasswordModalOpen] = useState(false)
  const [generatedPassword, setGeneratedPassword] = useState<string | null>(null)
  const [createdUsername, setCreatedUsername] = useState<string | null>(null)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [createForm] = Form.useForm<CreateUserForm>()
  const [editForm] = Form.useForm<EditUserForm>()

  const { data: users, isLoading, error } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => adminApi.listUsers(),
    enabled: currentUser?.is_admin,
  })

  const createUserMutation = useMutation({
    mutationFn: async (data: CreateUserForm) => {
      const response = await apiClient.post<CreateUserResponse>('/api/v1/users', data)
      return response.data
    },
    onSuccess: (data) => {
      setCreateModalOpen(false)
      createForm.resetFields()
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })

      if (data.generated_password) {
        setGeneratedPassword(data.generated_password)
        setCreatedUsername(data.user.username)
        setPasswordModalOpen(true)
      } else {
        message.success('User created successfully')
      }
    },
    onError: (error: any) => {
      message.error(error.response?.data?.message || 'Failed to create user')
    },
  })

  const updateUserMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: EditUserForm }) => {
      const response = await apiClient.patch(`/api/v1/users/${id}`, data)
      return response.data
    },
    onSuccess: () => {
      message.success('User updated successfully')
      setEditModalOpen(false)
      setSelectedUser(null)
      editForm.resetFields()
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
    },
    onError: (error: any) => {
      message.error(error.response?.data?.message || 'Failed to update user')
    },
  })

  const toggleUserStatusMutation = useMutation({
    mutationFn: async ({ id, is_active }: { id: string; is_active: boolean }) => {
      const response = await apiClient.patch(`/api/v1/users/${id}`, { is_active })
      return response.data
    },
    onSuccess: (_, variables) => {
      message.success(`User ${variables.is_active ? 'enabled' : 'disabled'} successfully`)
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
    },
    onError: (error: any) => {
      message.error(error.response?.data?.message || 'Failed to update user status')
    },
  })

  const resetPasswordMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiClient.post<{ temporary_password: string }>(`/api/v1/users/${id}/password/reset`)
      return response.data
    },
    onSuccess: (data, userId) => {
      const user = users?.find(u => u.id === userId)
      setGeneratedPassword(data.temporary_password)
      setCreatedUsername(user?.username || 'User')
      setPasswordModalOpen(true)
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
    },
    onError: (error: any) => {
      message.error(error.response?.data?.message || 'Failed to reset password')
    },
  })

  const handleCreateUser = (values: CreateUserForm) => {
    createUserMutation.mutate(values)
  }

  const handleEditUser = (values: EditUserForm) => {
    if (selectedUser) {
      updateUserMutation.mutate({ id: selectedUser.id, data: values })
    }
  }

  const handleToggleStatus = (user: User) => {
    toggleUserStatusMutation.mutate({ id: user.id, is_active: !user.is_active })
  }

  const openEditModal = (user: User) => {
    setSelectedUser(user)
    editForm.setFieldsValue({
      email: user.email,
      display_name: user.display_name || '',
      is_admin: user.is_admin,
    })
    setEditModalOpen(true)
  }

  const copyPassword = () => {
    if (generatedPassword) {
      navigator.clipboard.writeText(generatedPassword)
      message.success('Password copied to clipboard')
    }
  }

  const closePasswordModal = () => {
    setPasswordModalOpen(false)
    setGeneratedPassword(null)
    setCreatedUsername(null)
  }

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
      title: 'Status',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (isActive: boolean) => isActive ? <Tag color="green">Active</Tag> : <Tag color="red">Disabled</Tag>,
    },
    {
      title: 'Role',
      dataIndex: 'is_admin',
      key: 'is_admin',
      render: (isAdmin: boolean) => isAdmin ? <Tag color="gold">Admin</Tag> : <Tag>User</Tag>,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button
            type="link"
            icon={<EditOutlined />}
            onClick={() => openEditModal(record)}
          >
            Edit
          </Button>
          {record.id !== currentUser?.id && (
            <>
              <Button
                type="link"
                icon={<KeyOutlined />}
                onClick={() => resetPasswordMutation.mutate(record.id)}
                loading={resetPasswordMutation.isPending}
              >
                Reset Password
              </Button>
              <Button
                type="link"
                danger={record.is_active}
                icon={record.is_active ? <StopOutlined /> : <CheckOutlined />}
                onClick={() => handleToggleStatus(record)}
                loading={toggleUserStatusMutation.isPending}
              >
                {record.is_active ? 'Disable' : 'Enable'}
              </Button>
            </>
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
        <Spin size="large" />
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
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
          Create User
        </Button>
      </div>
      <Table columns={columns} dataSource={users || []} rowKey="id" />

      {/* Create User Modal */}
      <Modal
        title="Create User"
        open={createModalOpen}
        onCancel={() => {
          setCreateModalOpen(false)
          createForm.resetFields()
        }}
        footer={null}
      >
        <Alert
          message="Password will be auto-generated"
          description="A secure password will be generated and displayed after creation. The user will be required to change it on first login."
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <Form
          form={createForm}
          layout="vertical"
          onFinish={handleCreateUser}
          initialValues={{ is_admin: false }}
        >
          <Form.Item
            name="username"
            label="Username"
            rules={[
              { required: true, message: 'Please enter a username' },
              { min: 3, message: 'Username must be at least 3 characters' },
            ]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="email"
            label="Email"
            rules={[
              { required: true, message: 'Please enter an email' },
              { type: 'email', message: 'Please enter a valid email' },
            ]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="Display Name"
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="is_admin"
            label="Administrator"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={createUserMutation.isPending}>
                Create
              </Button>
              <Button onClick={() => {
                setCreateModalOpen(false)
                createForm.resetFields()
              }}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Generated Password Modal */}
      <Modal
        title="Temporary Password"
        open={passwordModalOpen}
        onCancel={closePasswordModal}
        footer={[
          <Button key="copy" icon={<CopyOutlined />} onClick={copyPassword}>
            Copy Password
          </Button>,
          <Button key="close" type="primary" onClick={closePasswordModal}>
            Done
          </Button>,
        ]}
      >
        <Alert
          message="Save this password!"
          description="This password will only be shown once. Make sure to save it or share it with the user securely."
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <div style={{ marginBottom: 16 }}>
          <Text strong>Username: </Text>
          <Text code>{createdUsername}</Text>
        </div>
        <div style={{ marginBottom: 16 }}>
          <Text strong>Temporary Password: </Text>
          <Text code copyable>{generatedPassword}</Text>
        </div>
        <Alert
          message="The user will be required to change this password on next login."
          type="info"
          showIcon
        />
      </Modal>

      {/* Edit User Modal */}
      <Modal
        title={`Edit User: ${selectedUser?.username}`}
        open={editModalOpen}
        onCancel={() => {
          setEditModalOpen(false)
          setSelectedUser(null)
          editForm.resetFields()
        }}
        footer={null}
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={handleEditUser}
        >
          <Form.Item
            name="email"
            label="Email"
            rules={[
              { type: 'email', message: 'Please enter a valid email' },
            ]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="Display Name"
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="is_admin"
            label="Administrator"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={updateUserMutation.isPending}>
                Save
              </Button>
              <Button onClick={() => {
                setEditModalOpen(false)
                setSelectedUser(null)
                editForm.resetFields()
              }}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Users
