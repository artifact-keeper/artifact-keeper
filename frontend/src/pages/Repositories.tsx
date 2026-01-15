import { useState } from 'react'
import { Table, Button, Space, Tag, Modal, Form, Input, Select, Switch, message, Popconfirm } from 'antd'
import { PlusOutlined, DeleteOutlined, EyeOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import type { ColumnsType } from 'antd/es/table'
import { repositoriesApi } from '../api'
import type { Repository, CreateRepositoryRequest, RepositoryFormat, RepositoryType } from '../types'

const formatOptions: { value: RepositoryFormat; label: string }[] = [
  { value: 'maven', label: 'Maven' },
  { value: 'pypi', label: 'PyPI' },
  { value: 'npm', label: 'NPM' },
  { value: 'docker', label: 'Docker' },
  { value: 'helm', label: 'Helm' },
  { value: 'rpm', label: 'RPM' },
  { value: 'debian', label: 'Debian' },
  { value: 'go', label: 'Go' },
  { value: 'nuget', label: 'NuGet' },
  { value: 'cargo', label: 'Cargo' },
  { value: 'generic', label: 'Generic' },
]

const repoTypeOptions: { value: RepositoryType; label: string }[] = [
  { value: 'local', label: 'Local' },
  { value: 'remote', label: 'Remote' },
  { value: 'virtual', label: 'Virtual' },
]

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const Repositories = () => {
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [form] = Form.useForm()
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data, isLoading } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => repositoriesApi.list({ per_page: 100 }),
  })

  const createMutation = useMutation({
    mutationFn: (data: CreateRepositoryRequest) => repositoriesApi.create(data),
    onSuccess: () => {
      message.success('Repository created successfully')
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      setIsModalOpen(false)
      form.resetFields()
    },
    onError: () => {
      message.error('Failed to create repository')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (key: string) => repositoriesApi.delete(key),
    onSuccess: () => {
      message.success('Repository deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
    },
    onError: () => {
      message.error('Failed to delete repository')
    },
  })

  const handleCreate = async (values: CreateRepositoryRequest) => {
    createMutation.mutate(values)
  }

  const columns: ColumnsType<Repository> = [
    {
      title: 'Key',
      dataIndex: 'key',
      key: 'key',
      render: (key: string) => <a onClick={() => navigate(`/repositories/${key}`)}>{key}</a>,
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'Format',
      dataIndex: 'format',
      key: 'format',
      render: (format: string) => <Tag color="blue">{format.toUpperCase()}</Tag>,
    },
    {
      title: 'Type',
      dataIndex: 'repo_type',
      key: 'repo_type',
      render: (type: string) => {
        const colors: Record<string, string> = {
          local: 'green',
          remote: 'orange',
          virtual: 'purple',
        }
        return <Tag color={colors[type] || 'default'}>{type}</Tag>
      },
    },
    {
      title: 'Storage',
      dataIndex: 'storage_used_bytes',
      key: 'storage_used_bytes',
      render: (bytes: number) => formatBytes(bytes),
    },
    {
      title: 'Public',
      dataIndex: 'is_public',
      key: 'is_public',
      render: (isPublic: boolean) => (
        <Tag color={isPublic ? 'green' : 'default'}>{isPublic ? 'Yes' : 'No'}</Tag>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button
            type="link"
            icon={<EyeOutlined />}
            onClick={() => navigate(`/repositories/${record.key}`)}
          >
            View
          </Button>
          <Popconfirm
            title="Delete repository"
            description="Are you sure you want to delete this repository?"
            onConfirm={() => deleteMutation.mutate(record.key)}
            okText="Yes"
            cancelText="No"
          >
            <Button type="link" danger icon={<DeleteOutlined />} loading={deleteMutation.isPending}>
              Delete
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Repositories</h1>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>
          Create Repository
        </Button>
      </div>
      <Table
        columns={columns}
        dataSource={data?.items || []}
        rowKey="id"
        loading={isLoading}
        pagination={{
          total: data?.pagination?.total || 0,
          pageSize: data?.pagination?.per_page || 20,
          showSizeChanger: true,
          showTotal: (total) => `Total ${total} repositories`,
        }}
      />

      <Modal
        title="Create Repository"
        open={isModalOpen}
        onCancel={() => {
          setIsModalOpen(false)
          form.resetFields()
        }}
        footer={null}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleCreate}
          initialValues={{ is_public: false, repo_type: 'local' }}
        >
          <Form.Item
            name="key"
            label="Repository Key"
            rules={[
              { required: true, message: 'Please enter a repository key' },
              { pattern: /^[a-z0-9-]+$/, message: 'Key must be lowercase alphanumeric with dashes' },
            ]}
          >
            <Input placeholder="my-repo" />
          </Form.Item>

          <Form.Item
            name="name"
            label="Name"
            rules={[{ required: true, message: 'Please enter a name' }]}
          >
            <Input placeholder="My Repository" />
          </Form.Item>

          <Form.Item name="description" label="Description">
            <Input.TextArea placeholder="Repository description" rows={3} />
          </Form.Item>

          <Form.Item
            name="format"
            label="Format"
            rules={[{ required: true, message: 'Please select a format' }]}
          >
            <Select options={formatOptions} placeholder="Select format" />
          </Form.Item>

          <Form.Item
            name="repo_type"
            label="Type"
            rules={[{ required: true, message: 'Please select a type' }]}
          >
            <Select options={repoTypeOptions} placeholder="Select type" />
          </Form.Item>

          <Form.Item name="is_public" label="Public" valuePropName="checked">
            <Switch />
          </Form.Item>

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={createMutation.isPending}>
                Create
              </Button>
              <Button onClick={() => {
                setIsModalOpen(false)
                form.resetFields()
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

export default Repositories
