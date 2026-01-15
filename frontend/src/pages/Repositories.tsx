import { useState } from 'react'
import { Table, Button, Space, Tag, Modal, Form, Input, Select, Switch, message, Popconfirm, Row, Col } from 'antd'
import { PlusOutlined, DeleteOutlined, EyeOutlined, EditOutlined, FilterOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import type { ColumnsType, TableProps } from 'antd/es/table'
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
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [editingRepo, setEditingRepo] = useState<Repository | null>(null)
  const [formatFilter, setFormatFilter] = useState<string | undefined>()
  const [typeFilter, setTypeFilter] = useState<string | undefined>()
  const [createForm] = Form.useForm()
  const [editForm] = Form.useForm()
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data, isLoading } = useQuery({
    queryKey: ['repositories', formatFilter, typeFilter],
    queryFn: () => repositoriesApi.list({ per_page: 100, format: formatFilter, repo_type: typeFilter }),
  })

  const createMutation = useMutation({
    mutationFn: (data: CreateRepositoryRequest) => repositoriesApi.create(data),
    onSuccess: () => {
      message.success('Repository created successfully')
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      setCreateModalOpen(false)
      createForm.resetFields()
    },
    onError: () => {
      message.error('Failed to create repository')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ key, data }: { key: string; data: Partial<CreateRepositoryRequest> }) =>
      repositoriesApi.update(key, data),
    onSuccess: () => {
      message.success('Repository updated successfully')
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      setEditModalOpen(false)
      setEditingRepo(null)
      editForm.resetFields()
    },
    onError: () => {
      message.error('Failed to update repository')
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

  const handleEdit = (repo: Repository) => {
    setEditingRepo(repo)
    editForm.setFieldsValue({
      name: repo.name,
      description: repo.description,
      is_public: repo.is_public,
    })
    setEditModalOpen(true)
  }

  const handleUpdate = async (values: Partial<CreateRepositoryRequest>) => {
    if (editingRepo) {
      updateMutation.mutate({ key: editingRepo.key, data: values })
    }
  }

  const onChange: TableProps<Repository>['onChange'] = (pagination, filters, sorter) => {
    console.log('Table params:', { pagination, filters, sorter })
  }

  const columns: ColumnsType<Repository> = [
    {
      title: 'Key',
      dataIndex: 'key',
      key: 'key',
      sorter: (a, b) => a.key.localeCompare(b.key),
      render: (key: string) => <a onClick={() => navigate(`/repositories/${key}`)}>{key}</a>,
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      sorter: (a, b) => a.name.localeCompare(b.name),
    },
    {
      title: 'Format',
      dataIndex: 'format',
      key: 'format',
      filters: formatOptions.map(f => ({ text: f.label, value: f.value })),
      onFilter: (value, record) => record.format === value,
      render: (format: string) => <Tag color="blue">{format.toUpperCase()}</Tag>,
    },
    {
      title: 'Type',
      dataIndex: 'repo_type',
      key: 'repo_type',
      filters: repoTypeOptions.map(t => ({ text: t.label, value: t.value })),
      onFilter: (value, record) => record.repo_type === value,
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
      sorter: (a, b) => a.storage_used_bytes - b.storage_used_bytes,
      render: (bytes: number) => formatBytes(bytes),
    },
    {
      title: 'Public',
      dataIndex: 'is_public',
      key: 'is_public',
      filters: [
        { text: 'Public', value: true },
        { text: 'Private', value: false },
      ],
      onFilter: (value, record) => record.is_public === value,
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
          <Button
            type="link"
            icon={<EditOutlined />}
            onClick={() => handleEdit(record)}
          >
            Edit
          </Button>
          <Popconfirm
            title="Delete repository"
            description="Are you sure you want to delete this repository? This will delete all artifacts."
            onConfirm={() => deleteMutation.mutate(record.key)}
            okText="Yes"
            cancelText="No"
            okButtonProps={{ danger: true }}
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
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
          Create Repository
        </Button>
      </div>

      {/* Quick Filters */}
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col>
          <Space>
            <FilterOutlined />
            <Select
              placeholder="Filter by format"
              allowClear
              style={{ width: 150 }}
              options={formatOptions}
              value={formatFilter}
              onChange={setFormatFilter}
            />
            <Select
              placeholder="Filter by type"
              allowClear
              style={{ width: 150 }}
              options={repoTypeOptions}
              value={typeFilter}
              onChange={setTypeFilter}
            />
            {(formatFilter || typeFilter) && (
              <Button
                type="link"
                onClick={() => {
                  setFormatFilter(undefined)
                  setTypeFilter(undefined)
                }}
              >
                Clear filters
              </Button>
            )}
          </Space>
        </Col>
      </Row>

      <Table
        columns={columns}
        dataSource={data?.items || []}
        rowKey="id"
        loading={isLoading}
        onChange={onChange}
        pagination={{
          total: data?.pagination?.total || 0,
          pageSize: data?.pagination?.per_page || 20,
          showSizeChanger: true,
          showTotal: (total) => `Total ${total} repositories`,
        }}
      />

      {/* Create Modal */}
      <Modal
        title="Create Repository"
        open={createModalOpen}
        onCancel={() => {
          setCreateModalOpen(false)
          createForm.resetFields()
        }}
        footer={null}
      >
        <Form
          form={createForm}
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
                setCreateModalOpen(false)
                createForm.resetFields()
              }}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Edit Modal */}
      <Modal
        title={`Edit Repository: ${editingRepo?.key}`}
        open={editModalOpen}
        onCancel={() => {
          setEditModalOpen(false)
          setEditingRepo(null)
          editForm.resetFields()
        }}
        footer={null}
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={handleUpdate}
        >
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

          <Form.Item name="is_public" label="Public" valuePropName="checked">
            <Switch />
          </Form.Item>

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={updateMutation.isPending}>
                Save Changes
              </Button>
              <Button onClick={() => {
                setEditModalOpen(false)
                setEditingRepo(null)
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

export default Repositories
