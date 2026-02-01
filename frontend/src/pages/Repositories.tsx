import { useState, useCallback } from 'react'
import { Table, Button, Space, Tag, Modal, Form, Input, Select, Switch, message, Row, Col, Tooltip, Typography, Alert } from 'antd'
import { PlusOutlined, DeleteOutlined, EyeOutlined, EditOutlined, FilterOutlined, ReloadOutlined, ExclamationCircleOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import type { ColumnsType, TableProps } from 'antd/es/table'
import { repositoriesApi } from '../api'
import type { Repository, CreateRepositoryRequest, RepositoryFormat, RepositoryType } from '../types'
import { useDocumentTitle } from '../hooks'
import { useAuth } from '../contexts'
import { RepoWizard } from '../components/admin'

const { Text } = Typography

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
  useDocumentTitle('Repositories')
  const { isAuthenticated } = useAuth()

  // Modal states
  const [wizardOpen, setWizardOpen] = useState(false)
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [editingRepo, setEditingRepo] = useState<Repository | null>(null)
  const [deletingRepo, setDeletingRepo] = useState<Repository | null>(null)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')

  // Filter states
  const [formatFilter, setFormatFilter] = useState<string | undefined>()
  const [typeFilter, setTypeFilter] = useState<string | undefined>()

  const [editForm] = Form.useForm()
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['repositories', formatFilter, typeFilter],
    queryFn: () => repositoriesApi.list({ per_page: 100, format: formatFilter, repo_type: typeFilter }),
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
      setDeleteModalOpen(false)
      setDeletingRepo(null)
      setDeleteConfirmText('')
    },
    onError: () => {
      message.error('Failed to delete repository')
    },
  })

  const handleWizardSuccess = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['repositories'] })
    setWizardOpen(false)
    message.success('Repository created successfully')
  }, [queryClient])

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

  const handleDeleteClick = (repo: Repository) => {
    setDeletingRepo(repo)
    setDeleteConfirmText('')
    setDeleteModalOpen(true)
  }

  const handleDeleteConfirm = () => {
    if (deletingRepo && deleteConfirmText === deletingRepo.key) {
      deleteMutation.mutate(deletingRepo.key)
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
          {isAuthenticated && (
            <Button
              type="link"
              icon={<EditOutlined />}
              onClick={() => handleEdit(record)}
            >
              Edit
            </Button>
          )}
          {isAuthenticated && (
            <Button
              type="link"
              danger
              icon={<DeleteOutlined />}
              onClick={() => handleDeleteClick(record)}
            >
              Delete
            </Button>
          )}
        </Space>
      ),
    },
  ]

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['repositories'] })
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>Repositories</h1>
        <Space>
          <Tooltip title="Refresh">
            <Button
              icon={<ReloadOutlined spin={isFetching} />}
              onClick={handleRefresh}
            />
          </Tooltip>
          {isAuthenticated && (
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setWizardOpen(true)}>
              Create Repository
            </Button>
          )}
        </Space>
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

      {/* Create Repository Wizard */}
      <RepoWizard
        visible={wizardOpen}
        onClose={() => setWizardOpen(false)}
        onSuccess={handleWizardSuccess}
      />

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

      {/* Delete Confirmation Modal with Type-to-Confirm */}
      <Modal
        title={
          <Space>
            <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />
            <span>Delete Repository</span>
          </Space>
        }
        open={deleteModalOpen}
        onCancel={() => {
          setDeleteModalOpen(false)
          setDeletingRepo(null)
          setDeleteConfirmText('')
        }}
        footer={[
          <Button key="cancel" onClick={() => {
            setDeleteModalOpen(false)
            setDeletingRepo(null)
            setDeleteConfirmText('')
          }}>
            Cancel
          </Button>,
          <Button
            key="delete"
            type="primary"
            danger
            loading={deleteMutation.isPending}
            disabled={deleteConfirmText !== deletingRepo?.key}
            onClick={handleDeleteConfirm}
          >
            Delete Repository
          </Button>,
        ]}
      >
        <Alert
          type="error"
          message="This action cannot be undone"
          description={
            <>
              Deleting repository <Text strong>{deletingRepo?.key}</Text> will permanently remove all artifacts and metadata.
            </>
          }
          style={{ marginBottom: 16 }}
        />
        <div style={{ marginBottom: 8 }}>
          <Text>To confirm, type the repository key <Text strong code>{deletingRepo?.key}</Text> below:</Text>
        </div>
        <Input
          placeholder={deletingRepo?.key}
          value={deleteConfirmText}
          onChange={(e) => setDeleteConfirmText(e.target.value)}
          status={deleteConfirmText && deleteConfirmText !== deletingRepo?.key ? 'error' : undefined}
        />
      </Modal>
    </div>
  )
}

export default Repositories
