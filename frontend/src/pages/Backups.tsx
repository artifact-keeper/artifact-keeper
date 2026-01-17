import { useState } from 'react'
import { Table, Button, Space, Tag, Modal, Form, Select, message, Popconfirm, Card, Row, Col, Statistic, Tooltip, Alert } from 'antd'
import { PlusOutlined, DeleteOutlined, ReloadOutlined, CloudDownloadOutlined, PlayCircleOutlined, StopOutlined, CheckCircleOutlined, CloseCircleOutlined, ClockCircleOutlined, SyncOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import apiClient from '../api/client'
import { useDocumentTitle } from '../hooks'
import { useAuth } from '../contexts'

interface Backup {
  id: string
  type: 'full' | 'incremental' | 'metadata'
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled'
  storage_path?: string
  size_bytes: number
  artifact_count: number
  started_at?: string
  completed_at?: string
  error_message?: string
  created_by?: string
  created_at: string
}

interface BackupsResponse {
  items: Backup[]
  total: number
}

interface CreateBackupRequest {
  type?: string
  repository_ids?: string[]
}

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const formatDuration = (start: string, end?: string): string => {
  if (!end) return 'In progress...'
  const ms = new Date(end).getTime() - new Date(start).getTime()
  const seconds = Math.floor(ms / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  if (hours > 0) return `${hours}h ${minutes % 60}m`
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`
  return `${seconds}s`
}

const statusColors: Record<string, string> = {
  pending: 'default',
  in_progress: 'processing',
  completed: 'success',
  failed: 'error',
  cancelled: 'warning',
}

const StatusIcon = ({ status }: { status: string }) => {
  switch (status) {
    case 'pending':
      return <ClockCircleOutlined />
    case 'in_progress':
      return <SyncOutlined spin />
    case 'completed':
      return <CheckCircleOutlined style={{ color: '#52c41a' }} />
    case 'failed':
      return <CloseCircleOutlined style={{ color: '#f5222d' }} />
    case 'cancelled':
      return <StopOutlined style={{ color: '#faad14' }} />
    default:
      return <ClockCircleOutlined />
  }
}

const Backups = () => {
  useDocumentTitle('Backups')
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [form] = Form.useForm<CreateBackupRequest>()

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['backups', statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.append('per_page', '100')
      if (statusFilter) params.append('status', statusFilter)
      const response = await apiClient.get<BackupsResponse>(`/api/v1/admin/backups?${params}`)
      return response.data
    },
    enabled: user?.is_admin,
    refetchInterval: 10000, // Refresh every 10 seconds to update in-progress backups
  })

  const createMutation = useMutation({
    mutationFn: async (data: CreateBackupRequest) => {
      const response = await apiClient.post<Backup>('/api/v1/admin/backups', data)
      return response.data
    },
    onSuccess: () => {
      message.success('Backup created successfully')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
      setCreateModalOpen(false)
      form.resetFields()
    },
    onError: () => {
      message.error('Failed to create backup')
    },
  })

  const executeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/api/v1/admin/backups/${id}/execute`)
    },
    onSuccess: () => {
      message.success('Backup started')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      message.error('Failed to start backup')
    },
  })

  const cancelMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/api/v1/admin/backups/${id}/cancel`)
    },
    onSuccess: () => {
      message.success('Backup cancelled')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      message.error('Failed to cancel backup')
    },
  })

  const restoreMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/api/v1/admin/backups/${id}/restore`)
    },
    onSuccess: () => {
      message.success('Restore started')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      message.error('Failed to start restore')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/api/v1/admin/backups/${id}`)
    },
    onSuccess: () => {
      message.success('Backup deleted')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      message.error('Failed to delete backup')
    },
  })

  const handleCreate = (values: CreateBackupRequest) => {
    createMutation.mutate(values)
  }

  const columns: ColumnsType<Backup> = [
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      width: 120,
      filters: [
        { text: 'Full', value: 'full' },
        { text: 'Incremental', value: 'incremental' },
        { text: 'Metadata', value: 'metadata' },
      ],
      onFilter: (value, record) => record.type === value,
      render: (type: string) => (
        <Tag color={type === 'full' ? 'blue' : type === 'incremental' ? 'green' : 'orange'}>
          {type.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 130,
      filters: [
        { text: 'Pending', value: 'pending' },
        { text: 'In Progress', value: 'in_progress' },
        { text: 'Completed', value: 'completed' },
        { text: 'Failed', value: 'failed' },
        { text: 'Cancelled', value: 'cancelled' },
      ],
      onFilter: (value, record) => record.status === value,
      render: (status: string) => (
        <Space>
          <StatusIcon status={status} />
          <Tag color={statusColors[status]}>{status.replace('_', ' ').toUpperCase()}</Tag>
        </Space>
      ),
    },
    {
      title: 'Size',
      dataIndex: 'size_bytes',
      key: 'size_bytes',
      width: 100,
      sorter: (a, b) => a.size_bytes - b.size_bytes,
      render: (bytes: number) => formatBytes(bytes),
    },
    {
      title: 'Artifacts',
      dataIndex: 'artifact_count',
      key: 'artifact_count',
      width: 100,
      sorter: (a, b) => a.artifact_count - b.artifact_count,
      render: (count: number) => count.toLocaleString(),
    },
    {
      title: 'Duration',
      key: 'duration',
      width: 120,
      render: (_: unknown, record: Backup) =>
        record.started_at ? formatDuration(record.started_at, record.completed_at) : '-',
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
      defaultSortOrder: 'descend',
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      title: 'Error',
      dataIndex: 'error_message',
      key: 'error_message',
      ellipsis: true,
      render: (msg: string | undefined) => msg ? (
        <Tooltip title={msg}>
          <span style={{ color: '#f5222d' }}>{msg}</span>
        </Tooltip>
      ) : '-',
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 150,
      render: (_: unknown, record: Backup) => (
        <Space>
          {record.status === 'pending' && (
            <Tooltip title="Execute Backup">
              <Button
                type="text"
                icon={<PlayCircleOutlined />}
                onClick={() => executeMutation.mutate(record.id)}
                loading={executeMutation.isPending}
              />
            </Tooltip>
          )}
          {record.status === 'in_progress' && (
            <Tooltip title="Cancel">
              <Button
                type="text"
                icon={<StopOutlined />}
                onClick={() => cancelMutation.mutate(record.id)}
                loading={cancelMutation.isPending}
              />
            </Tooltip>
          )}
          {record.status === 'completed' && (
            <Popconfirm
              title="Restore from backup"
              description="This will restore all data from this backup. Are you sure?"
              onConfirm={() => restoreMutation.mutate(record.id)}
              okText="Yes, Restore"
              cancelText="Cancel"
            >
              <Tooltip title="Restore">
                <Button
                  type="text"
                  icon={<CloudDownloadOutlined />}
                  loading={restoreMutation.isPending}
                />
              </Tooltip>
            </Popconfirm>
          )}
          {(record.status === 'completed' || record.status === 'failed' || record.status === 'cancelled') && (
            <Popconfirm
              title="Delete backup"
              description="Are you sure you want to delete this backup?"
              onConfirm={() => deleteMutation.mutate(record.id)}
              okText="Yes"
              cancelText="No"
            >
              <Tooltip title="Delete">
                <Button
                  type="text"
                  danger
                  icon={<DeleteOutlined />}
                  loading={deleteMutation.isPending}
                />
              </Tooltip>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  const completedBackups = data?.items?.filter(b => b.status === 'completed').length || 0
  const inProgressBackups = data?.items?.filter(b => b.status === 'in_progress').length || 0
  const totalSize = data?.items?.filter(b => b.status === 'completed')?.reduce((acc, b) => acc + b.size_bytes, 0) || 0
  const lastBackup = data?.items?.find(b => b.status === 'completed')

  if (!user?.is_admin) {
    return (
      <div>
        <h1>Backups</h1>
        <Card>
          <p>You must be an administrator to view this page.</p>
        </Card>
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Backups</h1>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['backups'] })}
            loading={isFetching}
          >
            Refresh
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
            Create Backup
          </Button>
        </Space>
      </div>

      {inProgressBackups > 0 && (
        <Alert
          message={`${inProgressBackups} backup(s) currently in progress`}
          type="info"
          showIcon
          icon={<SyncOutlined spin />}
          style={{ marginBottom: 16 }}
        />
      )}

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Total Backups"
              value={data?.items?.length || 0}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Completed"
              value={completedBackups}
              valueStyle={{ color: '#3f8600' }}
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Total Backup Size"
              value={formatBytes(totalSize)}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Last Backup"
              value={lastBackup ? new Date(lastBackup.created_at).toLocaleDateString() : 'Never'}
            />
          </Card>
        </Col>
      </Row>

      <Space style={{ marginBottom: 16 }}>
        <Select
          style={{ width: 150 }}
          placeholder="Filter by status"
          value={statusFilter}
          onChange={setStatusFilter}
          allowClear
          options={[
            { value: 'pending', label: 'Pending' },
            { value: 'in_progress', label: 'In Progress' },
            { value: 'completed', label: 'Completed' },
            { value: 'failed', label: 'Failed' },
            { value: 'cancelled', label: 'Cancelled' },
          ]}
        />
      </Space>

      <Table
        columns={columns}
        dataSource={data?.items || []}
        rowKey="id"
        loading={isLoading}
        pagination={{
          total: data?.total || 0,
          showSizeChanger: true,
          showTotal: (total) => `Total ${total} backups`,
        }}
      />

      <Modal
        title="Create Backup"
        open={createModalOpen}
        onCancel={() => {
          setCreateModalOpen(false)
          form.resetFields()
        }}
        footer={null}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleCreate}
          initialValues={{ type: 'full' }}
        >
          <Form.Item
            name="type"
            label="Backup Type"
            rules={[{ required: true, message: 'Please select a backup type' }]}
          >
            <Select
              options={[
                { value: 'full', label: 'Full - Complete backup of all data and artifacts' },
                { value: 'incremental', label: 'Incremental - Only changes since last backup' },
                { value: 'metadata', label: 'Metadata - Database only, no artifacts' },
              ]}
            />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={createMutation.isPending}>
                Create
              </Button>
              <Button onClick={() => {
                setCreateModalOpen(false)
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

export default Backups
