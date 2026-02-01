import { useState } from 'react'
import { Table, Button, Space, Tag, Modal, Form, Input, InputNumber, Select, message, Popconfirm, Progress, Card, Row, Col, Statistic, Tooltip } from 'antd'
import { PlusOutlined, DeleteOutlined, ReloadOutlined, CloudServerOutlined, SyncOutlined, WifiOutlined, DisconnectOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import apiClient from '../api/client'
import { useDocumentTitle } from '../hooks'
import { useAuth } from '../contexts'

interface EdgeNode {
  id: string
  name: string
  endpoint_url: string
  status: 'online' | 'offline' | 'syncing' | 'degraded'
  region?: string
  cache_size_bytes: number
  cache_used_bytes: number
  cache_usage_percent: number
  last_heartbeat_at?: string
  last_sync_at?: string
  created_at: string
}

interface EdgeNodesResponse {
  items: EdgeNode[]
  total: number
}

interface CreateEdgeNodeRequest {
  name: string
  endpoint_url: string
  region?: string
  cache_size_bytes?: number
}

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const statusColors: Record<string, string> = {
  online: 'green',
  offline: 'red',
  syncing: 'blue',
  degraded: 'orange',
}

const StatusIcon = ({ status }: { status: string }) => {
  switch (status) {
    case 'online':
      return <WifiOutlined style={{ color: '#52c41a' }} />
    case 'offline':
      return <DisconnectOutlined style={{ color: '#f5222d' }} />
    case 'syncing':
      return <SyncOutlined spin style={{ color: '#1890ff' }} />
    case 'degraded':
      return <WifiOutlined style={{ color: '#faad14' }} />
    default:
      return <CloudServerOutlined />
  }
}

const EdgeNodes = () => {
  useDocumentTitle('Edge Nodes')
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [form] = Form.useForm<CreateEdgeNodeRequest>()

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['edge-nodes', statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.append('per_page', '100')
      if (statusFilter) params.append('status', statusFilter)
      const response = await apiClient.get<EdgeNodesResponse>(`/api/v1/edge-nodes?${params}`)
      return response.data
    },
    enabled: user?.is_admin,
  })

  const createMutation = useMutation({
    mutationFn: async (data: CreateEdgeNodeRequest) => {
      const response = await apiClient.post<EdgeNode>('/api/v1/edge-nodes', data)
      return response.data
    },
    onSuccess: () => {
      message.success('Edge node registered successfully')
      queryClient.invalidateQueries({ queryKey: ['edge-nodes'] })
      setCreateModalOpen(false)
      form.resetFields()
    },
    onError: () => {
      message.error('Failed to register edge node')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/api/v1/edge-nodes/${id}`)
    },
    onSuccess: () => {
      message.success('Edge node unregistered successfully')
      queryClient.invalidateQueries({ queryKey: ['edge-nodes'] })
    },
    onError: () => {
      message.error('Failed to unregister edge node')
    },
  })

  const syncMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/api/v1/edge-nodes/${id}/sync`)
    },
    onSuccess: () => {
      message.success('Sync triggered successfully')
      queryClient.invalidateQueries({ queryKey: ['edge-nodes'] })
    },
    onError: () => {
      message.error('Failed to trigger sync')
    },
  })

  const handleCreate = (values: CreateEdgeNodeRequest) => {
    createMutation.mutate(values)
  }

  const columns: ColumnsType<EdgeNode> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      sorter: (a, b) => a.name.localeCompare(b.name),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      filters: [
        { text: 'Online', value: 'online' },
        { text: 'Offline', value: 'offline' },
        { text: 'Syncing', value: 'syncing' },
        { text: 'Degraded', value: 'degraded' },
      ],
      onFilter: (value, record) => record.status === value,
      render: (status: string) => (
        <Space>
          <StatusIcon status={status} />
          <Tag color={statusColors[status]}>{status.toUpperCase()}</Tag>
        </Space>
      ),
    },
    {
      title: 'Region',
      dataIndex: 'region',
      key: 'region',
      width: 120,
      render: (region: string | undefined) => region || '-',
    },
    {
      title: 'Endpoint',
      dataIndex: 'endpoint_url',
      key: 'endpoint_url',
      ellipsis: true,
      render: (url: string) => (
        <Tooltip title={url}>
          <a href={url} target="_blank" rel="noopener noreferrer">{url}</a>
        </Tooltip>
      ),
    },
    {
      title: 'Cache Usage',
      key: 'cache_usage',
      width: 200,
      render: (_: unknown, record: EdgeNode) => (
        <Space orientation="vertical" size="small" style={{ width: '100%' }}>
          <Progress
            percent={Math.round(record.cache_usage_percent)}
            size="small"
            status={record.cache_usage_percent > 90 ? 'exception' : 'normal'}
          />
          <span style={{ fontSize: 12, color: '#666' }}>
            {formatBytes(record.cache_used_bytes)} / {formatBytes(record.cache_size_bytes)}
          </span>
        </Space>
      ),
    },
    {
      title: 'Last Heartbeat',
      dataIndex: 'last_heartbeat_at',
      key: 'last_heartbeat_at',
      width: 180,
      render: (date: string | undefined) => date ? new Date(date).toLocaleString() : 'Never',
    },
    {
      title: 'Last Sync',
      dataIndex: 'last_sync_at',
      key: 'last_sync_at',
      width: 180,
      render: (date: string | undefined) => date ? new Date(date).toLocaleString() : 'Never',
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 120,
      render: (_: unknown, record: EdgeNode) => (
        <Space>
          <Tooltip title="Trigger Sync">
            <Button
              type="text"
              icon={<SyncOutlined />}
              onClick={() => syncMutation.mutate(record.id)}
              loading={syncMutation.isPending}
              disabled={record.status === 'offline'}
            />
          </Tooltip>
          <Popconfirm
            title="Unregister edge node"
            description="Are you sure you want to unregister this edge node?"
            onConfirm={() => deleteMutation.mutate(record.id)}
            okText="Yes"
            cancelText="No"
          >
            <Tooltip title="Unregister">
              <Button
                type="text"
                danger
                icon={<DeleteOutlined />}
                loading={deleteMutation.isPending}
              />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const onlineNodes = data?.items?.filter(n => n.status === 'online').length || 0
  const totalNodes = data?.items?.length || 0
  const totalCacheUsed = data?.items?.reduce((acc, n) => acc + n.cache_used_bytes, 0) || 0
  const totalCacheSize = data?.items?.reduce((acc, n) => acc + n.cache_size_bytes, 0) || 0

  if (!user?.is_admin) {
    return (
      <div>
        <h1>Edge Nodes</h1>
        <Card>
          <p>You must be an administrator to view this page.</p>
        </Card>
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Edge Nodes</h1>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['edge-nodes'] })}
            loading={isFetching}
          >
            Refresh
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
            Register Node
          </Button>
        </Space>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Total Nodes"
              value={totalNodes}
              prefix={<CloudServerOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Online"
              value={onlineNodes}
              styles={{ content: { color: '#3f8600' } }}
              prefix={<WifiOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Cache Used"
              value={formatBytes(totalCacheUsed)}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Total Cache Capacity"
              value={formatBytes(totalCacheSize)}
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
            { value: 'online', label: 'Online' },
            { value: 'offline', label: 'Offline' },
            { value: 'syncing', label: 'Syncing' },
            { value: 'degraded', label: 'Degraded' },
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
          showTotal: (total) => `Total ${total} nodes`,
        }}
      />

      <Modal
        title="Register Edge Node"
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
        >
          <Form.Item
            name="name"
            label="Name"
            rules={[{ required: true, message: 'Please enter a name' }]}
          >
            <Input placeholder="edge-us-west-1" />
          </Form.Item>
          <Form.Item
            name="endpoint_url"
            label="Endpoint URL"
            rules={[
              { required: true, message: 'Please enter the endpoint URL' },
              { type: 'url', message: 'Please enter a valid URL' },
            ]}
          >
            <Input placeholder="https://edge.example.com:8080" />
          </Form.Item>
          <Form.Item
            name="region"
            label="Region"
          >
            <Input placeholder="us-west-1" />
          </Form.Item>
          <Form.Item
            name="cache_size_bytes"
            label="Cache Size (GB)"
          >
            <InputNumber
              min={1}
              max={10240}
              placeholder="100"
              style={{ width: '100%' }}
              formatter={((value: string | undefined) => `${value} GB`) as never}
              parser={((value: string | undefined) => Number(value?.replace(' GB', '') || 1)) as never}
            />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={createMutation.isPending}>
                Register
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

export default EdgeNodes
