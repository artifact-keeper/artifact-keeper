import { useState } from 'react'
import { Table, Button, Space, Tag, Modal, Form, Input, Select, message, Popconfirm, Card, Row, Col, Statistic, Tooltip, Descriptions, Tabs } from 'antd'
import { PlusOutlined, DeleteOutlined, ReloadOutlined, ApiOutlined, CheckCircleOutlined, CloseCircleOutlined, SettingOutlined, PlayCircleOutlined, PauseCircleOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import apiClient from '../api/client'
import { useDocumentTitle } from '../hooks'
import { useAuth } from '../contexts'

interface Plugin {
  id: string
  name: string
  description?: string
  version: string
  plugin_type: 'format_handler' | 'storage_backend' | 'authentication' | 'authorization' | 'webhook' | 'custom'
  status: 'active' | 'disabled' | 'error'
  author?: string
  homepage?: string
  error_message?: string
  installed_at: string
  updated_at: string
}

interface PluginsResponse {
  items: Plugin[]
  total: number
}

interface PluginConfig {
  key: string
  value: string
  description?: string
}

const pluginTypeColors: Record<string, string> = {
  format_handler: 'blue',
  storage_backend: 'purple',
  authentication: 'gold',
  authorization: 'orange',
  webhook: 'cyan',
  custom: 'default',
}

const statusColors: Record<string, string> = {
  active: 'success',
  disabled: 'default',
  error: 'error',
}

const StatusIcon = ({ status }: { status: string }) => {
  switch (status) {
    case 'active':
      return <CheckCircleOutlined style={{ color: '#52c41a' }} />
    case 'disabled':
      return <PauseCircleOutlined style={{ color: '#999' }} />
    case 'error':
      return <CloseCircleOutlined style={{ color: '#f5222d' }} />
    default:
      return <ApiOutlined />
  }
}

const Plugins = () => {
  useDocumentTitle('Plugins')
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [installModalOpen, setInstallModalOpen] = useState(false)
  const [configModalOpen, setConfigModalOpen] = useState(false)
  const [selectedPlugin, setSelectedPlugin] = useState<Plugin | null>(null)
  const [typeFilter] = useState<string | undefined>()
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [form] = Form.useForm()
  const [configForm] = Form.useForm()

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['plugins', typeFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.append('per_page', '100')
      if (statusFilter) params.append('status', statusFilter)
      const response = await apiClient.get<PluginsResponse>(`/api/v1/plugins?${params}`)
      return response.data
    },
    enabled: user?.is_admin,
  })

  const { data: pluginConfig } = useQuery({
    queryKey: ['plugin-config', selectedPlugin?.id],
    queryFn: async () => {
      const response = await apiClient.get<{ items: PluginConfig[] }>(`/api/v1/plugins/${selectedPlugin?.id}/config`)
      return response.data.items
    },
    enabled: !!selectedPlugin && configModalOpen,
  })

  const enableMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/api/v1/plugins/${id}/enable`)
    },
    onSuccess: () => {
      message.success('Plugin enabled')
      queryClient.invalidateQueries({ queryKey: ['plugins'] })
    },
    onError: () => {
      message.error('Failed to enable plugin')
    },
  })

  const disableMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/api/v1/plugins/${id}/disable`)
    },
    onSuccess: () => {
      message.success('Plugin disabled')
      queryClient.invalidateQueries({ queryKey: ['plugins'] })
    },
    onError: () => {
      message.error('Failed to disable plugin')
    },
  })

  const uninstallMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/api/v1/plugins/${id}`)
    },
    onSuccess: () => {
      message.success('Plugin uninstalled')
      queryClient.invalidateQueries({ queryKey: ['plugins'] })
    },
    onError: () => {
      message.error('Failed to uninstall plugin')
    },
  })

  const updateConfigMutation = useMutation({
    mutationFn: async ({ id, config }: { id: string; config: Record<string, string> }) => {
      await apiClient.post(`/api/v1/plugins/${id}/config`, config)
    },
    onSuccess: () => {
      message.success('Configuration saved')
      queryClient.invalidateQueries({ queryKey: ['plugin-config'] })
      setConfigModalOpen(false)
    },
    onError: () => {
      message.error('Failed to save configuration')
    },
  })

  const openConfigModal = (plugin: Plugin) => {
    setSelectedPlugin(plugin)
    setConfigModalOpen(true)
  }

  const handleSaveConfig = (values: Record<string, string>) => {
    if (selectedPlugin) {
      updateConfigMutation.mutate({ id: selectedPlugin.id, config: values })
    }
  }

  const columns: ColumnsType<Plugin> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (name: string, record: Plugin) => (
        <Space>
          <ApiOutlined />
          <span>{name}</span>
          <Tag>{record.version}</Tag>
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'plugin_type',
      key: 'plugin_type',
      width: 150,
      filters: [
        { text: 'Format Handler', value: 'format_handler' },
        { text: 'Storage Backend', value: 'storage_backend' },
        { text: 'Authentication', value: 'authentication' },
        { text: 'Authorization', value: 'authorization' },
        { text: 'Webhook', value: 'webhook' },
        { text: 'Custom', value: 'custom' },
      ],
      onFilter: (value, record) => record.plugin_type === value,
      render: (type: string) => (
        <Tag color={pluginTypeColors[type]}>
          {type.replace('_', ' ').toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      filters: [
        { text: 'Active', value: 'active' },
        { text: 'Disabled', value: 'disabled' },
        { text: 'Error', value: 'error' },
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
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (desc: string | undefined) => desc || '-',
    },
    {
      title: 'Author',
      dataIndex: 'author',
      key: 'author',
      width: 150,
      render: (author: string | undefined) => author || '-',
    },
    {
      title: 'Installed',
      dataIndex: 'installed_at',
      key: 'installed_at',
      width: 180,
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 180,
      render: (_: unknown, record: Plugin) => (
        <Space>
          <Tooltip title="Configure">
            <Button
              type="text"
              icon={<SettingOutlined />}
              onClick={() => openConfigModal(record)}
            />
          </Tooltip>
          {record.status === 'disabled' ? (
            <Tooltip title="Enable">
              <Button
                type="text"
                icon={<PlayCircleOutlined />}
                onClick={() => enableMutation.mutate(record.id)}
                loading={enableMutation.isPending}
              />
            </Tooltip>
          ) : (
            <Tooltip title="Disable">
              <Button
                type="text"
                icon={<PauseCircleOutlined />}
                onClick={() => disableMutation.mutate(record.id)}
                loading={disableMutation.isPending}
              />
            </Tooltip>
          )}
          <Popconfirm
            title="Uninstall plugin"
            description="Are you sure you want to uninstall this plugin?"
            onConfirm={() => uninstallMutation.mutate(record.id)}
            okText="Yes"
            cancelText="No"
          >
            <Tooltip title="Uninstall">
              <Button
                type="text"
                danger
                icon={<DeleteOutlined />}
                loading={uninstallMutation.isPending}
              />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const activePlugins = data?.items?.filter(p => p.status === 'active').length || 0
  const errorPlugins = data?.items?.filter(p => p.status === 'error').length || 0

  if (!user?.is_admin) {
    return (
      <div>
        <h1>Plugins</h1>
        <Card>
          <p>You must be an administrator to view this page.</p>
        </Card>
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Plugins</h1>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['plugins'] })}
            loading={isFetching}
          >
            Refresh
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setInstallModalOpen(true)}>
            Install Plugin
          </Button>
        </Space>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Total Plugins"
              value={data?.items?.length || 0}
              prefix={<ApiOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Active"
              value={activePlugins}
              valueStyle={{ color: '#3f8600' }}
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Errors"
              value={errorPlugins}
              valueStyle={errorPlugins > 0 ? { color: '#cf1322' } : undefined}
              prefix={<CloseCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Disabled"
              value={(data?.items?.length || 0) - activePlugins - errorPlugins}
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
            { value: 'active', label: 'Active' },
            { value: 'disabled', label: 'Disabled' },
            { value: 'error', label: 'Error' },
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
          showTotal: (total) => `Total ${total} plugins`,
        }}
      />

      {/* Install Plugin Modal */}
      <Modal
        title="Install Plugin"
        open={installModalOpen}
        onCancel={() => {
          setInstallModalOpen(false)
          form.resetFields()
        }}
        footer={null}
      >
        <Form
          form={form}
          layout="vertical"
        >
          <Form.Item
            name="source"
            label="Plugin Source"
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { value: 'registry', label: 'Plugin Registry' },
                { value: 'url', label: 'URL' },
                { value: 'upload', label: 'Upload File' },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="identifier"
            label="Plugin Identifier / URL"
            rules={[{ required: true }]}
          >
            <Input placeholder="e.g., webhook-notifier or https://..." />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                Install
              </Button>
              <Button onClick={() => {
                setInstallModalOpen(false)
                form.resetFields()
              }}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Plugin Configuration Modal */}
      <Modal
        title={`Configure: ${selectedPlugin?.name}`}
        open={configModalOpen}
        onCancel={() => {
          setConfigModalOpen(false)
          setSelectedPlugin(null)
          configForm.resetFields()
        }}
        footer={null}
        width={600}
      >
        {selectedPlugin && (
          <Tabs
            items={[
              {
                key: 'info',
                label: 'Information',
                children: (
                  <Descriptions column={1} bordered size="small">
                    <Descriptions.Item label="Name">{selectedPlugin.name}</Descriptions.Item>
                    <Descriptions.Item label="Version">{selectedPlugin.version}</Descriptions.Item>
                    <Descriptions.Item label="Type">
                      <Tag color={pluginTypeColors[selectedPlugin.plugin_type]}>
                        {selectedPlugin.plugin_type.replace('_', ' ').toUpperCase()}
                      </Tag>
                    </Descriptions.Item>
                    <Descriptions.Item label="Status">
                      <Tag color={statusColors[selectedPlugin.status]}>
                        {selectedPlugin.status.toUpperCase()}
                      </Tag>
                    </Descriptions.Item>
                    {selectedPlugin.description && (
                      <Descriptions.Item label="Description">{selectedPlugin.description}</Descriptions.Item>
                    )}
                    {selectedPlugin.author && (
                      <Descriptions.Item label="Author">{selectedPlugin.author}</Descriptions.Item>
                    )}
                    {selectedPlugin.homepage && (
                      <Descriptions.Item label="Homepage">
                        <a href={selectedPlugin.homepage} target="_blank" rel="noopener noreferrer">
                          {selectedPlugin.homepage}
                        </a>
                      </Descriptions.Item>
                    )}
                    {selectedPlugin.error_message && (
                      <Descriptions.Item label="Error">
                        <span style={{ color: '#f5222d' }}>{selectedPlugin.error_message}</span>
                      </Descriptions.Item>
                    )}
                  </Descriptions>
                ),
              },
              {
                key: 'config',
                label: 'Configuration',
                children: (
                  <Form
                    form={configForm}
                    layout="vertical"
                    onFinish={handleSaveConfig}
                    initialValues={pluginConfig?.reduce((acc, c) => ({ ...acc, [c.key]: c.value }), {})}
                  >
                    {pluginConfig && pluginConfig.length > 0 ? (
                      <>
                        {pluginConfig.map((config) => (
                          <Form.Item
                            key={config.key}
                            name={config.key}
                            label={config.key}
                            tooltip={config.description}
                          >
                            <Input />
                          </Form.Item>
                        ))}
                        <Form.Item>
                          <Button type="primary" htmlType="submit" loading={updateConfigMutation.isPending}>
                            Save Configuration
                          </Button>
                        </Form.Item>
                      </>
                    ) : (
                      <p style={{ color: '#999' }}>No configuration options available for this plugin.</p>
                    )}
                  </Form>
                ),
              },
            ]}
          />
        )}
      </Modal>
    </div>
  )
}

export default Plugins
