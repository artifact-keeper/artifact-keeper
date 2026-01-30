import { useState } from 'react'
import { Table, Button, Space, Tag, Modal, Form, Input, Select, message, Popconfirm, Card, Row, Col, Statistic, Tooltip, Badge, Drawer, Timeline, Typography } from 'antd'
import { PlusOutlined, DeleteOutlined, ReloadOutlined, SendOutlined, CheckCircleOutlined, CloseCircleOutlined, PlayCircleOutlined, PauseCircleOutlined, ThunderboltOutlined, HistoryOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import { webhooksApi } from '../api/webhooks'
import type { Webhook, WebhookDelivery, WebhookEvent, CreateWebhookRequest } from '../api/webhooks'
import { useDocumentTitle } from '../hooks'
import { useAuth } from '../contexts'

const { Text, Paragraph } = Typography

const WEBHOOK_EVENTS: { value: WebhookEvent; label: string }[] = [
  { value: 'artifact_uploaded', label: 'Artifact Uploaded' },
  { value: 'artifact_deleted', label: 'Artifact Deleted' },
  { value: 'repository_created', label: 'Repository Created' },
  { value: 'repository_deleted', label: 'Repository Deleted' },
  { value: 'user_created', label: 'User Created' },
  { value: 'user_deleted', label: 'User Deleted' },
  { value: 'build_started', label: 'Build Started' },
  { value: 'build_completed', label: 'Build Completed' },
  { value: 'build_failed', label: 'Build Failed' },
]

const eventColor = (event: string): string => {
  if (event.includes('deleted') || event.includes('failed')) return 'red'
  if (event.includes('created') || event.includes('uploaded') || event.includes('completed')) return 'green'
  if (event.includes('started')) return 'blue'
  return 'default'
}

const Webhooks = () => {
  useDocumentTitle('Webhooks')
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [deliveryDrawerOpen, setDeliveryDrawerOpen] = useState(false)
  const [selectedWebhook, setSelectedWebhook] = useState<Webhook | null>(null)
  const [form] = Form.useForm<CreateWebhookRequest>()

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['webhooks'],
    queryFn: () => webhooksApi.list({ per_page: 100 }),
    enabled: user?.is_admin,
  })

  const { data: deliveries, isLoading: deliveriesLoading } = useQuery({
    queryKey: ['webhook-deliveries', selectedWebhook?.id],
    queryFn: () => webhooksApi.listDeliveries(selectedWebhook!.id, { per_page: 50 }),
    enabled: !!selectedWebhook && deliveryDrawerOpen,
  })

  const createMutation = useMutation({
    mutationFn: (values: CreateWebhookRequest) => webhooksApi.create(values),
    onSuccess: () => {
      message.success('Webhook created')
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      setCreateModalOpen(false)
      form.resetFields()
    },
    onError: () => message.error('Failed to create webhook'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.delete(id),
    onSuccess: () => {
      message.success('Webhook deleted')
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
    onError: () => message.error('Failed to delete webhook'),
  })

  const enableMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.enable(id),
    onSuccess: () => {
      message.success('Webhook enabled')
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
    onError: () => message.error('Failed to enable webhook'),
  })

  const disableMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.disable(id),
    onSuccess: () => {
      message.success('Webhook disabled')
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
    onError: () => message.error('Failed to disable webhook'),
  })

  const testMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.test(id),
    onSuccess: (result) => {
      if (result.success) {
        message.success(`Test delivery succeeded (HTTP ${result.status_code})`)
      } else {
        message.warning(`Test delivery failed: ${result.error || `HTTP ${result.status_code}`}`)
      }
      queryClient.invalidateQueries({ queryKey: ['webhook-deliveries'] })
    },
    onError: () => message.error('Failed to send test delivery'),
  })

  const redeliverMutation = useMutation({
    mutationFn: ({ webhookId, deliveryId }: { webhookId: string; deliveryId: string }) =>
      webhooksApi.redeliver(webhookId, deliveryId),
    onSuccess: (result) => {
      if (result.success) {
        message.success('Redelivery succeeded')
      } else {
        message.warning('Redelivery failed')
      }
      queryClient.invalidateQueries({ queryKey: ['webhook-deliveries'] })
    },
    onError: () => message.error('Failed to redeliver'),
  })

  const openDeliveries = (webhook: Webhook) => {
    setSelectedWebhook(webhook)
    setDeliveryDrawerOpen(true)
  }

  const columns: ColumnsType<Webhook> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (name: string, record: Webhook) => (
        <Space>
          <SendOutlined />
          <span>{name}</span>
          {!record.is_enabled && <Tag>DISABLED</Tag>}
        </Space>
      ),
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (url: string) => (
        <Text copyable style={{ fontSize: 12 }}>{url}</Text>
      ),
    },
    {
      title: 'Events',
      dataIndex: 'events',
      key: 'events',
      width: 280,
      render: (events: string[]) => (
        <Space wrap size={[0, 4]}>
          {events.map(e => (
            <Tag key={e} color={eventColor(e)} style={{ fontSize: 11 }}>
              {e.replace(/_/g, ' ')}
            </Tag>
          ))}
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'is_enabled',
      key: 'status',
      width: 100,
      render: (enabled: boolean) => (
        <Badge status={enabled ? 'success' : 'default'} text={enabled ? 'Active' : 'Disabled'} />
      ),
    },
    {
      title: 'Last Triggered',
      dataIndex: 'last_triggered_at',
      key: 'last_triggered_at',
      width: 180,
      render: (date?: string) => date ? new Date(date).toLocaleString() : 'Never',
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 200,
      render: (_: unknown, record: Webhook) => (
        <Space>
          <Tooltip title="View deliveries">
            <Button type="text" icon={<HistoryOutlined />} onClick={() => openDeliveries(record)} />
          </Tooltip>
          <Tooltip title="Send test">
            <Button
              type="text"
              icon={<ThunderboltOutlined />}
              onClick={() => testMutation.mutate(record.id)}
              loading={testMutation.isPending}
            />
          </Tooltip>
          {record.is_enabled ? (
            <Tooltip title="Disable">
              <Button
                type="text"
                icon={<PauseCircleOutlined />}
                onClick={() => disableMutation.mutate(record.id)}
                loading={disableMutation.isPending}
              />
            </Tooltip>
          ) : (
            <Tooltip title="Enable">
              <Button
                type="text"
                icon={<PlayCircleOutlined />}
                onClick={() => enableMutation.mutate(record.id)}
                loading={enableMutation.isPending}
              />
            </Tooltip>
          )}
          <Popconfirm
            title="Delete webhook"
            description="This will permanently remove the webhook and its delivery history."
            onConfirm={() => deleteMutation.mutate(record.id)}
            okText="Delete"
            cancelText="Cancel"
          >
            <Tooltip title="Delete">
              <Button type="text" danger icon={<DeleteOutlined />} loading={deleteMutation.isPending} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const webhooks = data?.items ?? []
  const enabledCount = webhooks.filter(w => w.is_enabled).length

  if (!user?.is_admin) {
    return (
      <div>
        <h1>Webhooks</h1>
        <Card>
          <p>You must be an administrator to view this page.</p>
        </Card>
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Webhooks</h1>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['webhooks'] })}
            loading={isFetching}
          >
            Refresh
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
            Create Webhook
          </Button>
        </Space>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Card>
            <Statistic title="Total Webhooks" value={webhooks.length} prefix={<SendOutlined />} />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic
              title="Active"
              value={enabledCount}
              styles={{ content: { color: '#3f8600' } }}
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic
              title="Disabled"
              value={webhooks.length - enabledCount}
              prefix={<CloseCircleOutlined />}
            />
          </Card>
        </Col>
      </Row>

      <Table
        columns={columns}
        dataSource={webhooks}
        rowKey="id"
        loading={isLoading}
        pagination={{
          total: data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (total) => `Total ${total} webhooks`,
        }}
      />

      {/* Create Webhook Modal */}
      <Modal
        title="Create Webhook"
        open={createModalOpen}
        onCancel={() => {
          setCreateModalOpen(false)
          form.resetFields()
        }}
        footer={null}
        width={600}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) => createMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="Name"
            rules={[{ required: true, message: 'Enter a webhook name' }]}
          >
            <Input placeholder="e.g., Slack Notifications" />
          </Form.Item>
          <Form.Item
            name="url"
            label="Payload URL"
            rules={[
              { required: true, message: 'Enter a URL' },
              { type: 'url', message: 'Must be a valid URL' },
            ]}
          >
            <Input placeholder="https://example.com/webhook" />
          </Form.Item>
          <Form.Item
            name="events"
            label="Events"
            rules={[{ required: true, message: 'Select at least one event' }]}
          >
            <Select
              mode="multiple"
              placeholder="Select events to subscribe to"
              options={WEBHOOK_EVENTS}
            />
          </Form.Item>
          <Form.Item name="secret" label="Secret" tooltip="Used to sign payloads for verification">
            <Input.Password placeholder="Optional shared secret" />
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

      {/* Delivery History Drawer */}
      <Drawer
        title={`Deliveries: ${selectedWebhook?.name ?? ''}`}
        open={deliveryDrawerOpen}
        onClose={() => {
          setDeliveryDrawerOpen(false)
          setSelectedWebhook(null)
        }}
        width={520}
      >
        {deliveriesLoading ? (
          <div style={{ textAlign: 'center', padding: 40 }}>Loading...</div>
        ) : (
          <Timeline
            items={(deliveries?.items ?? []).map((d: WebhookDelivery) => ({
              color: d.success ? 'green' : 'red',
              children: (
                <div key={d.id}>
                  <Space>
                    <Tag color={eventColor(d.event)}>{d.event.replace(/_/g, ' ')}</Tag>
                    {d.success ? (
                      <Tag color="success">HTTP {d.response_status}</Tag>
                    ) : (
                      <Tag color="error">{d.response_status ? `HTTP ${d.response_status}` : 'Failed'}</Tag>
                    )}
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {new Date(d.created_at).toLocaleString()}
                    </Text>
                  </Space>
                  <div style={{ marginTop: 4 }}>
                    <Text type="secondary" style={{ fontSize: 11 }}>
                      Attempts: {d.attempts}
                    </Text>
                    {!d.success && selectedWebhook && (
                      <Button
                        type="link"
                        size="small"
                        onClick={() => redeliverMutation.mutate({
                          webhookId: selectedWebhook.id,
                          deliveryId: d.id,
                        })}
                        loading={redeliverMutation.isPending}
                      >
                        Redeliver
                      </Button>
                    )}
                  </div>
                  {d.response_body && (
                    <Paragraph
                      ellipsis={{ rows: 2, expandable: true }}
                      style={{ fontSize: 11, marginTop: 4, marginBottom: 0 }}
                      code
                    >
                      {d.response_body}
                    </Paragraph>
                  )}
                </div>
              ),
            }))}
          />
        )}
        {!deliveriesLoading && (deliveries?.items ?? []).length === 0 && (
          <div style={{ textAlign: 'center', color: '#999', padding: 40 }}>
            No deliveries yet
          </div>
        )}
      </Drawer>
    </div>
  )
}

export default Webhooks
