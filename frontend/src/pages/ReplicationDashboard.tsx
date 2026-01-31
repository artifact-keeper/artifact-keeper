import { useState } from 'react'
import {
  Card,
  Row,
  Col,
  Table,
  Tag,
  Tabs,
  Select,
  Progress,
  Statistic,
  Badge,
  Space,
  Button,
  message,
} from 'antd'
import {
  CloudServerOutlined,
  WifiOutlined,
  DisconnectOutlined,
  SyncOutlined,
  ReloadOutlined,
} from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import { replicationApi } from '../api/replication'
import type { EdgeNode, EdgeNodePeer } from '../api/replication'
import { repositoriesApi } from '../api/repositories'
import { useDocumentTitle } from '../hooks'
import { useAuth } from '../contexts'
import type { Repository } from '../types'

// -- Shared helpers --

const STATUS_COLORS: Record<string, string> = {
  online: 'green',
  offline: 'red',
  syncing: 'blue',
  degraded: 'orange',
  connected: 'green',
  disconnected: 'red',
}

const PRIORITY_LABELS: Record<number, { label: string; color: string }> = {
  0: { label: 'P0 - Critical', color: 'red' },
  1: { label: 'P1 - High', color: 'orange' },
  2: { label: 'P2 - Normal', color: 'blue' },
  3: { label: 'P3 - Low', color: 'default' },
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

function formatBandwidth(bps: number): string {
  if (bps === 0) return '0 bps'
  const k = 1000
  const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps']
  const i = Math.floor(Math.log(bps) / Math.log(k))
  return `${parseFloat((bps / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function formatTimestamp(date: string | undefined): string {
  if (!date) return 'Never'
  return new Date(date).toLocaleString()
}

function getCachePercent(node: EdgeNode): number {
  if (node.cache_size_bytes === 0) return 0
  return Math.round((node.cache_used_bytes / node.cache_size_bytes) * 100)
}

function StatusIcon({ status }: { status: string }) {
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

// -- Overview Tab --

function OverviewTab({ nodes, isLoading }: { nodes: EdgeNode[]; isLoading: boolean }) {
  if (isLoading) {
    return <Card loading />
  }

  if (nodes.length === 0) {
    return (
      <Card>
        <p>No edge nodes registered. Register nodes from the Edge Nodes page.</p>
      </Card>
    )
  }

  return (
    <Row gutter={[16, 16]}>
      {nodes.map((node) => {
        const cachePercent = getCachePercent(node)
        return (
          <Col xs={24} sm={12} lg={8} xl={6} key={node.id}>
            <Card
              title={
                <Space>
                  <Badge status={node.status === 'online' ? 'success' : 'error'} />
                  {node.name}
                </Space>
              }
              extra={
                <Tag color={STATUS_COLORS[node.status]}>
                  {node.status.toUpperCase()}
                </Tag>
              }
              size="small"
            >
              {node.region && (
                <p style={{ margin: '0 0 8px', color: '#666' }}>
                  Region: {node.region}
                </p>
              )}

              <div style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span>Cache Usage</span>
                  <span>{formatBytes(node.cache_used_bytes)} / {formatBytes(node.cache_size_bytes)}</span>
                </div>
                <Progress
                  percent={cachePercent}
                  size="small"
                  status={cachePercent > 90 ? 'exception' : 'normal'}
                />
              </div>

              <Row gutter={16}>
                <Col span={12}>
                  <Statistic
                    title="Last Sync"
                    value={formatTimestamp(node.last_sync_at)}
                    valueStyle={{ fontSize: 12 }}
                  />
                </Col>
                <Col span={12}>
                  <Statistic
                    title="Heartbeat"
                    value={formatTimestamp(node.last_heartbeat_at)}
                    valueStyle={{ fontSize: 12 }}
                  />
                </Col>
              </Row>
            </Card>
          </Col>
        )
      })}
    </Row>
  )
}

// -- Topology Tab --

interface PeerRow extends EdgeNodePeer {
  source_node_name: string;
}

function TopologyTab({ nodes, isLoading }: { nodes: EdgeNode[]; isLoading: boolean }) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | undefined>()

  const { data: peers, isLoading: peersLoading } = useQuery({
    queryKey: ['edge-node-peers', selectedNodeId],
    queryFn: () => replicationApi.getEdgeNodePeers(selectedNodeId!),
    enabled: !!selectedNodeId,
  })

  const nodeMap = new Map(nodes.map((n) => [n.id, n.name]))

  const peerRows: PeerRow[] = (peers ?? []).map((peer) => ({
    ...peer,
    source_node_name: selectedNodeId ? (nodeMap.get(selectedNodeId) ?? 'Unknown') : 'Unknown',
  }))

  const columns: ColumnsType<PeerRow> = [
    {
      title: 'Source',
      dataIndex: 'source_node_name',
      key: 'source',
    },
    {
      title: 'Target',
      dataIndex: 'target_node_id',
      key: 'target',
      render: (id: string) => nodeMap.get(id) ?? id,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => (
        <Tag color={STATUS_COLORS[status] ?? 'default'}>{status.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Latency',
      dataIndex: 'latency_ms',
      key: 'latency',
      width: 100,
      sorter: (a, b) => a.latency_ms - b.latency_ms,
      render: (ms: number) => `${ms} ms`,
    },
    {
      title: 'Bandwidth',
      dataIndex: 'bandwidth_estimate_bps',
      key: 'bandwidth',
      width: 120,
      render: (bps: number) => formatBandwidth(bps),
    },
    {
      title: 'Shared Artifacts',
      dataIndex: 'shared_artifacts_count',
      key: 'shared',
      width: 130,
    },
    {
      title: 'Transferred',
      dataIndex: 'bytes_transferred_total',
      key: 'transferred',
      width: 120,
      render: (bytes: number) => formatBytes(bytes),
    },
    {
      title: 'Success / Failure',
      key: 'success_rate',
      width: 140,
      render: (_: unknown, record: PeerRow) => {
        const total = record.transfer_success_count + record.transfer_failure_count
        if (total === 0) return '-'
        return (
          <Space>
            <Tag color="green">{record.transfer_success_count}</Tag>
            <Tag color={record.transfer_failure_count > 0 ? 'red' : 'default'}>
              {record.transfer_failure_count}
            </Tag>
          </Space>
        )
      },
    },
  ]

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Select
          style={{ width: 300 }}
          placeholder="Select an edge node to view peers"
          value={selectedNodeId}
          onChange={setSelectedNodeId}
          loading={isLoading}
          options={nodes.map((node) => ({
            value: node.id,
            label: `${node.name} (${node.status})`,
          }))}
          allowClear
        />
      </div>

      <Table
        columns={columns}
        dataSource={peerRows}
        rowKey="id"
        loading={peersLoading}
        pagination={false}
        locale={{ emptyText: selectedNodeId ? 'No peers found' : 'Select a node to view peer connections' }}
      />
    </div>
  )
}

// -- Priority Tab --

interface RepoWithPriority {
  repository: Repository;
  priority: number | null;
}

function PriorityTab({ nodes }: { nodes: EdgeNode[] }) {
  const queryClient = useQueryClient()
  const [selectedNodeId, setSelectedNodeId] = useState<string | undefined>()

  const { data: repos, isLoading: reposLoading } = useQuery({
    queryKey: ['repositories-list'],
    queryFn: () => repositoriesApi.list({ per_page: 200 }),
  })

  const { data: assignedRepoIds } = useQuery({
    queryKey: ['edge-node-repos', selectedNodeId],
    queryFn: () => replicationApi.getEdgeNodeRepos(selectedNodeId!),
    enabled: !!selectedNodeId,
  })

  const assignMutation = useMutation({
    mutationFn: ({ nodeId, repoId, priority }: { nodeId: string; repoId: string; priority: number }) =>
      replicationApi.assignRepoToEdge(nodeId, { repository_id: repoId, priority }),
    onSuccess: () => {
      message.success('Replication priority updated')
      queryClient.invalidateQueries({ queryKey: ['edge-node-repos', selectedNodeId] })
    },
    onError: () => {
      message.error('Failed to update replication priority')
    },
  })

  const assignedSet = new Set(assignedRepoIds ?? [])

  const repoRows: RepoWithPriority[] = (repos?.items ?? []).map((repo) => ({
    repository: repo,
    priority: assignedSet.has(repo.id) ? 2 : null,
  }))

  function handlePriorityChange(repoId: string, priority: number) {
    if (!selectedNodeId) return
    assignMutation.mutate({ nodeId: selectedNodeId, repoId, priority })
  }

  const columns: ColumnsType<RepoWithPriority> = [
    {
      title: 'Repository',
      key: 'name',
      render: (_: unknown, record: RepoWithPriority) => (
        <div>
          <div style={{ fontWeight: 500 }}>{record.repository.name}</div>
          <div style={{ fontSize: 12, color: '#666' }}>{record.repository.key}</div>
        </div>
      ),
      sorter: (a, b) => a.repository.name.localeCompare(b.repository.name),
    },
    {
      title: 'Format',
      key: 'format',
      width: 100,
      render: (_: unknown, record: RepoWithPriority) => (
        <Tag>{record.repository.format.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Type',
      key: 'type',
      width: 100,
      render: (_: unknown, record: RepoWithPriority) => record.repository.repo_type,
    },
    {
      title: 'Assigned',
      key: 'assigned',
      width: 100,
      render: (_: unknown, record: RepoWithPriority) => (
        <Badge
          status={assignedSet.has(record.repository.id) ? 'success' : 'default'}
          text={assignedSet.has(record.repository.id) ? 'Yes' : 'No'}
        />
      ),
      filters: [
        { text: 'Assigned', value: true },
        { text: 'Unassigned', value: false },
      ],
      onFilter: (value, record) => assignedSet.has(record.repository.id) === value,
    },
    {
      title: 'Replication Priority',
      key: 'priority',
      width: 200,
      render: (_: unknown, record: RepoWithPriority) => (
        <Select
          style={{ width: 160 }}
          placeholder="Set priority"
          disabled={!selectedNodeId}
          value={assignedSet.has(record.repository.id) ? record.priority : undefined}
          onChange={(value) => handlePriorityChange(record.repository.id, value)}
          options={[0, 1, 2, 3].map((p) => ({
            value: p,
            label: PRIORITY_LABELS[p].label,
          }))}
          loading={assignMutation.isPending}
        />
      ),
    },
  ]

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Select
          style={{ width: 300 }}
          placeholder="Select an edge node"
          value={selectedNodeId}
          onChange={setSelectedNodeId}
          options={nodes.map((node) => ({
            value: node.id,
            label: `${node.name} (${node.region ?? 'no region'})`,
          }))}
          allowClear
        />
      </div>

      <Table
        columns={columns}
        dataSource={repoRows}
        rowKey={(record) => record.repository.id}
        loading={reposLoading}
        pagination={{
          showSizeChanger: true,
          showTotal: (total) => `Total ${total} repositories`,
        }}
      />
    </div>
  )
}

// -- Main Dashboard --

const ReplicationDashboard = () => {
  useDocumentTitle('Replication Dashboard')
  const { user } = useAuth()
  const queryClient = useQueryClient()

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['edge-nodes-replication'],
    queryFn: () => replicationApi.listEdgeNodes({ per_page: 100 }),
    enabled: user?.is_admin,
  })

  const nodes = data?.items ?? []
  const onlineCount = nodes.filter((n) => n.status === 'online').length
  const syncingCount = nodes.filter((n) => n.status === 'syncing').length
  const degradedCount = nodes.filter((n) => n.status === 'degraded').length
  const totalCacheUsed = nodes.reduce((acc, n) => acc + n.cache_used_bytes, 0)
  const totalCacheSize = nodes.reduce((acc, n) => acc + n.cache_size_bytes, 0)

  if (!user?.is_admin) {
    return (
      <div>
        <h1>Replication Dashboard</h1>
        <Card>
          <p>You must be an administrator to view this page.</p>
        </Card>
      </div>
    )
  }

  const tabItems = [
    {
      key: 'overview',
      label: 'Overview',
      children: <OverviewTab nodes={nodes} isLoading={isLoading} />,
    },
    {
      key: 'topology',
      label: 'Topology',
      children: <TopologyTab nodes={nodes} isLoading={isLoading} />,
    },
    {
      key: 'priority',
      label: 'Priority',
      children: <PriorityTab nodes={nodes} />,
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Replication Dashboard</h1>
        <Button
          icon={<ReloadOutlined />}
          onClick={() => queryClient.invalidateQueries({ queryKey: ['edge-nodes-replication'] })}
          loading={isFetching}
        >
          Refresh
        </Button>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Total Nodes"
              value={nodes.length}
              prefix={<CloudServerOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Online"
              value={onlineCount}
              styles={{ content: { color: '#3f8600' } }}
              prefix={<WifiOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Syncing / Degraded"
              value={`${syncingCount} / ${degradedCount}`}
              styles={{ content: { color: syncingCount > 0 ? '#1890ff' : undefined } }}
              prefix={<SyncOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Cache Usage"
              value={totalCacheSize > 0
                ? `${formatBytes(totalCacheUsed)} / ${formatBytes(totalCacheSize)}`
                : 'N/A'
              }
            />
          </Card>
        </Col>
      </Row>

      <Tabs items={tabItems} />
    </div>
  )
}

export default ReplicationDashboard
