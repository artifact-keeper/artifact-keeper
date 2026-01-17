import { Card, Row, Col, Statistic, Spin, Alert, Table, Tag, Button, Tooltip } from 'antd'
// Removed unused Space import
import {
  DatabaseOutlined,
  FileOutlined,
  UserOutlined,
  HddOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ReloadOutlined
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import { adminApi, repositoriesApi } from '../api'
import type { Repository } from '../types'
import { useAuth } from '../contexts'
import { useDocumentTitle } from '../hooks'
import { useNavigate } from 'react-router-dom'

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const Dashboard = () => {
  useDocumentTitle('Dashboard')
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data: stats, isLoading: statsLoading, error: statsError, isFetching: statsFetching } = useQuery({
    queryKey: ['admin-stats'],
    queryFn: () => adminApi.getStats(),
    enabled: user?.is_admin,
  })

  const { data: health, isLoading: healthLoading, isFetching: healthFetching } = useQuery({
    queryKey: ['health'],
    queryFn: () => adminApi.getHealth(),
  })

  const { data: recentRepos, isLoading: reposLoading, isFetching: reposFetching } = useQuery({
    queryKey: ['recent-repositories'],
    queryFn: () => repositoriesApi.list({ per_page: 5 }),
  })

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['admin-stats'] })
    queryClient.invalidateQueries({ queryKey: ['health'] })
    queryClient.invalidateQueries({ queryKey: ['recent-repositories'] })
  }

  const isRefreshing = statsFetching || healthFetching || reposFetching

  const repoColumns: ColumnsType<Repository> = [
    {
      title: 'Key',
      dataIndex: 'key',
      key: 'key',
      render: (key: string) => <a onClick={() => navigate(`/repositories/${key}`)}>{key}</a>,
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
        const colors: Record<string, string> = { local: 'green', remote: 'orange', virtual: 'purple' }
        return <Tag color={colors[type]}>{type}</Tag>
      },
    },
    {
      title: 'Storage',
      dataIndex: 'storage_used_bytes',
      key: 'storage_used_bytes',
      render: (bytes: number) => formatBytes(bytes),
    },
  ]

  if (statsLoading || healthLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 50 }}>
        <Spin size="large" tip="Loading dashboard..." />
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>Dashboard</h1>
        <Tooltip title="Refresh data">
          <Button
            icon={<ReloadOutlined spin={isRefreshing} />}
            onClick={handleRefresh}
            loading={isRefreshing}
          >
            Refresh
          </Button>
        </Tooltip>
      </div>

      {/* System Health */}
      <Card title="System Health" style={{ marginBottom: 16 }}>
        <Row gutter={16}>
          <Col span={8}>
            <Statistic
              title="Status"
              value={health?.status || 'Unknown'}
              valueStyle={{ color: health?.status === 'healthy' ? '#3f8600' : '#cf1322' }}
              prefix={health?.status === 'healthy' ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
            />
          </Col>
          <Col span={8}>
            <Statistic
              title="Database"
              value={health?.checks?.database?.status || 'Unknown'}
              valueStyle={{ color: health?.checks?.database?.status === 'healthy' ? '#3f8600' : '#cf1322' }}
              prefix={health?.checks?.database?.status === 'healthy' ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
            />
          </Col>
          <Col span={8}>
            <Statistic
              title="Storage"
              value={health?.checks?.storage?.status || 'Unknown'}
              valueStyle={{ color: health?.checks?.storage?.status === 'healthy' ? '#3f8600' : '#cf1322' }}
              prefix={health?.checks?.storage?.status === 'healthy' ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
            />
          </Col>
        </Row>
      </Card>

      {/* Admin Stats */}
      {user?.is_admin ? (
        statsError ? (
          <Alert
            message="Failed to load admin statistics"
            type="error"
            style={{ marginBottom: 16 }}
          />
        ) : (
          <Row gutter={16} style={{ marginBottom: 16 }}>
            <Col span={6}>
              <Card hoverable onClick={() => navigate('/repositories')}>
                <Statistic
                  title="Repositories"
                  value={stats?.total_repositories || 0}
                  prefix={<DatabaseOutlined />}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic
                  title="Artifacts"
                  value={stats?.total_artifacts || 0}
                  prefix={<FileOutlined />}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card hoverable onClick={() => navigate('/users')}>
                <Statistic
                  title="Users"
                  value={stats?.total_users || 0}
                  prefix={<UserOutlined />}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic
                  title="Total Storage"
                  value={formatBytes(stats?.total_storage_bytes || 0)}
                  prefix={<HddOutlined />}
                />
              </Card>
            </Col>
          </Row>
        )
      ) : (
        <Alert
          message="Admin statistics are only available for administrators"
          type="info"
          style={{ marginBottom: 16 }}
        />
      )}

      {/* Recent Repositories */}
      <Card
        title="Recent Repositories"
        extra={
          <Button type="link" onClick={() => navigate('/repositories')}>
            View All
          </Button>
        }
      >
        <Table
          columns={repoColumns}
          dataSource={recentRepos?.items || []}
          rowKey="id"
          loading={reposLoading}
          pagination={false}
          size="small"
          locale={{ emptyText: 'No repositories yet. Create your first repository!' }}
        />
      </Card>
    </div>
  )
}

export default Dashboard
