import { Card, Row, Col, Statistic, Spin, Alert, Table, Tag } from 'antd'
import {
  DatabaseOutlined,
  FileOutlined,
  UserOutlined,
  HddOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import { adminApi, repositoriesApi } from '../api'
import type { Repository } from '../types'
import { useAuth } from '../contexts'

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const Dashboard = () => {
  const { user } = useAuth()

  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ['admin-stats'],
    queryFn: () => adminApi.getStats(),
    enabled: user?.is_admin,
  })

  const { data: health, isLoading: healthLoading } = useQuery({
    queryKey: ['health'],
    queryFn: () => adminApi.getHealth(),
  })

  const { data: recentRepos, isLoading: reposLoading } = useQuery({
    queryKey: ['recent-repositories'],
    queryFn: () => repositoriesApi.list({ per_page: 5 }),
  })

  const repoColumns: ColumnsType<Repository> = [
    {
      title: 'Key',
      dataIndex: 'key',
      key: 'key',
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
      <h1>Dashboard</h1>

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
              <Card>
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
              <Card>
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
      <Card title="Recent Repositories">
        <Table
          columns={repoColumns}
          dataSource={recentRepos?.items || []}
          rowKey="id"
          loading={reposLoading}
          pagination={false}
          size="small"
        />
      </Card>
    </div>
  )
}

export default Dashboard
