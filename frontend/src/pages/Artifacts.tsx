import { useState } from 'react'
import { Table, Input, Select, Space, Tag, Button, Tooltip, message, Popconfirm, Card, Row, Col, Statistic } from 'antd'
import { SearchOutlined, DownloadOutlined, DeleteOutlined, ReloadOutlined, FileOutlined, DatabaseOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import type { ColumnsType } from 'antd/es/table'
import { repositoriesApi, artifactsApi } from '../api'
import type { Artifact, Repository } from '../types'
import { useDocumentTitle } from '../hooks'

const { Search } = Input

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const Artifacts = () => {
  useDocumentTitle('Artifacts')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [selectedRepo, setSelectedRepo] = useState<string | undefined>()
  const [searchTerm, setSearchTerm] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  // Fetch repositories for selector
  const { data: reposData } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => repositoriesApi.list({ per_page: 100 }),
  })

  // Fetch artifacts for selected repository
  const { data: artifactsData, isLoading, isFetching } = useQuery({
    queryKey: ['artifacts', selectedRepo, searchTerm, page, pageSize],
    queryFn: () => artifactsApi.list(selectedRepo!, { page, per_page: pageSize, search: searchTerm || undefined }),
    enabled: !!selectedRepo,
  })

  const deleteMutation = useMutation({
    mutationFn: ({ repoKey, path }: { repoKey: string; path: string }) => artifactsApi.delete(repoKey, path),
    onSuccess: () => {
      message.success('Artifact deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['artifacts'] })
    },
    onError: () => {
      message.error('Failed to delete artifact')
    },
  })

  const handleDownload = (artifact: Artifact) => {
    const url = artifactsApi.getDownloadUrl(artifact.repository_key, artifact.path)
    window.open(url, '_blank')
  }

  const handleDelete = (artifact: Artifact) => {
    deleteMutation.mutate({ repoKey: artifact.repository_key, path: artifact.path })
  }

  const columns: ColumnsType<Artifact> = [
    {
      title: 'Path',
      dataIndex: 'path',
      key: 'path',
      ellipsis: true,
      render: (path: string, record: Artifact) => (
        <Tooltip title={path}>
          <a onClick={() => navigate(`/repositories/${record.repository_key}?artifact=${encodeURIComponent(path)}`)}>
            {path}
          </a>
        </Tooltip>
      ),
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      width: 200,
    },
    {
      title: 'Version',
      dataIndex: 'version',
      key: 'version',
      width: 120,
      render: (version: string | undefined) => version || '-',
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
      title: 'Downloads',
      dataIndex: 'download_count',
      key: 'download_count',
      width: 100,
      sorter: (a, b) => a.download_count - b.download_count,
      render: (count: number) => count.toLocaleString(),
    },
    {
      title: 'Type',
      dataIndex: 'content_type',
      key: 'content_type',
      width: 150,
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 120,
      render: (_: unknown, record: Artifact) => (
        <Space>
          <Tooltip title="Download">
            <Button
              type="text"
              icon={<DownloadOutlined />}
              onClick={() => handleDownload(record)}
            />
          </Tooltip>
          <Popconfirm
            title="Delete artifact"
            description="Are you sure you want to delete this artifact?"
            onConfirm={() => handleDelete(record)}
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
        </Space>
      ),
    },
  ]

  const totalArtifacts = artifactsData?.pagination?.total || 0
  const totalSize = artifactsData?.items?.reduce((acc, a) => acc + a.size_bytes, 0) || 0

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Artifacts</h1>
        <Button
          icon={<ReloadOutlined />}
          onClick={() => queryClient.invalidateQueries({ queryKey: ['artifacts'] })}
          loading={isFetching}
        >
          Refresh
        </Button>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Card>
            <Statistic
              title="Total Artifacts"
              value={totalArtifacts}
              prefix={<FileOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic
              title="Total Size"
              value={formatBytes(totalSize)}
              prefix={<DatabaseOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic
              title="Repositories"
              value={reposData?.items?.length || 0}
            />
          </Card>
        </Col>
      </Row>

      <Space style={{ marginBottom: 16, width: '100%' }} direction="vertical" size="middle">
        <Row gutter={16}>
          <Col span={8}>
            <Select
              style={{ width: '100%' }}
              placeholder="Select a repository"
              value={selectedRepo}
              onChange={(value) => {
                setSelectedRepo(value)
                setPage(1)
              }}
              options={reposData?.items?.map((repo: Repository) => ({
                value: repo.key,
                label: `${repo.key} (${repo.format})`,
              }))}
              showSearch
              filterOption={(input, option) =>
                (option?.label?.toString() ?? '').toLowerCase().includes(input.toLowerCase())
              }
              allowClear
            />
          </Col>
          <Col span={16}>
            <Search
              placeholder="Search artifacts by path or name..."
              allowClear
              enterButton={<SearchOutlined />}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onSearch={(value) => {
                setSearchTerm(value)
                setPage(1)
              }}
              disabled={!selectedRepo}
            />
          </Col>
        </Row>
      </Space>

      {!selectedRepo ? (
        <Card style={{ textAlign: 'center', padding: 48 }}>
          <FileOutlined style={{ fontSize: 48, color: '#ccc', marginBottom: 16 }} />
          <p style={{ color: '#999' }}>Select a repository to browse artifacts</p>
        </Card>
      ) : (
        <Table
          columns={columns}
          dataSource={artifactsData?.items || []}
          rowKey="id"
          loading={isLoading}
          pagination={{
            current: page,
            pageSize: pageSize,
            total: artifactsData?.pagination?.total || 0,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} artifacts`,
            onChange: (newPage, newPageSize) => {
              setPage(newPage)
              setPageSize(newPageSize)
            },
          }}
        />
      )}
    </div>
  )
}

export default Artifacts
