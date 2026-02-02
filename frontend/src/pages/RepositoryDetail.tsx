import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Card,
  Table,
  Button,
  Space,
  Tag,
  Breadcrumb,
  Descriptions,
  Input,
  message,
  Popconfirm,
  Spin,
  Empty,
  Typography,
  Modal,
  Upload,
  Form,
  Progress,
  Tooltip,
  Switch,
  Select,
  Collapse
} from 'antd'
import {
  ArrowLeftOutlined,
  DownloadOutlined,
  DeleteOutlined,
  SearchOutlined,
  FileOutlined,
  FolderOutlined,
  UploadOutlined,
  InboxOutlined,
  InfoCircleOutlined,
  CopyOutlined,
  CheckOutlined,
  SafetyCertificateOutlined
} from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import type { UploadFile } from 'antd/es/upload/interface'
import { repositoriesApi, artifactsApi, securityApi } from '../api'
import type { Artifact } from '../types'
import { useAuth } from '../contexts/AuthContext'
import { useDocumentTitle } from '../hooks'

const { Search } = Input
const { Text, Paragraph } = Typography
const { Dragger } = Upload

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const RepositoryDetail = () => {
  const { key, artifactId } = useParams<{ key: string; artifactId?: string }>()
  useDocumentTitle(key ? `Repository: ${key}` : 'Repository')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const [searchQuery, setSearchQuery] = useState('')
  const [uploadModalOpen, setUploadModalOpen] = useState(false)
  const [detailModalOpen, setDetailModalOpen] = useState(false)
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [fileList, setFileList] = useState<UploadFile[]>([])
  const [copiedField, setCopiedField] = useState<string | null>(null)
  const [form] = Form.useForm()
  const [securityForm] = Form.useForm()

  const { data: repository, isLoading: repoLoading } = useQuery({
    queryKey: ['repository', key],
    queryFn: () => repositoriesApi.get(key!),
    enabled: !!key,
  })

  const { data: artifactsData, isLoading: artifactsLoading } = useQuery({
    queryKey: ['artifacts', key, searchQuery],
    queryFn: () => artifactsApi.list(key!, { search: searchQuery || undefined, per_page: 100 }),
    enabled: !!key,
  })

  const { data: repoSecurity, isLoading: securityLoading } = useQuery({
    queryKey: ['repository-security', key],
    queryFn: () => securityApi.getRepoSecurity(key!),
    enabled: !!key && !!user?.is_admin,
  })

  const updateSecurityMutation = useMutation({
    mutationFn: (values: { scan_enabled: boolean; scan_on_upload: boolean; scan_on_proxy: boolean; block_on_policy_violation: boolean; severity_threshold: string }) =>
      securityApi.updateRepoSecurity(key!, values),
    onSuccess: () => {
      message.success('Security settings updated')
      queryClient.invalidateQueries({ queryKey: ['repository-security', key] })
      queryClient.invalidateQueries({ queryKey: ['security', 'scan-configs'] })
    },
    onError: () => {
      message.error('Failed to update security settings')
    },
  })

  // Auto-open artifact detail modal when navigated via /repositories/:key/artifacts/:artifactId
  useEffect(() => {
    if (artifactId && artifactsData?.items) {
      const artifact = artifactsData.items.find((a: Artifact) => a.id === artifactId)
      if (artifact) {
        setSelectedArtifact(artifact)
        setDetailModalOpen(true)
      }
    }
  }, [artifactId, artifactsData])

  const deleteMutation = useMutation({
    mutationFn: (path: string) => artifactsApi.delete(key!, path),
    onSuccess: () => {
      message.success('Artifact deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['artifacts', key] })
      queryClient.invalidateQueries({ queryKey: ['repository', key] })
      setDetailModalOpen(false)
      setSelectedArtifact(null)
    },
    onError: () => {
      message.error('Failed to delete artifact')
    },
  })

  const handleDownload = (artifact: Artifact) => {
    const url = artifactsApi.getDownloadUrl(key!, artifact.path)
    const token = localStorage.getItem('access_token')
    const link = document.createElement('a')
    link.href = `${url}?token=${token}`
    link.download = artifact.name
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const handleCopy = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedField(field)
      message.success('Copied to clipboard')
      setTimeout(() => setCopiedField(null), 2000)
    } catch {
      message.error('Failed to copy')
    }
  }

  const handleUpload = async () => {
    if (fileList.length === 0) {
      message.error('Please select a file to upload')
      return
    }

    const values = await form.validateFields()
    const file = fileList[0].originFileObj as File

    setUploading(true)
    setUploadProgress(0)

    try {
      await artifactsApi.upload(key!, file, values.path, (percent) => {
        setUploadProgress(percent)
      })
      message.success('Artifact uploaded successfully')
      queryClient.invalidateQueries({ queryKey: ['artifacts', key] })
      queryClient.invalidateQueries({ queryKey: ['repository', key] })
      setUploadModalOpen(false)
      setFileList([])
      form.resetFields()
    } catch {
      message.error('Failed to upload artifact')
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
  }

  const showArtifactDetails = (artifact: Artifact) => {
    setSelectedArtifact(artifact)
    setDetailModalOpen(true)
  }

  const getDownloadUrlForDisplay = (artifact: Artifact) => {
    return artifactsApi.getDownloadUrl(key!, artifact.path)
  }

  const columns: ColumnsType<Artifact> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record) => (
        <Space>
          {record.content_type?.includes('directory') ? (
            <FolderOutlined style={{ color: '#faad14' }} />
          ) : (
            <FileOutlined style={{ color: '#1890ff' }} />
          )}
          <a onClick={() => showArtifactDetails(record)}>{name}</a>
        </Space>
      ),
    },
    {
      title: 'Path',
      dataIndex: 'path',
      key: 'path',
      render: (path: string) => <Text code ellipsis style={{ maxWidth: 300 }}>{path}</Text>,
    },
    {
      title: 'Version',
      dataIndex: 'version',
      key: 'version',
      render: (version: string) => version ? <Tag>{version}</Tag> : '-',
    },
    {
      title: 'Size',
      dataIndex: 'size_bytes',
      key: 'size_bytes',
      render: (bytes: number) => formatBytes(bytes),
      sorter: (a, b) => a.size_bytes - b.size_bytes,
    },
    {
      title: 'Downloads',
      dataIndex: 'download_count',
      key: 'download_count',
      sorter: (a, b) => a.download_count - b.download_count,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => new Date(date).toLocaleDateString(),
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Tooltip title="View details">
            <Button
              type="link"
              icon={<InfoCircleOutlined />}
              onClick={() => showArtifactDetails(record)}
            >
              Details
            </Button>
          </Tooltip>
          <Button
            type="link"
            icon={<DownloadOutlined />}
            onClick={() => handleDownload(record)}
          >
            Download
          </Button>
          <Popconfirm
            title="Delete artifact"
            description="Are you sure you want to delete this artifact?"
            onConfirm={() => deleteMutation.mutate(record.path)}
            okText="Yes"
            cancelText="No"
          >
            <Button type="link" danger icon={<DeleteOutlined />}>
              Delete
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  if (repoLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 50 }}>
        <Spin size="large" />
      </div>
    )
  }

  if (!repository) {
    return <Empty description="Repository not found" />
  }

  return (
    <div>
      <Breadcrumb style={{ marginBottom: 16 }}>
        <Breadcrumb.Item>
          <a onClick={() => navigate('/repositories')}>Repositories</a>
        </Breadcrumb.Item>
        <Breadcrumb.Item>{repository.key}</Breadcrumb.Item>
      </Breadcrumb>

      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/repositories')}>
          Back to Repositories
        </Button>
        <Button
          type="primary"
          icon={<UploadOutlined />}
          onClick={() => setUploadModalOpen(true)}
        >
          Upload Artifact
        </Button>
      </div>

      <Card title="Repository Details" style={{ marginBottom: 16 }}>
        <Descriptions column={3}>
          <Descriptions.Item label="Key">{repository.key}</Descriptions.Item>
          <Descriptions.Item label="Name">{repository.name}</Descriptions.Item>
          <Descriptions.Item label="Format">
            <Tag color="blue">{repository.format.toUpperCase()}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Type">
            <Tag color={repository.repo_type === 'local' ? 'green' : repository.repo_type === 'remote' ? 'orange' : 'purple'}>
              {repository.repo_type}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Public">
            <Tag color={repository.is_public ? 'green' : 'default'}>
              {repository.is_public ? 'Yes' : 'No'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Storage Used">
            {formatBytes(repository.storage_used_bytes)}
          </Descriptions.Item>
          {repository.description && (
            <Descriptions.Item label="Description" span={3}>
              {repository.description}
            </Descriptions.Item>
          )}
        </Descriptions>
      </Card>

      {user?.is_admin && (
        <Collapse
          style={{ marginBottom: 16 }}
          items={[{
            key: 'security',
            label: (
              <Space>
                <SafetyCertificateOutlined />
                <span>Security Scan Settings</span>
                {repoSecurity?.config?.scan_enabled ? (
                  <Tag color="green">Enabled</Tag>
                ) : (
                  <Tag>Disabled</Tag>
                )}
              </Space>
            ),
            children: securityLoading ? (
              <Spin />
            ) : (
              <Form
                form={securityForm}
                layout="horizontal"
                labelCol={{ span: 8 }}
                wrapperCol={{ span: 16 }}
                style={{ maxWidth: 500 }}
                initialValues={{
                  scan_enabled: repoSecurity?.config?.scan_enabled ?? false,
                  scan_on_upload: repoSecurity?.config?.scan_on_upload ?? true,
                  scan_on_proxy: repoSecurity?.config?.scan_on_proxy ?? false,
                  block_on_policy_violation: repoSecurity?.config?.block_on_policy_violation ?? false,
                  severity_threshold: repoSecurity?.config?.severity_threshold ?? 'high',
                }}
                onFinish={(values) => updateSecurityMutation.mutate(values)}
              >
                <Form.Item name="scan_enabled" label="Enable Scanning" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name="scan_on_upload" label="Scan on Upload" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name="scan_on_proxy" label="Scan on Proxy" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name="block_on_policy_violation" label="Block on Violation" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name="severity_threshold" label="Severity Threshold">
                  <Select
                    options={[
                      { label: 'Critical', value: 'critical' },
                      { label: 'High', value: 'high' },
                      { label: 'Medium', value: 'medium' },
                      { label: 'Low', value: 'low' },
                    ]}
                  />
                </Form.Item>
                <Form.Item wrapperCol={{ offset: 8, span: 16 }}>
                  <Button
                    type="primary"
                    htmlType="submit"
                    loading={updateSecurityMutation.isPending}
                  >
                    Save Settings
                  </Button>
                </Form.Item>
              </Form>
            ),
          }]}
        />
      )}

      <Card
        title="Artifacts"
        extra={
          <Search
            placeholder="Search artifacts..."
            allowClear
            onSearch={setSearchQuery}
            style={{ width: 300 }}
            prefix={<SearchOutlined />}
          />
        }
      >
        <Table
          columns={columns}
          dataSource={artifactsData?.items || []}
          rowKey="id"
          loading={artifactsLoading}
          pagination={{
            total: artifactsData?.pagination?.total || 0,
            pageSize: artifactsData?.pagination?.per_page || 20,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} artifacts`,
          }}
        />
      </Card>

      {/* Upload Modal */}
      <Modal
        title="Upload Artifact"
        open={uploadModalOpen}
        onCancel={() => {
          if (!uploading) {
            setUploadModalOpen(false)
            setFileList([])
            form.resetFields()
          }
        }}
        footer={[
          <Button
            key="cancel"
            onClick={() => {
              setUploadModalOpen(false)
              setFileList([])
              form.resetFields()
            }}
            disabled={uploading}
          >
            Cancel
          </Button>,
          <Button
            key="upload"
            type="primary"
            onClick={handleUpload}
            loading={uploading}
            disabled={fileList.length === 0}
          >
            Upload
          </Button>,
        ]}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="path"
            label="Path (optional)"
            help="Specify a custom path for the artifact, e.g., 'libs/mylib-1.0.jar'"
          >
            <Input placeholder="path/to/artifact" />
          </Form.Item>

          <Form.Item label="File" required>
            <Dragger
              fileList={fileList}
              beforeUpload={(file) => {
                setFileList([file as unknown as UploadFile])
                return false
              }}
              onRemove={() => {
                setFileList([])
              }}
              maxCount={1}
              disabled={uploading}
            >
              <p className="ant-upload-drag-icon">
                <InboxOutlined />
              </p>
              <p className="ant-upload-text">Click or drag file to this area to upload</p>
              <p className="ant-upload-hint">
                Upload a single artifact file to this repository
              </p>
            </Dragger>
          </Form.Item>

          {uploading && (
            <Form.Item label="Upload Progress">
              <Progress percent={uploadProgress} status="active" />
            </Form.Item>
          )}
        </Form>
      </Modal>

      {/* Artifact Detail Modal */}
      <Modal
        title={
          <Space>
            <FileOutlined />
            <span>Artifact Details</span>
          </Space>
        }
        open={detailModalOpen}
        onCancel={() => {
          setDetailModalOpen(false)
          setSelectedArtifact(null)
        }}
        width={700}
        footer={[
          <Button
            key="download"
            type="primary"
            icon={<DownloadOutlined />}
            onClick={() => selectedArtifact && handleDownload(selectedArtifact)}
          >
            Download
          </Button>,
          <Popconfirm
            key="delete"
            title="Delete artifact"
            description="Are you sure you want to delete this artifact?"
            onConfirm={() => selectedArtifact && deleteMutation.mutate(selectedArtifact.path)}
            okText="Yes"
            cancelText="No"
          >
            <Button danger icon={<DeleteOutlined />}>
              Delete
            </Button>
          </Popconfirm>,
          <Button key="close" onClick={() => setDetailModalOpen(false)}>
            Close
          </Button>,
        ]}
      >
        {selectedArtifact && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="Name">
              <Text strong>{selectedArtifact.name}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Path">
              <Space>
                <Text code>{selectedArtifact.path}</Text>
                <Tooltip title="Copy path">
                  <Button
                    type="text"
                    size="small"
                    icon={copiedField === 'path' ? <CheckOutlined style={{ color: '#52c41a' }} /> : <CopyOutlined />}
                    onClick={() => handleCopy(selectedArtifact.path, 'path')}
                  />
                </Tooltip>
              </Space>
            </Descriptions.Item>
            {selectedArtifact.version && (
              <Descriptions.Item label="Version">
                <Tag color="blue">{selectedArtifact.version}</Tag>
              </Descriptions.Item>
            )}
            <Descriptions.Item label="Size">
              {formatBytes(selectedArtifact.size_bytes)} ({selectedArtifact.size_bytes.toLocaleString()} bytes)
            </Descriptions.Item>
            <Descriptions.Item label="Content Type">
              <Tag>{selectedArtifact.content_type}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Downloads">
              {selectedArtifact.download_count.toLocaleString()}
            </Descriptions.Item>
            <Descriptions.Item label="Created">
              {new Date(selectedArtifact.created_at).toLocaleString()}
            </Descriptions.Item>
            <Descriptions.Item label="SHA-256 Checksum">
              <Space orientation="vertical" style={{ width: '100%' }}>
                <Paragraph
                  code
                  copyable={{
                    text: selectedArtifact.checksum_sha256,
                    tooltips: ['Copy checksum', 'Copied!'],
                  }}
                  style={{ margin: 0, wordBreak: 'break-all' }}
                >
                  {selectedArtifact.checksum_sha256}
                </Paragraph>
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="Download URL">
              <Space orientation="vertical" style={{ width: '100%' }}>
                <Paragraph
                  code
                  copyable={{
                    text: getDownloadUrlForDisplay(selectedArtifact),
                    tooltips: ['Copy URL', 'Copied!'],
                  }}
                  style={{ margin: 0, wordBreak: 'break-all', fontSize: 12 }}
                >
                  {getDownloadUrlForDisplay(selectedArtifact)}
                </Paragraph>
              </Space>
            </Descriptions.Item>
            {selectedArtifact.metadata && Object.keys(selectedArtifact.metadata).length > 0 && (
              <Descriptions.Item label="Metadata">
                <pre style={{ margin: 0, fontSize: 12, background: '#f5f5f5', padding: 8, borderRadius: 4 }}>
                  {JSON.stringify(selectedArtifact.metadata, null, 2)}
                </pre>
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
      </Modal>
    </div>
  )
}

export default RepositoryDetail
