import { useState } from 'react'
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
  Progress
} from 'antd'
import {
  ArrowLeftOutlined,
  DownloadOutlined,
  DeleteOutlined,
  SearchOutlined,
  FileOutlined,
  FolderOutlined,
  UploadOutlined,
  InboxOutlined
} from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ColumnsType } from 'antd/es/table'
import type { UploadFile } from 'antd/es/upload/interface'
import { repositoriesApi, artifactsApi } from '../api'
import type { Artifact } from '../types'

const { Search } = Input
const { Text } = Typography
const { Dragger } = Upload

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const RepositoryDetail = () => {
  const { key } = useParams<{ key: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [searchQuery, setSearchQuery] = useState('')
  const [uploadModalOpen, setUploadModalOpen] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [fileList, setFileList] = useState<UploadFile[]>([])
  const [form] = Form.useForm()

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

  const deleteMutation = useMutation({
    mutationFn: (path: string) => artifactsApi.delete(key!, path),
    onSuccess: () => {
      message.success('Artifact deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['artifacts', key] })
      queryClient.invalidateQueries({ queryKey: ['repository', key] })
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
    } catch (error) {
      message.error('Failed to upload artifact')
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
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
          <span>{name}</span>
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
    </div>
  )
}

export default RepositoryDetail
