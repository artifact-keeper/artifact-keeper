import { Table, Button, Space, Tag } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'

interface Repository {
  id: string
  key: string
  name: string
  format: string
  repoType: string
  artifactCount: number
  isPublic: boolean
}

const Repositories = () => {
  // TODO: Fetch from API
  const repositories: Repository[] = []

  const columns: ColumnsType<Repository> = [
    {
      title: 'Key',
      dataIndex: 'key',
      key: 'key',
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'Format',
      dataIndex: 'format',
      key: 'format',
      render: (format: string) => <Tag color="blue">{format}</Tag>,
    },
    {
      title: 'Type',
      dataIndex: 'repoType',
      key: 'repoType',
      render: (type: string) => {
        const colors: Record<string, string> = {
          local: 'green',
          remote: 'orange',
          virtual: 'purple',
        }
        return <Tag color={colors[type] || 'default'}>{type}</Tag>
      },
    },
    {
      title: 'Artifacts',
      dataIndex: 'artifactCount',
      key: 'artifactCount',
    },
    {
      title: 'Public',
      dataIndex: 'isPublic',
      key: 'isPublic',
      render: (isPublic: boolean) => isPublic ? 'Yes' : 'No',
    },
    {
      title: 'Actions',
      key: 'actions',
      render: () => (
        <Space>
          <Button type="link">View</Button>
          <Button type="link">Edit</Button>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h1>Repositories</h1>
        <Button type="primary" icon={<PlusOutlined />}>
          Create Repository
        </Button>
      </div>
      <Table columns={columns} dataSource={repositories} rowKey="id" />
    </div>
  )
}

export default Repositories
