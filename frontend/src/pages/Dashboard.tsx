import { Card, Row, Col, Statistic } from 'antd'
import { DatabaseOutlined, FileOutlined, UserOutlined, CloudServerOutlined } from '@ant-design/icons'

const Dashboard = () => {
  // TODO: Fetch real stats from API
  const stats = {
    repositories: 12,
    artifacts: 1543,
    users: 45,
    edgeNodes: 3,
  }

  return (
    <div>
      <h1>Dashboard</h1>
      <Row gutter={16}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Repositories"
              value={stats.repositories}
              prefix={<DatabaseOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Artifacts"
              value={stats.artifacts}
              prefix={<FileOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Users"
              value={stats.users}
              prefix={<UserOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Edge Nodes"
              value={stats.edgeNodes}
              prefix={<CloudServerOutlined />}
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default Dashboard
