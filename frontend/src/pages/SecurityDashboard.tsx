import { Card, Col, Row, Statistic, Table, Tag, Typography, Button, Spin, Empty } from 'antd';
import {
  SafetyCertificateOutlined,
  BugOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  ScanOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { securityApi } from '../api';
import type { RepoSecurityScore } from '../types/security';

const { Title } = Typography;

const gradeColors: Record<string, string> = {
  A: '#52c41a',
  B: '#73d13d',
  C: '#faad14',
  D: '#fa8c16',
  F: '#f5222d',
};

const gradeTag = (grade: string) => (
  <Tag
    color={gradeColors[grade] || '#d9d9d9'}
    style={{ fontSize: 16, fontWeight: 700, padding: '2px 12px' }}
  >
    {grade}
  </Tag>
);

export default function SecurityDashboard() {
  const { user } = useAuth();

  const { data: dashboard, isLoading: dashLoading } = useQuery({
    queryKey: ['security', 'dashboard'],
    queryFn: securityApi.getDashboard,
  });

  const { data: scores, isLoading: scoresLoading } = useQuery({
    queryKey: ['security', 'scores'],
    queryFn: securityApi.getAllScores,
  });

  if (!user?.is_admin) {
    return (
      <Card>
        <p>You must be an administrator to view security information.</p>
      </Card>
    );
  }

  const columns = [
    {
      title: 'Repository',
      dataIndex: 'repository_id',
      key: 'repository_id',
      render: (id: string) => <code>{id.slice(0, 8)}...</code>,
    },
    {
      title: 'Grade',
      dataIndex: 'grade',
      key: 'grade',
      render: (grade: string) => gradeTag(grade),
      sorter: (a: RepoSecurityScore, b: RepoSecurityScore) => a.score - b.score,
    },
    {
      title: 'Score',
      dataIndex: 'score',
      key: 'score',
      sorter: (a: RepoSecurityScore, b: RepoSecurityScore) => a.score - b.score,
      render: (score: number) => `${score}/100`,
    },
    {
      title: 'Critical',
      dataIndex: 'critical_count',
      key: 'critical',
      render: (count: number) =>
        count > 0 ? <Tag color="red">{count}</Tag> : <Tag color="green">0</Tag>,
    },
    {
      title: 'High',
      dataIndex: 'high_count',
      key: 'high',
      render: (count: number) =>
        count > 0 ? <Tag color="orange">{count}</Tag> : <Tag color="green">0</Tag>,
    },
    {
      title: 'Medium',
      dataIndex: 'medium_count',
      key: 'medium',
      render: (count: number) =>
        count > 0 ? <Tag color="gold">{count}</Tag> : <span>{count}</span>,
    },
    {
      title: 'Acknowledged',
      dataIndex: 'acknowledged_count',
      key: 'acknowledged',
    },
    {
      title: 'Last Scan',
      dataIndex: 'last_scan_at',
      key: 'last_scan_at',
      render: (val: string | null) =>
        val ? new Date(val).toLocaleDateString() : <Tag>Never</Tag>,
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={3} style={{ margin: 0 }}>
          <SafetyCertificateOutlined /> Security Dashboard
        </Title>
        <Link to="/security/scans">
          <Button type="primary" icon={<ScanOutlined />}>
            View All Scans
          </Button>
        </Link>
      </div>

      {dashLoading ? (
        <Spin size="large" />
      ) : dashboard ? (
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="Repos with Scanning"
                value={dashboard.repos_with_scanning}
                prefix={<CheckCircleOutlined />}
                valueStyle={{ color: '#52c41a' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="Total Scans"
                value={dashboard.total_scans}
                prefix={<ScanOutlined />}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="Open Findings"
                value={dashboard.total_findings}
                prefix={<BugOutlined />}
                valueStyle={{
                  color: dashboard.total_findings > 0 ? '#faad14' : '#52c41a',
                }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="Critical Findings"
                value={dashboard.critical_findings}
                prefix={<ExclamationCircleOutlined />}
                valueStyle={{
                  color: dashboard.critical_findings > 0 ? '#f5222d' : '#52c41a',
                }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="High Findings"
                value={dashboard.high_findings}
                prefix={<WarningOutlined />}
                valueStyle={{
                  color: dashboard.high_findings > 0 ? '#fa8c16' : '#52c41a',
                }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="Grade A Repos"
                value={dashboard.repos_grade_a}
                valueStyle={{ color: '#52c41a' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="Grade F Repos"
                value={dashboard.repos_grade_f}
                valueStyle={{
                  color: dashboard.repos_grade_f > 0 ? '#f5222d' : '#52c41a',
                }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="Policy Blocks"
                value={dashboard.policy_violations_blocked}
                prefix={<SafetyCertificateOutlined />}
              />
            </Card>
          </Col>
        </Row>
      ) : null}

      <Card title="Repository Security Scores" style={{ marginTop: 16 }}>
        {scoresLoading ? (
          <Spin />
        ) : scores && scores.length > 0 ? (
          <Table
            dataSource={scores}
            columns={columns}
            rowKey="id"
            pagination={{ pageSize: 20 }}
          />
        ) : (
          <Empty description="No security scores yet. Enable scanning on a repository to get started." />
        )}
      </Card>
    </div>
  );
}
