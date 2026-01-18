import React, { useState, useEffect } from 'react';
import {
  Card,
  Typography,
  Space,
  Statistic,
  Row,
  Col,
  Table,
  Tag,
  Alert,
  Collapse,
  Button,
  Spin,
  Divider,
} from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  DownloadOutlined,
  FileTextOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { MigrationReport as MigrationReportType, MigrationJob } from '../../types/migration';
import { migrationApi } from '../../api/migration';

const { Title, Text, Paragraph } = Typography;
const { Panel } = Collapse;

interface MigrationReportProps {
  jobId: string;
}

interface ReportError {
  code: string;
  message: string;
  item_path?: string;
}

interface ReportWarning {
  code: string;
  message: string;
  item_path?: string;
}

interface SummaryStats {
  duration_seconds?: number;
  total_bytes_transferred?: number;
  repositories?: ItemStats;
  artifacts?: ItemStats;
  users?: ItemStats;
  groups?: ItemStats;
  permissions?: ItemStats;
}

interface ItemStats {
  total: number;
  migrated: number;
  failed: number;
  skipped: number;
}

const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const MigrationReport: React.FC<MigrationReportProps> = ({ jobId }) => {
  const [report, setReport] = useState<MigrationReportType | null>(null);
  const [job, setJob] = useState<MigrationJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadReport();
  }, [jobId]);

  const loadReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const [reportData, jobData] = await Promise.all([
        migrationApi.getMigrationReport(jobId),
        migrationApi.getMigration(jobId),
      ]);
      setReport(reportData);
      setJob(jobData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load report');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadHtml = () => {
    window.open(`/api/migrations/${jobId}/report?format=html`, '_blank');
  };

  const handleDownloadJson = async () => {
    try {
      const data = await migrationApi.getMigrationReport(jobId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `migration-report-${jobId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download report:', err);
    }
  };

  if (loading) {
    return (
      <Card>
        <div style={{ textAlign: 'center', padding: 40 }}>
          <Spin size="large" />
          <div style={{ marginTop: 16 }}>Loading report...</div>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <Alert
          type="error"
          message="Failed to load report"
          description={error}
          showIcon
        />
      </Card>
    );
  }

  if (!report) {
    return (
      <Card>
        <Alert
          type="info"
          message="Report Not Available"
          description="The migration report is not yet available. Reports are generated when a migration completes."
          showIcon
        />
      </Card>
    );
  }

  const summary = report.summary as SummaryStats;
  const errors = (report.errors || []) as ReportError[];
  const warnings = (report.warnings || []) as ReportWarning[];
  const recommendations = (report.recommendations || []) as string[];

  const isSuccess = job?.status === 'completed' && errors.length === 0;
  const hasWarnings = warnings.length > 0;
  const hasFailed = job?.status === 'failed' || errors.length > 0;

  const errorColumns: ColumnsType<ReportError> = [
    {
      title: 'Code',
      dataIndex: 'code',
      key: 'code',
      width: 150,
      render: (code: string) => <Tag color="red">{code}</Tag>,
    },
    {
      title: 'Message',
      dataIndex: 'message',
      key: 'message',
    },
    {
      title: 'Path',
      dataIndex: 'item_path',
      key: 'item_path',
      render: (path: string | undefined) =>
        path ? <Text code>{path}</Text> : '-',
    },
  ];

  const warningColumns: ColumnsType<ReportWarning> = [
    {
      title: 'Code',
      dataIndex: 'code',
      key: 'code',
      width: 150,
      render: (code: string) => <Tag color="orange">{code}</Tag>,
    },
    {
      title: 'Message',
      dataIndex: 'message',
      key: 'message',
    },
    {
      title: 'Path',
      dataIndex: 'item_path',
      key: 'item_path',
      render: (path: string | undefined) =>
        path ? <Text code>{path}</Text> : '-',
    },
  ];

  const renderItemStats = (label: string, stats?: ItemStats) => {
    if (!stats) return null;
    return (
      <Card size="small" title={label}>
        <Row gutter={16}>
          <Col span={6}>
            <Statistic title="Total" value={stats.total} />
          </Col>
          <Col span={6}>
            <Statistic
              title="Migrated"
              value={stats.migrated}
              valueStyle={{ color: '#52c41a' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Failed"
              value={stats.failed}
              valueStyle={{ color: stats.failed > 0 ? '#ff4d4f' : undefined }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Skipped"
              value={stats.skipped}
              valueStyle={{ color: stats.skipped > 0 ? '#faad14' : undefined }}
            />
          </Col>
        </Row>
      </Card>
    );
  };

  return (
    <Card>
      <Space direction="vertical" style={{ width: '100%' }} size="large">
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Space>
            <FileTextOutlined style={{ fontSize: 24 }} />
            <Title level={4} style={{ margin: 0 }}>Migration Report</Title>
          </Space>
          <Space>
            <Button icon={<DownloadOutlined />} onClick={handleDownloadJson}>
              Download JSON
            </Button>
            <Button icon={<DownloadOutlined />} onClick={handleDownloadHtml}>
              Download HTML
            </Button>
          </Space>
        </div>

        {/* Overall Status */}
        <Alert
          type={isSuccess ? 'success' : hasFailed ? 'error' : 'warning'}
          message={
            isSuccess ? 'Migration Completed Successfully' :
            hasFailed ? 'Migration Completed with Errors' :
            'Migration Completed with Warnings'
          }
          icon={
            isSuccess ? <CheckCircleOutlined /> :
            hasFailed ? <CloseCircleOutlined /> :
            <ExclamationCircleOutlined />
          }
          showIcon
        />

        {/* Summary Stats */}
        <Row gutter={16}>
          <Col span={8}>
            <Card size="small">
              <Statistic
                title="Duration"
                value={summary.duration_seconds ? formatDuration(summary.duration_seconds) : '-'}
              />
            </Card>
          </Col>
          <Col span={8}>
            <Card size="small">
              <Statistic
                title="Data Transferred"
                value={summary.total_bytes_transferred ? formatBytes(summary.total_bytes_transferred) : '-'}
              />
            </Card>
          </Col>
          <Col span={8}>
            <Card size="small">
              <Statistic
                title="Generated"
                value={new Date(report.generated_at).toLocaleString()}
              />
            </Card>
          </Col>
        </Row>

        {/* Item Statistics */}
        <div>
          <Title level={5}>Migration Summary</Title>
          <Space direction="vertical" style={{ width: '100%' }}>
            {renderItemStats('Repositories', summary.repositories)}
            {renderItemStats('Artifacts', summary.artifacts)}
            {renderItemStats('Users', summary.users)}
            {renderItemStats('Groups', summary.groups)}
            {renderItemStats('Permissions', summary.permissions)}
          </Space>
        </div>

        <Divider />

        {/* Errors */}
        {errors.length > 0 && (
          <Collapse defaultActiveKey={['errors']}>
            <Panel
              header={
                <Space>
                  <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
                  <span>Errors ({errors.length})</span>
                </Space>
              }
              key="errors"
            >
              <Table
                columns={errorColumns}
                dataSource={errors}
                rowKey={(_, index) => `error-${index}`}
                size="small"
                pagination={{ pageSize: 10 }}
              />
            </Panel>
          </Collapse>
        )}

        {/* Warnings */}
        {warnings.length > 0 && (
          <Collapse>
            <Panel
              header={
                <Space>
                  <ExclamationCircleOutlined style={{ color: '#faad14' }} />
                  <span>Warnings ({warnings.length})</span>
                </Space>
              }
              key="warnings"
            >
              <Table
                columns={warningColumns}
                dataSource={warnings}
                rowKey={(_, index) => `warning-${index}`}
                size="small"
                pagination={{ pageSize: 10 }}
              />
            </Panel>
          </Collapse>
        )}

        {/* Recommendations */}
        {recommendations.length > 0 && (
          <div>
            <Title level={5}>Recommendations</Title>
            <ul>
              {recommendations.map((rec, index) => (
                <li key={index}><Paragraph>{rec}</Paragraph></li>
              ))}
            </ul>
          </div>
        )}
      </Space>
    </Card>
  );
};

export default MigrationReport;
