import React, { useState, useEffect } from 'react';
import { Tabs, Typography, Card, Table, Button, Space, Tag, Modal, message } from 'antd';
import {
  SwapOutlined,
  CloudDownloadOutlined,
  PlusOutlined,
  PlayCircleOutlined,
  PauseCircleOutlined,
  StopOutlined,
  ReloadOutlined,
  DeleteOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { MigrationWizard, ImportFromExport } from '../../../components/migration';
import type { MigrationJob, SourceConnection } from '../../../types/migration';
import { migrationApi } from '../../../api/migration';

const { Title, Text } = Typography;

const getStatusColor = (status: string): string => {
  switch (status) {
    case 'pending':
      return 'default';
    case 'ready':
      return 'cyan';
    case 'assessing':
      return 'processing';
    case 'running':
      return 'blue';
    case 'paused':
      return 'orange';
    case 'completed':
      return 'green';
    case 'failed':
      return 'red';
    case 'cancelled':
      return 'default';
    default:
      return 'default';
  }
};

const MigrationPage: React.FC = () => {
  const [showWizard, setShowWizard] = useState(false);
  const [jobs, setJobs] = useState<MigrationJob[]>([]);
  const [connections, setConnections] = useState<SourceConnection[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [jobsData, connectionsData] = await Promise.all([
        migrationApi.listMigrations(),
        migrationApi.listConnections(),
      ]);
      setJobs(jobsData.items);
      setConnections(connectionsData);
    } catch (error) {
      console.error('Failed to load migration data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePauseMigration = async (jobId: string) => {
    try {
      await migrationApi.pauseMigration(jobId);
      message.success('Migration paused');
      loadData();
    } catch (error) {
      message.error('Failed to pause migration');
    }
  };

  const handleResumeMigration = async (jobId: string) => {
    try {
      await migrationApi.resumeMigration(jobId);
      message.success('Migration resumed');
      loadData();
    } catch (error) {
      message.error('Failed to resume migration');
    }
  };

  const handleCancelMigration = async (jobId: string) => {
    try {
      await migrationApi.cancelMigration(jobId);
      message.success('Migration cancelled');
      loadData();
    } catch (error) {
      message.error('Failed to cancel migration');
    }
  };

  const handleDeleteMigration = async (jobId: string) => {
    Modal.confirm({
      title: 'Delete Migration Job',
      content: 'Are you sure you want to delete this migration job? This action cannot be undone.',
      okText: 'Delete',
      okType: 'danger',
      onOk: async () => {
        try {
          await migrationApi.deleteMigration(jobId);
          message.success('Migration deleted');
          loadData();
        } catch (error) {
          message.error('Failed to delete migration');
        }
      },
    });
  };

  const jobColumns: ColumnsType<MigrationJob> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 100,
      render: (id: string) => <Text code>{id.slice(0, 8)}...</Text>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => <Tag color={getStatusColor(status)}>{status}</Tag>,
    },
    {
      title: 'Progress',
      key: 'progress',
      width: 150,
      render: (_: unknown, record: MigrationJob) => (
        <Space direction="vertical" size={0}>
          <Text>{(record.progress_percent ?? 0).toFixed(1)}%</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {record.completed_items}/{record.total_items} items
          </Text>
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'job_type',
      key: 'job_type',
      width: 100,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 200,
      render: (_: unknown, record: MigrationJob) => (
        <Space>
          {record.status === 'running' && (
            <Button
              size="small"
              icon={<PauseCircleOutlined />}
              onClick={() => handlePauseMigration(record.id)}
            >
              Pause
            </Button>
          )}
          {record.status === 'paused' && (
            <Button
              size="small"
              icon={<PlayCircleOutlined />}
              onClick={() => handleResumeMigration(record.id)}
            >
              Resume
            </Button>
          )}
          {['running', 'paused', 'pending', 'ready'].includes(record.status) && (
            <Button
              size="small"
              icon={<StopOutlined />}
              danger
              onClick={() => handleCancelMigration(record.id)}
            >
              Cancel
            </Button>
          )}
          {['completed', 'failed', 'cancelled'].includes(record.status) && (
            <Button
              size="small"
              icon={<DeleteOutlined />}
              danger
              onClick={() => handleDeleteMigration(record.id)}
            >
              Delete
            </Button>
          )}
        </Space>
      ),
    },
  ];

  const connectionColumns: ColumnsType<SourceConnection> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      render: (url: string) => <Text code>{url}</Text>,
    },
    {
      title: 'Auth Type',
      dataIndex: 'auth_type',
      key: 'auth_type',
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Verified',
      dataIndex: 'verified_at',
      key: 'verified_at',
      render: (date: string | null) =>
        date ? (
          <Tag color="green">Verified</Tag>
        ) : (
          <Tag color="warning">Not Verified</Tag>
        ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: unknown, record: SourceConnection) => (
        <Button
          size="small"
          icon={<DeleteOutlined />}
          danger
          onClick={async () => {
            try {
              await migrationApi.deleteConnection(record.id);
              message.success('Connection deleted');
              loadData();
            } catch (error) {
              message.error('Failed to delete connection');
            }
          }}
        >
          Delete
        </Button>
      ),
    },
  ];

  const tabItems = [
    {
      key: 'live',
      label: (
        <span>
          <SwapOutlined />
          Live Migration
        </span>
      ),
      children: showWizard ? (
        <MigrationWizard
          onComplete={() => {
            setShowWizard(false);
            loadData();
          }}
          onCancel={() => setShowWizard(false)}
        />
      ) : (
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <Card
            title="Migration Jobs"
            extra={
              <Space>
                <Button icon={<ReloadOutlined />} onClick={loadData}>
                  Refresh
                </Button>
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => setShowWizard(true)}
                >
                  New Migration
                </Button>
              </Space>
            }
          >
            <Table
              columns={jobColumns}
              dataSource={jobs}
              rowKey="id"
              loading={loading}
              pagination={{ pageSize: 10 }}
            />
          </Card>

          <Card
            title="Source Connections"
            extra={
              <Button
                icon={<UnorderedListOutlined />}
                onClick={() => setShowWizard(true)}
              >
                Add Connection
              </Button>
            }
          >
            <Table
              columns={connectionColumns}
              dataSource={connections}
              rowKey="id"
              loading={loading}
              pagination={{ pageSize: 5 }}
            />
          </Card>
        </Space>
      ),
    },
    {
      key: 'import',
      label: (
        <span>
          <CloudDownloadOutlined />
          Import from Export
        </span>
      ),
      children: (
        <ImportFromExport
          onComplete={() => {
            loadData();
            message.success('Import completed successfully');
          }}
        />
      ),
    },
  ];

  return (
    <div style={{ padding: '24px' }}>
      <Title level={2}>Migration from Artifactory</Title>
      <p style={{ marginBottom: '24px' }}>
        Migrate your repositories, artifacts, users, and permissions from JFrog
        Artifactory to Artifact Keeper.
      </p>
      <Tabs defaultActiveKey="live" items={tabItems} />
    </div>
  );
};

export default MigrationPage;
