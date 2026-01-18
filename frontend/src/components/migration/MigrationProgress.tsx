import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Card,
  Progress,
  Typography,
  Space,
  Statistic,
  Row,
  Col,
  Tag,
  Button,
  Alert,
  Descriptions,
} from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
  SyncOutlined,
  StopOutlined,
} from '@ant-design/icons';
import type { MigrationJob } from '../../types/migration';
import { migrationApi } from '../../api/migration';

const { Title, Text } = Typography;

interface MigrationProgressProps {
  jobId: string;
  onComplete?: (job: MigrationJob) => void;
  onError?: (error: string) => void;
}

interface ProgressData {
  job_id: string;
  status: string;
  total_items: number;
  completed_items: number;
  failed_items: number;
  skipped_items: number;
  total_bytes: number;
  transferred_bytes: number;
  progress_percent: number;
}

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

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'running':
      return <SyncOutlined spin />;
    case 'paused':
      return <PauseCircleOutlined />;
    case 'completed':
      return <CheckCircleOutlined />;
    case 'failed':
      return <CloseCircleOutlined />;
    case 'cancelled':
      return <StopOutlined />;
    default:
      return null;
  }
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const formatDuration = (startTime: string | null): string => {
  if (!startTime) return '-';
  const start = new Date(startTime);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - start.getTime()) / 1000);

  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
};

export const MigrationProgress: React.FC<MigrationProgressProps> = ({
  jobId,
  onComplete,
  onError,
}) => {
  const [progress, setProgress] = useState<ProgressData | null>(null);
  const [job, setJob] = useState<MigrationJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);

  const connectSSE = useCallback(() => {
    const eventSource = migrationApi.streamProgress(jobId);
    eventSourceRef.current = eventSource;

    eventSource.onopen = () => {
      setConnected(true);
      setError(null);
    };

    eventSource.addEventListener('connected', (event: MessageEvent) => {
      console.log('SSE connected:', event.data);
    });

    eventSource.addEventListener('progress', (event: MessageEvent) => {
      try {
        const data: ProgressData = JSON.parse(event.data);
        setProgress(data);
      } catch (e: unknown) {
        console.error('Failed to parse progress data:', e);
      }
    });

    eventSource.addEventListener('complete', (event: MessageEvent) => {
      try {
        const data: ProgressData = JSON.parse(event.data);
        setProgress(data);
        eventSource.close();
        // Fetch full job details
        migrationApi.getMigration(jobId).then((job) => {
          setJob(job);
          onComplete?.(job);
        });
      } catch (e: unknown) {
        console.error('Failed to parse complete data:', e);
      }
    });

    eventSource.addEventListener('error', (event: MessageEvent) => {
      if (event.data) {
        try {
          const data = JSON.parse(event.data);
          setError(data.message || 'Unknown error');
          onError?.(data.message);
        } catch {
          // MessageEvent error, not our custom error event
        }
      }
    });

    eventSource.onerror = () => {
      setConnected(false);
      // Attempt to reconnect after 5 seconds
      setTimeout(() => {
        if (eventSourceRef.current?.readyState === EventSource.CLOSED) {
          connectSSE();
        }
      }, 5000);
    };
  }, [jobId, onComplete, onError]);

  useEffect(() => {
    // Fetch initial job data
    migrationApi.getMigration(jobId).then(setJob).catch(console.error);

    // Connect to SSE stream
    connectSSE();

    return () => {
      eventSourceRef.current?.close();
    };
  }, [jobId, connectSSE]);

  const handlePause = async () => {
    try {
      await migrationApi.pauseMigration(jobId);
      const updatedJob = await migrationApi.getMigration(jobId);
      setJob(updatedJob);
    } catch (error) {
      console.error('Failed to pause migration:', error);
    }
  };

  const handleResume = async () => {
    try {
      await migrationApi.resumeMigration(jobId);
      const updatedJob = await migrationApi.getMigration(jobId);
      setJob(updatedJob);
    } catch (error) {
      console.error('Failed to resume migration:', error);
    }
  };

  const handleCancel = async () => {
    try {
      await migrationApi.cancelMigration(jobId);
      const updatedJob = await migrationApi.getMigration(jobId);
      setJob(updatedJob);
    } catch (error) {
      console.error('Failed to cancel migration:', error);
    }
  };

  const currentStatus = progress?.status || job?.status || 'pending';
  const isRunning = currentStatus === 'running';
  const isPaused = currentStatus === 'paused';
  const isComplete = ['completed', 'failed', 'cancelled'].includes(currentStatus);

  const progressPercent = progress?.progress_percent || job?.progress_percent || 0;
  const completedItems = progress?.completed_items || job?.completed_items || 0;
  const failedItems = progress?.failed_items || job?.failed_items || 0;
  const skippedItems = progress?.skipped_items || job?.skipped_items || 0;
  const totalItems = progress?.total_items || job?.total_items || 0;
  const transferredBytes = progress?.transferred_bytes || job?.transferred_bytes || 0;
  const totalBytes = progress?.total_bytes || job?.total_bytes || 0;

  return (
    <Card>
      <Space direction="vertical" style={{ width: '100%' }} size="large">
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Space>
            <Title level={4} style={{ margin: 0 }}>Migration Progress</Title>
            <Tag icon={getStatusIcon(currentStatus)} color={getStatusColor(currentStatus)}>
              {currentStatus.toUpperCase()}
            </Tag>
            {!connected && isRunning && (
              <Tag color="warning">Reconnecting...</Tag>
            )}
          </Space>
          <Space>
            {isRunning && (
              <Button icon={<PauseCircleOutlined />} onClick={handlePause}>
                Pause
              </Button>
            )}
            {isPaused && (
              <Button type="primary" icon={<PlayCircleOutlined />} onClick={handleResume}>
                Resume
              </Button>
            )}
            {(isRunning || isPaused) && (
              <Button danger icon={<StopOutlined />} onClick={handleCancel}>
                Cancel
              </Button>
            )}
          </Space>
        </div>

        {/* Error Alert */}
        {error && (
          <Alert type="error" message={error} showIcon />
        )}

        {/* Main Progress */}
        <div>
          <Progress
            percent={Math.round(progressPercent)}
            status={
              currentStatus === 'failed' ? 'exception' :
              currentStatus === 'completed' ? 'success' :
              'active'
            }
            strokeWidth={20}
          />
        </div>

        {/* Statistics */}
        <Row gutter={16}>
          <Col span={6}>
            <Statistic
              title="Completed"
              value={completedItems}
              suffix={`/ ${totalItems}`}
              valueStyle={{ color: '#52c41a' }}
              prefix={<CheckCircleOutlined />}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Failed"
              value={failedItems}
              valueStyle={{ color: failedItems > 0 ? '#ff4d4f' : undefined }}
              prefix={<CloseCircleOutlined />}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Skipped"
              value={skippedItems}
              valueStyle={{ color: skippedItems > 0 ? '#faad14' : undefined }}
              prefix={<ExclamationCircleOutlined />}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Data Transferred"
              value={formatBytes(transferredBytes)}
              suffix={totalBytes > 0 ? `/ ${formatBytes(totalBytes)}` : ''}
            />
          </Col>
        </Row>

        {/* Details */}
        {job && (
          <Descriptions size="small" column={2}>
            <Descriptions.Item label="Job ID">
              <Text code>{job.id.slice(0, 8)}...</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Type">{job.job_type}</Descriptions.Item>
            <Descriptions.Item label="Started">
              {job.started_at ? new Date(job.started_at).toLocaleString() : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="Duration">
              {formatDuration(job.started_at)}
            </Descriptions.Item>
          </Descriptions>
        )}

        {/* Completion Message */}
        {isComplete && (
          <Alert
            type={currentStatus === 'completed' ? 'success' : currentStatus === 'failed' ? 'error' : 'warning'}
            message={
              currentStatus === 'completed' ? 'Migration Completed Successfully' :
              currentStatus === 'failed' ? 'Migration Failed' :
              'Migration Cancelled'
            }
            description={
              currentStatus === 'completed'
                ? `Successfully migrated ${completedItems} items. ${failedItems} failed, ${skippedItems} skipped.`
                : currentStatus === 'failed'
                ? job?.error_summary || 'An error occurred during migration.'
                : 'The migration was cancelled by the user.'
            }
            showIcon
          />
        )}
      </Space>
    </Card>
  );
};

export default MigrationProgress;
