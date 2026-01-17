import React, { useMemo, useCallback } from 'react';
import { Table, Tag, Typography, Tooltip } from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
  ClockCircleOutlined,
  ExclamationCircleOutlined,
  StopOutlined,
  MinusCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType, TablePaginationConfig } from 'antd/es/table';
import type { Build, BuildStatus } from '../../../types';
import { colors } from '../../../styles/tokens';
import { formatDate, formatDuration } from '../../../utils';

const { Text } = Typography;

export interface BuildListProps {
  builds: Build[];
  loading?: boolean;
  onSelect?: (build: Build) => void;
  pagination?: {
    current: number;
    pageSize: number;
    total: number;
    onChange: (page: number, pageSize: number) => void;
  };
}

const getStatusIcon = (status: BuildStatus): React.ReactNode => {
  const iconStyle = { marginRight: 4 };
  switch (status) {
    case 'success':
      return <CheckCircleOutlined style={iconStyle} />;
    case 'failed':
      return <CloseCircleOutlined style={iconStyle} />;
    case 'running':
      return <SyncOutlined spin style={iconStyle} />;
    case 'pending':
    case 'queued':
      return <ClockCircleOutlined style={iconStyle} />;
    case 'cancelled':
      return <StopOutlined style={iconStyle} />;
    case 'unstable':
      return <ExclamationCircleOutlined style={iconStyle} />;
    default:
      return <MinusCircleOutlined style={iconStyle} />;
  }
};

const getStatusTagColor = (status: BuildStatus): string => {
  switch (status) {
    case 'success':
      return 'success';
    case 'failed':
      return 'error';
    case 'running':
      return 'processing';
    case 'pending':
    case 'queued':
      return 'default';
    case 'cancelled':
      return 'default';
    case 'unstable':
      return 'warning';
    default:
      return 'default';
  }
};

export const BuildList: React.FC<BuildListProps> = ({
  builds,
  loading = false,
  onSelect,
  pagination,
}) => {
  const handleRowClick = useCallback(
    (build: Build) => {
      if (onSelect) {
        onSelect(build);
      }
    },
    [onSelect]
  );

  const columns: ColumnsType<Build> = useMemo(
    () => [
      {
        title: 'Build Name',
        key: 'name',
        width: '25%',
        render: (_: unknown, record: Build) => (
          <div>
            <Text strong>{record.project_name}</Text>
            {record.branch && (
              <div>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {record.branch}
                </Text>
              </div>
            )}
          </div>
        ),
      },
      {
        title: 'Build Number',
        dataIndex: 'build_number',
        key: 'build_number',
        width: '12%',
        render: (buildNumber: string) => (
          <Text code>#{buildNumber}</Text>
        ),
      },
      {
        title: 'Started',
        dataIndex: 'started_at',
        key: 'started_at',
        width: '18%',
        render: (date: string | undefined) => (
          <Tooltip title={date ? new Date(date).toLocaleString() : undefined}>
            <Text type="secondary">{formatDate(date)}</Text>
          </Tooltip>
        ),
      },
      {
        title: 'Duration',
        dataIndex: 'duration_ms',
        key: 'duration',
        width: '12%',
        render: (duration: number | undefined) => (
          <Text>{formatDuration(duration)}</Text>
        ),
      },
      {
        title: 'Status',
        dataIndex: 'status',
        key: 'status',
        width: '15%',
        render: (status: BuildStatus) => (
          <Tag color={getStatusTagColor(status)}>
            {getStatusIcon(status)}
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Tag>
        ),
      },
      {
        title: 'Artifacts',
        dataIndex: 'artifact_count',
        key: 'artifacts',
        width: '10%',
        align: 'right',
        render: (count: number) => (
          <Text type="secondary">{count}</Text>
        ),
      },
    ],
    []
  );

  const tablePagination: TablePaginationConfig | false = pagination
    ? {
        current: pagination.current,
        pageSize: pagination.pageSize,
        total: pagination.total,
        onChange: pagination.onChange,
        showSizeChanger: true,
        showTotal: (total, range) =>
          `${range[0]}-${range[1]} of ${total} builds`,
        pageSizeOptions: ['10', '20', '50', '100'],
      }
    : false;

  return (
    <Table<Build>
      columns={columns}
      dataSource={builds}
      rowKey="id"
      loading={loading}
      pagination={tablePagination}
      onRow={(build) => ({
        onClick: () => handleRowClick(build),
        style: {
          cursor: onSelect ? 'pointer' : 'default',
        },
      })}
      size="middle"
      locale={{
        emptyText: 'No builds found',
      }}
      style={{
        backgroundColor: colors.bgContainer,
      }}
    />
  );
};

export default BuildList;
