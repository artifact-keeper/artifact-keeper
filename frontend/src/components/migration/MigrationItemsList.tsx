import React, { useState, useEffect } from 'react';
import {
  Table,
  Tag,
  Space,
  Typography,
  Input,
  Select,
  Button,
  Tooltip,
  Card,
} from 'antd';
import {
  SearchOutlined,
  ReloadOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  SyncOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { MigrationItem } from '../../types/migration';
import { migrationApi } from '../../api/migration';

const { Text } = Typography;
const { Option } = Select;

interface MigrationItemsListProps {
  jobId: string;
  autoRefresh?: boolean;
  refreshInterval?: number;
}

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'pending', label: 'Pending' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'skipped', label: 'Skipped' },
];

const TYPE_OPTIONS = [
  { value: '', label: 'All Types' },
  { value: 'repository', label: 'Repository' },
  { value: 'artifact', label: 'Artifact' },
  { value: 'user', label: 'User' },
  { value: 'group', label: 'Group' },
  { value: 'permission', label: 'Permission' },
];

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'completed':
      return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
    case 'failed':
      return <CloseCircleOutlined style={{ color: '#ff4d4f' }} />;
    case 'skipped':
      return <ExclamationCircleOutlined style={{ color: '#faad14' }} />;
    case 'in_progress':
      return <SyncOutlined spin style={{ color: '#1890ff' }} />;
    case 'pending':
      return <ClockCircleOutlined style={{ color: '#d9d9d9' }} />;
    default:
      return null;
  }
};

const getStatusColor = (status: string): string => {
  switch (status) {
    case 'completed':
      return 'success';
    case 'failed':
      return 'error';
    case 'skipped':
      return 'warning';
    case 'in_progress':
      return 'processing';
    case 'pending':
      return 'default';
    default:
      return 'default';
  }
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const MigrationItemsList: React.FC<MigrationItemsListProps> = ({
  jobId,
  autoRefresh = false,
  refreshInterval = 5000,
}) => {
  const [items, setItems] = useState<MigrationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 50,
    total: 0,
  });
  const [filters, setFilters] = useState({
    status: '',
    itemType: '',
    search: '',
  });

  const loadItems = async (page = 1, pageSize = 50) => {
    setLoading(true);
    try {
      const result = await migrationApi.listMigrationItems(jobId, {
        page,
        per_page: pageSize,
        status: filters.status || undefined,
        item_type: filters.itemType || undefined,
      });
      setItems(result.items);
      if (result.pagination) {
        setPagination({
          current: result.pagination.page,
          pageSize: result.pagination.per_page,
          total: result.pagination.total,
        });
      }
    } catch (error) {
      console.error('Failed to load migration items:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadItems(pagination.current, pagination.pageSize);
  }, [jobId, filters.status, filters.itemType]);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadItems(pagination.current, pagination.pageSize);
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval, pagination.current, pagination.pageSize]);

  const handleTableChange = (newPagination: { current?: number; pageSize?: number }) => {
    loadItems(newPagination.current, newPagination.pageSize);
  };

  const filteredItems = items.filter((item) => {
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      return (
        item.source_path.toLowerCase().includes(searchLower) ||
        (item.target_path?.toLowerCase().includes(searchLower))
      );
    }
    return true;
  });

  const columns: ColumnsType<MigrationItem> = [
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => (
        <Tag icon={getStatusIcon(status)} color={getStatusColor(status)}>
          {status}
        </Tag>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'item_type',
      key: 'item_type',
      width: 100,
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Source Path',
      dataIndex: 'source_path',
      key: 'source_path',
      ellipsis: true,
      render: (path: string) => (
        <Tooltip title={path}>
          <Text code style={{ fontSize: 12 }}>{path}</Text>
        </Tooltip>
      ),
    },
    {
      title: 'Target Path',
      dataIndex: 'target_path',
      key: 'target_path',
      ellipsis: true,
      render: (path: string | null) =>
        path ? (
          <Tooltip title={path}>
            <Text code style={{ fontSize: 12 }}>{path}</Text>
          </Tooltip>
        ) : (
          <Text type="secondary">-</Text>
        ),
    },
    {
      title: 'Size',
      dataIndex: 'size_bytes',
      key: 'size_bytes',
      width: 100,
      align: 'right',
      render: (bytes: number) => formatBytes(bytes),
    },
    {
      title: 'Retries',
      dataIndex: 'retry_count',
      key: 'retry_count',
      width: 80,
      align: 'center',
      render: (count: number) =>
        count > 0 ? <Text type="warning">{count}</Text> : '-',
    },
    {
      title: 'Error',
      dataIndex: 'error_message',
      key: 'error_message',
      width: 200,
      ellipsis: true,
      render: (error: string | null) =>
        error ? (
          <Tooltip title={error}>
            <Text type="danger" style={{ fontSize: 12 }}>{error}</Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
  ];

  const summary = {
    total: items.length,
    completed: items.filter((i) => i.status === 'completed').length,
    failed: items.filter((i) => i.status === 'failed').length,
    skipped: items.filter((i) => i.status === 'skipped').length,
    inProgress: items.filter((i) => i.status === 'in_progress').length,
    pending: items.filter((i) => i.status === 'pending').length,
  };

  return (
    <Card
      title="Migration Items"
      extra={
        <Button icon={<ReloadOutlined />} onClick={() => loadItems()} loading={loading}>
          Refresh
        </Button>
      }
    >
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        {/* Filters */}
        <Space wrap>
          <Input
            placeholder="Search paths..."
            prefix={<SearchOutlined />}
            value={filters.search}
            onChange={(e) => setFilters({ ...filters, search: e.target.value })}
            style={{ width: 250 }}
            allowClear
          />
          <Select
            value={filters.status}
            onChange={(value) => setFilters({ ...filters, status: value })}
            style={{ width: 150 }}
          >
            {STATUS_OPTIONS.map((opt) => (
              <Option key={opt.value} value={opt.value}>
                {opt.label}
              </Option>
            ))}
          </Select>
          <Select
            value={filters.itemType}
            onChange={(value) => setFilters({ ...filters, itemType: value })}
            style={{ width: 150 }}
          >
            {TYPE_OPTIONS.map((opt) => (
              <Option key={opt.value} value={opt.value}>
                {opt.label}
              </Option>
            ))}
          </Select>
        </Space>

        {/* Summary */}
        <Space split={<span style={{ color: '#d9d9d9' }}>|</span>}>
          <Text>
            <CheckCircleOutlined style={{ color: '#52c41a' }} /> {summary.completed} completed
          </Text>
          <Text>
            <CloseCircleOutlined style={{ color: '#ff4d4f' }} /> {summary.failed} failed
          </Text>
          <Text>
            <ExclamationCircleOutlined style={{ color: '#faad14' }} /> {summary.skipped} skipped
          </Text>
          <Text>
            <SyncOutlined style={{ color: '#1890ff' }} /> {summary.inProgress} in progress
          </Text>
          <Text>
            <ClockCircleOutlined style={{ color: '#d9d9d9' }} /> {summary.pending} pending
          </Text>
        </Space>

        {/* Table */}
        <Table
          columns={columns}
          dataSource={filteredItems}
          rowKey="id"
          loading={loading}
          size="small"
          pagination={{
            ...pagination,
            showSizeChanger: true,
            showTotal: (total) => `${total} items`,
          }}
          onChange={handleTableChange}
          scroll={{ x: 1000 }}
        />
      </Space>
    </Card>
  );
};

export default MigrationItemsList;
