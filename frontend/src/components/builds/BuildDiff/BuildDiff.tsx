import React from 'react';
import { Card, Row, Col, Typography, Tag, Table, Divider, Empty, Space, Badge } from 'antd';
import {
  PlusCircleOutlined,
  MinusCircleOutlined,
  SwapOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
  ClockCircleOutlined,
  ExclamationCircleOutlined,
  StopOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type {
  BuildDiff as BuildDiffType,
  BuildSummary,
  ModuleDiff,
  DependencyChange,
  BuildDependency,
  BuildStatus,
} from '../../../types';
import { colors } from '../../../styles/tokens';
import { formatFileSize } from '../../../utils';

const { Title, Text } = Typography;

export interface BuildDiffProps {
  buildA: BuildSummary;
  buildB: BuildSummary;
  diffResult: BuildDiffType;
}

// Use a shorter date format for build diff views
const formatDateShort = (dateString: string | undefined): string => {
  if (!dateString) return '-';
  const date = new Date(dateString);
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

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
      return null;
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

const getChangeStatusColor = (status: string): string => {
  switch (status) {
    case 'added':
      return 'success';
    case 'removed':
      return 'error';
    case 'modified':
      return 'warning';
    case 'unchanged':
      return 'default';
    default:
      return 'default';
  }
};

const getChangeStatusIcon = (status: string): React.ReactNode => {
  switch (status) {
    case 'added':
      return <PlusCircleOutlined style={{ color: colors.success }} />;
    case 'removed':
      return <MinusCircleOutlined style={{ color: colors.error }} />;
    case 'modified':
      return <SwapOutlined style={{ color: colors.warning }} />;
    default:
      return null;
  }
};


const BuildSummaryCard: React.FC<{ build: BuildSummary; label: string }> = ({ build, label }) => (
  <Card size="small" style={{ height: '100%' }}>
    <Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>
      {label}
    </Text>
    <div style={{ marginBottom: 8 }}>
      <Text strong style={{ fontSize: 16 }}>{build.project_name}</Text>
      <Text code style={{ marginLeft: 8 }}>#{build.build_number}</Text>
    </div>
    <Space direction="vertical" size={4}>
      <div>
        <Tag color={getStatusTagColor(build.status)}>
          {getStatusIcon(build.status)}
          {build.status.charAt(0).toUpperCase() + build.status.slice(1)}
        </Tag>
      </div>
      {build.branch && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          Branch: {build.branch}
        </Text>
      )}
      {build.commit_sha && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          Commit: <Text code style={{ fontSize: 11 }}>{build.commit_sha.substring(0, 8)}</Text>
        </Text>
      )}
      {build.completed_at && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          Completed: {formatDateShort(build.completed_at)}
        </Text>
      )}
    </Space>
  </Card>
);

const ModuleDiffsSection: React.FC<{ moduleDiffs: ModuleDiff[] }> = ({ moduleDiffs }) => {
  const filteredDiffs = moduleDiffs.filter((m) => m.status !== 'unchanged');

  if (filteredDiffs.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="No module changes between builds"
      />
    );
  }

  const columns: ColumnsType<ModuleDiff> = [
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <Space>
          {getChangeStatusIcon(status)}
          <Tag color={getChangeStatusColor(status)}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Tag>
        </Space>
      ),
    },
    {
      title: 'Module',
      dataIndex: 'module_name',
      key: 'module_name',
      render: (name: string) => <Text strong>{name}</Text>,
    },
    {
      title: 'Version Change',
      key: 'version',
      render: (_: unknown, record: ModuleDiff) => {
        if (record.status === 'added') {
          return <Text type="success">{record.version_to || '-'}</Text>;
        }
        if (record.status === 'removed') {
          return <Text delete type="danger">{record.version_from || '-'}</Text>;
        }
        if (record.version_from !== record.version_to) {
          return (
            <Space>
              <Text type="secondary">{record.version_from}</Text>
              <SwapOutlined />
              <Text type="success">{record.version_to}</Text>
            </Space>
          );
        }
        return <Text>{record.version_from || '-'}</Text>;
      },
    },
    {
      title: 'Artifact Changes',
      key: 'artifacts',
      render: (_: unknown, record: ModuleDiff) => {
        const added = record.artifact_changes.filter((a) => a.status === 'added').length;
        const removed = record.artifact_changes.filter((a) => a.status === 'removed').length;
        const modified = record.artifact_changes.filter((a) => a.status === 'modified').length;

        return (
          <Space>
            {added > 0 && <Badge count={`+${added}`} style={{ backgroundColor: colors.success }} />}
            {removed > 0 && <Badge count={`-${removed}`} style={{ backgroundColor: colors.error }} />}
            {modified > 0 && <Badge count={`~${modified}`} style={{ backgroundColor: colors.warning }} />}
            {added === 0 && removed === 0 && modified === 0 && <Text type="secondary">-</Text>}
          </Space>
        );
      },
    },
  ];

  return (
    <Table<ModuleDiff>
      columns={columns}
      dataSource={filteredDiffs}
      rowKey="module_name"
      pagination={false}
      size="small"
    />
  );
};

const DependencySection: React.FC<{
  added: BuildDependency[];
  removed: BuildDependency[];
  changed: DependencyChange[];
}> = ({ added, removed, changed }) => {
  if (added.length === 0 && removed.length === 0 && changed.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="No dependency changes between builds"
      />
    );
  }

  const addedColumns: ColumnsType<BuildDependency> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => (
        <Space>
          <PlusCircleOutlined style={{ color: colors.success }} />
          <Text>{name}</Text>
        </Space>
      ),
    },
    {
      title: 'Version',
      dataIndex: 'version',
      key: 'version',
      render: (version: string) => <Text code>{version}</Text>,
    },
    {
      title: 'Type',
      dataIndex: 'dependency_type',
      key: 'type',
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Scope',
      dataIndex: 'scope',
      key: 'scope',
      render: (scope: string) => <Text type="secondary">{scope}</Text>,
    },
  ];

  const removedColumns: ColumnsType<BuildDependency> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => (
        <Space>
          <MinusCircleOutlined style={{ color: colors.error }} />
          <Text delete>{name}</Text>
        </Space>
      ),
    },
    {
      title: 'Version',
      dataIndex: 'version',
      key: 'version',
      render: (version: string) => <Text code delete>{version}</Text>,
    },
    {
      title: 'Type',
      dataIndex: 'dependency_type',
      key: 'type',
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Scope',
      dataIndex: 'scope',
      key: 'scope',
      render: (scope: string) => <Text type="secondary">{scope}</Text>,
    },
  ];

  const changedColumns: ColumnsType<DependencyChange> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => (
        <Space>
          <SwapOutlined style={{ color: colors.warning }} />
          <Text>{name}</Text>
        </Space>
      ),
    },
    {
      title: 'Version Change',
      key: 'version',
      render: (_: unknown, record: DependencyChange) => (
        <Space>
          <Text code>{record.version_from}</Text>
          <SwapOutlined />
          <Text code type="success">{record.version_to}</Text>
        </Space>
      ),
    },
    {
      title: 'License Changed',
      dataIndex: 'license_changed',
      key: 'license',
      render: (changed: boolean) =>
        changed ? (
          <Tag color="warning">License Changed</Tag>
        ) : (
          <Text type="secondary">No</Text>
        ),
    },
  ];

  return (
    <div>
      {added.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <Title level={5} style={{ color: colors.success }}>
            <PlusCircleOutlined style={{ marginRight: 8 }} />
            Added Dependencies ({added.length})
          </Title>
          <Table<BuildDependency>
            columns={addedColumns}
            dataSource={added}
            rowKey="id"
            pagination={false}
            size="small"
          />
        </div>
      )}

      {removed.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <Title level={5} style={{ color: colors.error }}>
            <MinusCircleOutlined style={{ marginRight: 8 }} />
            Removed Dependencies ({removed.length})
          </Title>
          <Table<BuildDependency>
            columns={removedColumns}
            dataSource={removed}
            rowKey="id"
            pagination={false}
            size="small"
          />
        </div>
      )}

      {changed.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <Title level={5} style={{ color: colors.warning }}>
            <SwapOutlined style={{ marginRight: 8 }} />
            Changed Dependencies ({changed.length})
          </Title>
          <Table<DependencyChange>
            columns={changedColumns}
            dataSource={changed}
            rowKey="identifier"
            pagination={false}
            size="small"
          />
        </div>
      )}
    </div>
  );
};

export const BuildDiff: React.FC<BuildDiffProps> = ({
  buildA,
  buildB,
  diffResult,
}) => {
  const totalModuleChanges = diffResult.module_diffs.filter((m) => m.status !== 'unchanged').length;
  const totalDepChanges =
    diffResult.added_dependencies.length +
    diffResult.removed_dependencies.length +
    diffResult.changed_dependencies.length;

  return (
    <div style={{ padding: '16px 24px' }}>
      <Title level={4} style={{ marginBottom: 16 }}>
        Build Comparison
      </Title>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={24} md={12}>
          <BuildSummaryCard build={buildA} label="Previous Build" />
        </Col>
        <Col xs={24} md={12}>
          <BuildSummaryCard build={buildB} label="Current Build" />
        </Col>
      </Row>

      <Divider />

      <div style={{ marginBottom: 24 }}>
        <Title level={5} style={{ marginBottom: 16 }}>
          Module Differences
          {totalModuleChanges > 0 && (
            <Badge
              count={totalModuleChanges}
              style={{ marginLeft: 8 }}
            />
          )}
        </Title>
        <ModuleDiffsSection moduleDiffs={diffResult.module_diffs} />
      </div>

      <Divider />

      <div style={{ marginBottom: 24 }}>
        <Title level={5} style={{ marginBottom: 16 }}>
          Dependency Differences
          {totalDepChanges > 0 && (
            <Badge
              count={totalDepChanges}
              style={{ marginLeft: 8 }}
            />
          )}
        </Title>
        <DependencySection
          added={diffResult.added_dependencies}
          removed={diffResult.removed_dependencies}
          changed={diffResult.changed_dependencies}
        />
      </div>
    </div>
  );
};

export default BuildDiff;
