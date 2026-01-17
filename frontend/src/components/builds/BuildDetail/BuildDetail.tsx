import React from 'react';
import { Tabs, Button, Space, Typography, Divider, Tag, Table, Descriptions, Empty, Badge } from 'antd';
import {
  SwapOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
  ClockCircleOutlined,
  ExclamationCircleOutlined,
  StopOutlined,
  MinusCircleOutlined,
  FileOutlined,
  BugOutlined,
  SettingOutlined,
  InfoCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type {
  BuildDetail as BuildDetailType,
  BuildModuleArtifact,
  BuildIssue,
  BuildStatus,
} from '../../../types';
import { formatDate, formatDuration, formatFileSize } from '../../../utils';

const { Title, Text } = Typography;

export interface BuildDetailProps {
  build: BuildDetailType;
  artifacts?: BuildModuleArtifact[];
  onCompare?: (build: BuildDetailType) => void;
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

const getSeverityColor = (severity: BuildIssue['severity']): string => {
  switch (severity) {
    case 'critical':
      return 'red';
    case 'high':
      return 'orange';
    case 'medium':
      return 'gold';
    case 'low':
      return 'blue';
    case 'info':
      return 'default';
    default:
      return 'default';
  }
};

const OverviewTab: React.FC<{ build: BuildDetailType }> = ({ build }) => (
  <Descriptions
    bordered
    column={{ xs: 1, sm: 2, md: 2, lg: 2 }}
    size="small"
  >
    <Descriptions.Item label="Project Name">{build.project_name}</Descriptions.Item>
    <Descriptions.Item label="Build Number">#{build.build_number}</Descriptions.Item>
    <Descriptions.Item label="Status">
      <Tag color={getStatusTagColor(build.status)}>
        {getStatusIcon(build.status)}
        {build.status.charAt(0).toUpperCase() + build.status.slice(1)}
      </Tag>
    </Descriptions.Item>
    <Descriptions.Item label="Duration">{formatDuration(build.duration_ms)}</Descriptions.Item>
    <Descriptions.Item label="Started">{formatDate(build.started_at)}</Descriptions.Item>
    <Descriptions.Item label="Completed">{formatDate(build.completed_at)}</Descriptions.Item>
    <Descriptions.Item label="Triggered By">{build.triggered_by || '-'}</Descriptions.Item>
    <Descriptions.Item label="Trigger Source">{build.trigger_source || '-'}</Descriptions.Item>
    <Descriptions.Item label="Branch">{build.branch || '-'}</Descriptions.Item>
    <Descriptions.Item label="Commit">
      {build.commit_sha ? (
        <Text code style={{ fontSize: 12 }}>{build.commit_sha.substring(0, 8)}</Text>
      ) : (
        '-'
      )}
    </Descriptions.Item>
    <Descriptions.Item label="Modules">{build.module_count}</Descriptions.Item>
    <Descriptions.Item label="Artifacts">
      {build.artifact_count} ({formatFileSize(build.artifact_size_bytes)})
    </Descriptions.Item>
  </Descriptions>
);

const ArtifactsTab: React.FC<{ build: BuildDetailType; artifacts?: BuildModuleArtifact[] }> = ({
  build,
  artifacts,
}) => {
  const allArtifacts = artifacts || build.modules.flatMap((m) => m.artifacts);

  const columns: ColumnsType<BuildModuleArtifact> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => (
        <Space>
          <FileOutlined />
          <Text>{name}</Text>
        </Space>
      ),
    },
    {
      title: 'Path',
      dataIndex: 'path',
      key: 'path',
      ellipsis: true,
      render: (path: string) => (
        <Text type="secondary" style={{ fontSize: 12 }}>{path}</Text>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Size',
      dataIndex: 'size_bytes',
      key: 'size',
      width: 100,
      align: 'right',
      render: (size: number) => <Text>{formatFileSize(size)}</Text>,
    },
  ];

  if (allArtifacts.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="No artifacts produced by this build"
      />
    );
  }

  return (
    <Table<BuildModuleArtifact>
      columns={columns}
      dataSource={allArtifacts}
      rowKey="id"
      pagination={{
        pageSize: 10,
        showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} artifacts`,
      }}
      size="small"
    />
  );
};

const IssuesTab: React.FC<{ build: BuildDetailType }> = ({ build }) => {
  const columns: ColumnsType<BuildIssue> = [
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: BuildIssue['severity']) => (
        <Tag color={getSeverityColor(severity)}>
          {severity.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'issue_type',
      key: 'issue_type',
      width: 120,
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Title',
      dataIndex: 'title',
      key: 'title',
      render: (title: string, record: BuildIssue) => (
        <div>
          <Text strong>{title}</Text>
          {record.file_path && (
            <div>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {record.file_path}
                {record.line_number && `:${record.line_number}`}
              </Text>
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (description: string) => (
        <Text type="secondary">{description}</Text>
      ),
    },
  ];

  if (build.all_issues.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="No issues found in this build"
      />
    );
  }

  return (
    <Table<BuildIssue>
      columns={columns}
      dataSource={build.all_issues}
      rowKey="id"
      pagination={{
        pageSize: 10,
        showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} issues`,
      }}
      size="small"
    />
  );
};

const EnvironmentTab: React.FC<{ build: BuildDetailType }> = ({ build }) => {
  const { environment } = build;

  if (!environment) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="No environment information available"
      />
    );
  }

  const envVariables = Object.entries(environment.variables || {});

  return (
    <div>
      <Descriptions
        bordered
        column={{ xs: 1, sm: 2 }}
        size="small"
        style={{ marginBottom: 24 }}
      >
        <Descriptions.Item label="Operating System">{environment.os || '-'}</Descriptions.Item>
        <Descriptions.Item label="Architecture">{environment.arch || '-'}</Descriptions.Item>
        <Descriptions.Item label="Build Tool">{environment.build_tool || '-'}</Descriptions.Item>
        <Descriptions.Item label="Build Tool Version">
          {environment.build_tool_version || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="Runtime Version">
          {environment.runtime_version || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="CI System">{environment.ci_system || '-'}</Descriptions.Item>
      </Descriptions>

      {envVariables.length > 0 && (
        <>
          <Title level={5} style={{ marginTop: 16, marginBottom: 8 }}>
            Environment Variables
          </Title>
          <Descriptions bordered column={1} size="small">
            {envVariables.map(([key, value]) => (
              <Descriptions.Item key={key} label={key}>
                <Text code>{value}</Text>
              </Descriptions.Item>
            ))}
          </Descriptions>
        </>
      )}
    </div>
  );
};

export const BuildDetail: React.FC<BuildDetailProps> = ({
  build,
  artifacts,
  onCompare,
}) => {
  const handleCompare = () => {
    if (onCompare) {
      onCompare(build);
    }
  };

  const issueCount = build.all_issues.length;
  const artifactCount = build.artifact_count || build.modules.reduce((acc, m) => acc + m.artifacts.length, 0);

  const tabItems = [
    {
      key: 'overview',
      label: (
        <Space>
          <InfoCircleOutlined />
          Overview
        </Space>
      ),
      children: <OverviewTab build={build} />,
    },
    {
      key: 'artifacts',
      label: (
        <Space>
          <FileOutlined />
          Artifacts
          <Badge count={artifactCount} style={{ marginLeft: 4 }} showZero />
        </Space>
      ),
      children: <ArtifactsTab build={build} artifacts={artifacts} />,
    },
    {
      key: 'issues',
      label: (
        <Space>
          <BugOutlined />
          Issues
          <Badge count={issueCount} style={{ marginLeft: 4 }} showZero />
        </Space>
      ),
      children: <IssuesTab build={build} />,
    },
    {
      key: 'environment',
      label: (
        <Space>
          <SettingOutlined />
          Environment
        </Space>
      ),
      children: <EnvironmentTab build={build} />,
    },
  ];

  return (
    <div style={{ padding: '16px 24px' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: 16,
        }}
      >
        <div>
          <Space align="center" style={{ marginBottom: 4 }}>
            <Title level={4} style={{ margin: 0 }}>
              {build.project_name}
            </Title>
            <Text code style={{ fontSize: 14 }}>#{build.build_number}</Text>
            <Tag color={getStatusTagColor(build.status)}>
              {getStatusIcon(build.status)}
              {build.status.charAt(0).toUpperCase() + build.status.slice(1)}
            </Tag>
          </Space>
          {build.branch && (
            <div>
              <Text type="secondary" style={{ fontSize: 13 }}>
                Branch: {build.branch}
              </Text>
            </div>
          )}
        </div>
        <Space>
          {onCompare && (
            <Button icon={<SwapOutlined />} onClick={handleCompare}>
              Compare with Previous
            </Button>
          )}
        </Space>
      </div>

      <Divider style={{ margin: '16px 0' }} />

      <Tabs
        defaultActiveKey="overview"
        items={tabItems}
        style={{
          minHeight: 300,
        }}
      />
    </div>
  );
};

export default BuildDetail;
