import React, { useCallback, useMemo, useState } from 'react';
import { Table, Button, Space, Typography, Tag, Tooltip } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  DownloadOutlined,
  SwapOutlined,
  CheckCircleOutlined,
  ExperimentOutlined,
} from '@ant-design/icons';
import type { PackageVersion } from '../../../types';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;

export interface VersionHistoryProps {
  versions: PackageVersion[];
  onSelect?: (version: PackageVersion) => void;
  selected?: string;
  onCompare?: (version1: PackageVersion, version2: PackageVersion) => void;
}

const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const size = bytes / Math.pow(k, i);

  return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
};

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

const formatRelativeTime = (dateString: string): string => {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) {
    return 'today';
  } else if (diffDays === 1) {
    return 'yesterday';
  } else if (diffDays < 7) {
    return `${diffDays} days ago`;
  } else if (diffDays < 30) {
    const weeks = Math.floor(diffDays / 7);
    return `${weeks} week${weeks === 1 ? '' : 's'} ago`;
  } else if (diffDays < 365) {
    const months = Math.floor(diffDays / 30);
    return `${months} month${months === 1 ? '' : 's'} ago`;
  } else {
    const years = Math.floor(diffDays / 365);
    return `${years} year${years === 1 ? '' : 's'} ago`;
  }
};

export const VersionHistory: React.FC<VersionHistoryProps> = ({
  versions,
  onSelect,
  selected,
  onCompare,
}) => {
  const [compareVersions, setCompareVersions] = useState<string[]>([]);

  const handleRowClick = useCallback(
    (version: PackageVersion) => {
      if (onSelect) {
        onSelect(version);
      }
    },
    [onSelect]
  );

  const handleCompareToggle = useCallback(
    (versionId: string, e: React.MouseEvent) => {
      e.stopPropagation();
      setCompareVersions((prev) => {
        if (prev.includes(versionId)) {
          return prev.filter((id) => id !== versionId);
        }
        if (prev.length >= 2) {
          return [prev[1], versionId];
        }
        return [...prev, versionId];
      });
    },
    []
  );

  const handleCompare = useCallback(() => {
    if (onCompare && compareVersions.length === 2) {
      const version1 = versions.find((v) => v.id === compareVersions[0]);
      const version2 = versions.find((v) => v.id === compareVersions[1]);
      if (version1 && version2) {
        onCompare(version1, version2);
      }
    }
  }, [onCompare, compareVersions, versions]);

  const columns: ColumnsType<PackageVersion> = useMemo(
    () => [
      {
        title: 'Version',
        dataIndex: 'version',
        key: 'version',
        render: (version: string, record) => (
          <Space>
            <Text strong>{version}</Text>
            {record.is_latest && (
              <Tag color="green" icon={<CheckCircleOutlined />}>
                Latest
              </Tag>
            )}
            {record.is_prerelease && (
              <Tag color="orange" icon={<ExperimentOutlined />}>
                Pre-release
              </Tag>
            )}
          </Space>
        ),
      },
      {
        title: 'Size',
        dataIndex: 'size_bytes',
        key: 'size_bytes',
        width: 100,
        align: 'right',
        render: (bytes: number) => (
          <Text type="secondary">{formatFileSize(bytes)}</Text>
        ),
      },
      {
        title: 'Downloads',
        dataIndex: 'download_count',
        key: 'download_count',
        width: 120,
        align: 'right',
        render: (count: number) => (
          <Space size={4}>
            <DownloadOutlined style={{ color: colors.textTertiary }} />
            <Text type="secondary">{count.toLocaleString()}</Text>
          </Space>
        ),
      },
      {
        title: 'Published',
        dataIndex: 'created_at',
        key: 'created_at',
        width: 160,
        render: (dateString: string) => (
          <Tooltip title={new Date(dateString).toLocaleString()}>
            <Space orientation="vertical" size={0}>
              <Text>{formatDate(dateString)}</Text>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {formatRelativeTime(dateString)}
              </Text>
            </Space>
          </Tooltip>
        ),
      },
      {
        title: 'Uploaded By',
        dataIndex: 'uploaded_by',
        key: 'uploaded_by',
        width: 140,
        render: (uploadedBy?: string) => (
          <Text type="secondary">{uploadedBy || '-'}</Text>
        ),
      },
      ...(onCompare
        ? [
            {
              title: 'Compare',
              key: 'compare',
              width: 80,
              align: 'center' as const,
              render: (_: unknown, record: PackageVersion) => (
                <Button
                  type={compareVersions.includes(record.id) ? 'primary' : 'text'}
                  size="small"
                  icon={<SwapOutlined />}
                  onClick={(e) => handleCompareToggle(record.id, e)}
                  aria-label={`Select ${record.version} for comparison`}
                />
              ),
            },
          ]
        : []),
    ],
    [onCompare, compareVersions, handleCompareToggle]
  );

  return (
    <div>
      {onCompare && compareVersions.length === 2 && (
        <div
          style={{
            marginBottom: spacing.md,
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <Button
            type="primary"
            icon={<SwapOutlined />}
            onClick={handleCompare}
          >
            Compare Selected Versions
          </Button>
        </div>
      )}

      <Table<PackageVersion>
        columns={columns}
        dataSource={versions}
        rowKey="id"
        size="middle"
        pagination={{
          pageSize: 10,
          showSizeChanger: true,
          showTotal: (total) => `${total} versions`,
        }}
        onRow={(record) => ({
          onClick: () => handleRowClick(record),
          style: {
            cursor: onSelect ? 'pointer' : 'default',
            backgroundColor:
              selected === record.id ? colors.bgContainerLight : undefined,
          },
        })}
        locale={{
          emptyText: 'No versions available',
        }}
      />
    </div>
  );
};

export default VersionHistory;
