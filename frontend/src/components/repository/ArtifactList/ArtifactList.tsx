import React, { useMemo, useCallback } from 'react';
import { Table, Typography } from 'antd';
import type { ColumnsType, TablePaginationConfig } from 'antd/es/table';
import type { SorterResult } from 'antd/es/table/interface';
import type { Artifact } from '../../../types';
import {
  ArtifactListItem,
  formatFileSize,
  formatRelativeTime,
  renderArtifactName,
  renderRelativeTime,
} from './ArtifactListItem';
import { colors } from '../../../styles/tokens';

const { Text } = Typography;

export interface ArtifactListProps {
  artifacts: Artifact[];
  loading?: boolean;
  onSelect?: (artifact: Artifact) => void;
  onDownload: (artifact: Artifact) => void;
  onDelete: (artifact: Artifact) => void;
  pagination?: {
    current: number;
    pageSize: number;
    total: number;
    onChange: (page: number, pageSize: number) => void;
  };
  onSort?: (field: string, order: 'ascend' | 'descend' | null) => void;
}

export const ArtifactList: React.FC<ArtifactListProps> = ({
  artifacts,
  loading = false,
  onSelect,
  onDownload,
  onDelete,
  pagination,
  onSort,
}) => {
  const handleRowClick = useCallback(
    (artifact: Artifact) => {
      if (onSelect) {
        onSelect(artifact);
      }
    },
    [onSelect]
  );

  const handleTableChange = useCallback(
    (
      _pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter: SorterResult<Artifact> | SorterResult<Artifact>[]
    ) => {
      if (onSort && !Array.isArray(sorter) && sorter.field) {
        onSort(sorter.field as string, sorter.order || null);
      }
    },
    [onSort]
  );

  const columns: ColumnsType<Artifact> = useMemo(
    () => [
      {
        title: 'Name',
        dataIndex: 'name',
        key: 'name',
        sorter: true,
        render: (_, artifact) => renderArtifactName(artifact),
        ellipsis: true,
      },
      {
        title: 'Size',
        dataIndex: 'size_bytes',
        key: 'size_bytes',
        sorter: true,
        width: 100,
        render: (sizeBytes: number) => (
          <Text type="secondary">{formatFileSize(sizeBytes)}</Text>
        ),
      },
      {
        title: 'Modified',
        dataIndex: 'created_at',
        key: 'created_at',
        sorter: true,
        width: 140,
        render: (dateString: string) => renderRelativeTime(dateString),
      },
      {
        title: 'Downloads',
        dataIndex: 'download_count',
        key: 'download_count',
        sorter: true,
        width: 100,
        align: 'right',
        render: (count: number) => (
          <Text type="secondary">{count.toLocaleString()}</Text>
        ),
      },
      {
        title: 'Actions',
        key: 'actions',
        width: 140,
        align: 'center',
        render: (_, artifact) => (
          <ArtifactListItem
            artifact={artifact}
            onDownload={onDownload}
            onDelete={onDelete}
          />
        ),
      },
    ],
    [onDownload, onDelete]
  );

  const tablePagination: TablePaginationConfig | false = pagination
    ? {
        current: pagination.current,
        pageSize: pagination.pageSize,
        total: pagination.total,
        onChange: pagination.onChange,
        showSizeChanger: true,
        showTotal: (total, range) =>
          `${range[0]}-${range[1]} of ${total} artifacts`,
        pageSizeOptions: ['10', '20', '50', '100'],
      }
    : false;

  return (
    <Table<Artifact>
      columns={columns}
      dataSource={artifacts}
      rowKey="id"
      loading={loading}
      pagination={tablePagination}
      onChange={handleTableChange}
      onRow={(artifact) => ({
        onClick: () => handleRowClick(artifact),
        style: {
          cursor: onSelect ? 'pointer' : 'default',
        },
      })}
      size="middle"
      locale={{
        emptyText: 'No artifacts found',
      }}
      style={{
        backgroundColor: colors.bgContainer,
      }}
    />
  );
};

export default ArtifactList;
