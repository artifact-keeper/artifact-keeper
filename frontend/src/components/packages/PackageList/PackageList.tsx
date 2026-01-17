import React, { useMemo, useCallback } from 'react';
import { Table, Row, Col, Segmented, Space, Typography, Tooltip } from 'antd';
import type { ColumnsType, TablePaginationConfig } from 'antd/es/table';
import type { SorterResult } from 'antd/es/table/interface';
import {
  AppstoreOutlined,
  UnorderedListOutlined,
  DownloadOutlined,
} from '@ant-design/icons';
import type { Package, PackageType } from '../../../types';
import { PackageCard } from './PackageCard';
import { EmptyState } from '../../common/EmptyState/EmptyState';
import { colors, spacing } from '../../../styles/tokens';
import { formatFileSize, formatRelativeTime } from '../../../utils';

const { Text } = Typography;

export type ViewMode = 'grid' | 'list';

export interface PackageListProps {
  packages: Package[];
  loading?: boolean;
  viewMode?: ViewMode;
  onSelect?: (pkg: Package) => void;
  onViewModeChange?: (mode: ViewMode) => void;
  pagination?: {
    current: number;
    pageSize: number;
    total: number;
    onChange: (page: number, pageSize: number) => void;
  };
  onSort?: (field: string, order: 'ascend' | 'descend' | null) => void;
}

const packageTypeLabels: Record<PackageType, string> = {
  maven: 'Maven',
  gradle: 'Gradle',
  npm: 'npm',
  pypi: 'PyPI',
  nuget: 'NuGet',
  go: 'Go',
  rubygems: 'RubyGems',
  docker: 'Docker',
  helm: 'Helm',
  rpm: 'RPM',
  debian: 'Debian',
  conan: 'Conan',
  cargo: 'Cargo',
  generic: 'Generic',
};

export const PackageList: React.FC<PackageListProps> = ({
  packages,
  loading = false,
  viewMode = 'grid',
  onSelect,
  onViewModeChange,
  pagination,
  onSort,
}) => {
  const handleRowClick = useCallback(
    (pkg: Package) => {
      if (onSelect) {
        onSelect(pkg);
      }
    },
    [onSelect]
  );

  const handleTableChange = useCallback(
    (
      _pagination: TablePaginationConfig,
      _filters: Record<string, (string | number | boolean)[] | null>,
      sorter: SorterResult<Package> | SorterResult<Package>[]
    ) => {
      if (onSort && !Array.isArray(sorter) && sorter.field) {
        onSort(sorter.field as string, sorter.order || null);
      }
    },
    [onSort]
  );

  const handleViewModeChange = useCallback(
    (value: string | number) => {
      if (onViewModeChange) {
        onViewModeChange(value as ViewMode);
      }
    },
    [onViewModeChange]
  );

  const columns: ColumnsType<Package> = useMemo(
    () => [
      {
        title: 'Package',
        dataIndex: 'name',
        key: 'name',
        sorter: true,
        render: (_, pkg) => (
          <Space direction="vertical" size={0}>
            <Text strong>{pkg.name}</Text>
            {pkg.latest_version && (
              <Text type="secondary" style={{ fontSize: 12 }}>
                v{pkg.latest_version}
              </Text>
            )}
          </Space>
        ),
        ellipsis: true,
      },
      {
        title: 'Type',
        dataIndex: 'package_type',
        key: 'package_type',
        width: 100,
        render: (packageType: PackageType) => (
          <Text type="secondary">{packageTypeLabels[packageType] || packageType}</Text>
        ),
      },
      {
        title: 'Versions',
        dataIndex: 'version_count',
        key: 'version_count',
        width: 100,
        align: 'right',
        sorter: true,
        render: (count: number) => (
          <Text type="secondary">{count.toLocaleString()}</Text>
        ),
      },
      {
        title: 'Size',
        dataIndex: 'total_size_bytes',
        key: 'total_size_bytes',
        width: 100,
        align: 'right',
        sorter: true,
        render: (bytes: number) => (
          <Text type="secondary">{formatFileSize(bytes)}</Text>
        ),
      },
      {
        title: 'Downloads',
        dataIndex: 'total_downloads',
        key: 'total_downloads',
        width: 120,
        align: 'right',
        sorter: true,
        render: (count: number) => (
          <Space size={4}>
            <DownloadOutlined style={{ color: colors.textTertiary }} />
            <Text type="secondary">{count.toLocaleString()}</Text>
          </Space>
        ),
      },
      {
        title: 'Last Updated',
        dataIndex: 'updated_at',
        key: 'updated_at',
        width: 140,
        sorter: true,
        render: (dateString: string) => {
          const fullDate = new Date(dateString).toLocaleString();
          return (
            <Tooltip title={fullDate}>
              <Text type="secondary">{formatRelativeTime(dateString)}</Text>
            </Tooltip>
          );
        },
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
          `${range[0]}-${range[1]} of ${total} packages`,
        pageSizeOptions: ['12', '24', '48', '96'],
      }
    : false;

  const gridPagination = pagination
    ? {
        current: pagination.current,
        pageSize: pagination.pageSize,
        total: pagination.total,
        onChange: pagination.onChange,
        showSizeChanger: true,
        showTotal: (total: number, range: [number, number]) =>
          `${range[0]}-${range[1]} of ${total} packages`,
        pageSizeOptions: ['12', '24', '48', '96'],
      }
    : undefined;

  if (!loading && packages.length === 0) {
    return (
      <EmptyState
        type="artifacts"
        title="No packages found"
        description="Try adjusting your filters or search criteria."
      />
    );
  }

  return (
    <div>
      {onViewModeChange && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            marginBottom: spacing.md,
          }}
        >
          <Segmented
            value={viewMode}
            onChange={handleViewModeChange}
            options={[
              {
                value: 'grid',
                icon: <AppstoreOutlined />,
              },
              {
                value: 'list',
                icon: <UnorderedListOutlined />,
              },
            ]}
          />
        </div>
      )}

      {viewMode === 'grid' ? (
        <>
          <Row gutter={[spacing.md, spacing.md]}>
            {packages.map((pkg) => (
              <Col key={pkg.id} xs={24} sm={12} md={8} lg={6} xl={6}>
                <PackageCard package={pkg} onClick={onSelect} />
              </Col>
            ))}
          </Row>
          {gridPagination && (
            <div
              style={{
                display: 'flex',
                justifyContent: 'flex-end',
                marginTop: spacing.lg,
              }}
            >
              <Table
                dataSource={[]}
                columns={[]}
                pagination={gridPagination}
                showHeader={false}
                style={{ width: 'auto' }}
              />
            </div>
          )}
        </>
      ) : (
        <Table<Package>
          columns={columns}
          dataSource={packages}
          rowKey="id"
          loading={loading}
          pagination={tablePagination}
          onChange={handleTableChange}
          onRow={(pkg) => ({
            onClick: () => handleRowClick(pkg),
            style: {
              cursor: onSelect ? 'pointer' : 'default',
            },
          })}
          size="middle"
          locale={{
            emptyText: 'No packages found',
          }}
          style={{
            backgroundColor: colors.bgContainer,
          }}
        />
      )}
    </div>
  );
};

export default PackageList;
