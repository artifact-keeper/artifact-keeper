import React, { useMemo, useCallback, useState } from 'react';
import {
  Table,
  Card,
  List,
  Button,
  Space,
  Typography,
  Empty,
  Tag,
  Tooltip,
  Radio,
  Select,
  Pagination,
  Spin,
} from 'antd';
import type { ColumnsType, TablePaginationConfig } from 'antd/es/table';
import type { SorterResult } from 'antd/es/table/interface';
import {
  DownloadOutlined,
  AppstoreOutlined,
  UnorderedListOutlined,
  FileOutlined,
  FolderOutlined,
  SortAscendingOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { ArtifactSearchHit } from '../../../types';
import { formatFileSize, formatRelativeTime } from '../../../utils';

const { Text, Title } = Typography;

export type ViewMode = 'list' | 'grid';
export type SortField = 'name' | 'created_at' | 'size_bytes';
export type SortOrder = 'ascend' | 'descend';

export interface SearchResultsPagination {
  current: number;
  pageSize: number;
  total: number;
  onChange: (page: number, pageSize: number) => void;
}

export interface SearchResultsProps {
  results: ArtifactSearchHit[];
  loading?: boolean;
  onSelect?: (result: ArtifactSearchHit) => void;
  onDownload?: (result: ArtifactSearchHit) => void;
  pagination?: SearchResultsPagination;
  viewMode?: ViewMode;
  onViewModeChange?: (mode: ViewMode) => void;
  sortField?: SortField;
  sortOrder?: SortOrder;
  onSortChange?: (field: SortField, order: SortOrder) => void;
}

const getFormatColor = (contentType: string): string => {
  if (contentType.includes('java') || contentType.includes('jar')) {
    return 'orange';
  }
  if (contentType.includes('python') || contentType.includes('whl')) {
    return 'blue';
  }
  if (contentType.includes('npm') || contentType.includes('javascript')) {
    return 'green';
  }
  if (contentType.includes('docker') || contentType.includes('tar')) {
    return 'purple';
  }
  if (contentType.includes('zip') || contentType.includes('compressed')) {
    return 'cyan';
  }
  return 'default';
};

export const SearchResults: React.FC<SearchResultsProps> = ({
  results,
  loading = false,
  onSelect,
  onDownload,
  pagination,
  viewMode: controlledViewMode,
  onViewModeChange,
  sortField: controlledSortField,
  sortOrder: controlledSortOrder,
  onSortChange,
}) => {
  const navigate = useNavigate();
  const [internalViewMode, setInternalViewMode] = useState<ViewMode>('list');
  const [internalSortField, setInternalSortField] = useState<SortField>('name');
  const [internalSortOrder, setInternalSortOrder] = useState<SortOrder>('ascend');

  const viewMode = controlledViewMode ?? internalViewMode;
  const sortField = controlledSortField ?? internalSortField;
  const sortOrder = controlledSortOrder ?? internalSortOrder;

  const handleViewModeChange = useCallback(
    (mode: ViewMode) => {
      if (onViewModeChange) {
        onViewModeChange(mode);
      } else {
        setInternalViewMode(mode);
      }
    },
    [onViewModeChange]
  );

  const handleSortChange = useCallback(
    (field: SortField, order: SortOrder) => {
      if (onSortChange) {
        onSortChange(field, order);
      } else {
        setInternalSortField(field);
        setInternalSortOrder(order);
      }
    },
    [onSortChange]
  );

  const handleResultClick = useCallback(
    (result: ArtifactSearchHit) => {
      if (onSelect) {
        onSelect(result);
      } else {
        navigate(`/repositories/${result.repository_key}/artifacts/${result.id}`);
      }
    },
    [onSelect, navigate]
  );

  const handleDownload = useCallback(
    (result: ArtifactSearchHit, e: React.MouseEvent) => {
      e.stopPropagation();
      if (onDownload) {
        onDownload(result);
      }
    },
    [onDownload]
  );

  const handleTableChange = useCallback(
    (
      _pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter: SorterResult<ArtifactSearchHit> | SorterResult<ArtifactSearchHit>[]
    ) => {
      if (!Array.isArray(sorter) && sorter.field && sorter.order) {
        handleSortChange(sorter.field as SortField, sorter.order);
      }
    },
    [handleSortChange]
  );

  const columns: ColumnsType<ArtifactSearchHit> = useMemo(
    () => [
      {
        title: 'Name',
        dataIndex: 'name',
        key: 'name',
        sorter: true,
        sortOrder: sortField === 'name' ? sortOrder : undefined,
        render: (name: string, result) => (
          <Space>
            <FileOutlined style={{ fontSize: 16, color: colors.textSecondary }} />
            <div>
              <Text
                strong
                style={{ color: colors.link, cursor: 'pointer' }}
                dangerouslySetInnerHTML={{
                  __html: result.name_highlighted || name,
                }}
              />
              {result.version && (
                <Tag style={{ marginLeft: spacing.xs }}>
                  v{result.version}
                </Tag>
              )}
            </div>
          </Space>
        ),
        ellipsis: true,
      },
      {
        title: 'Path',
        dataIndex: 'path',
        key: 'path',
        render: (path: string, result) => (
          <Tooltip title={path}>
            <Text
              type="secondary"
              ellipsis
              style={{ maxWidth: 200 }}
              dangerouslySetInnerHTML={{
                __html: result.path_highlighted || path,
              }}
            />
          </Tooltip>
        ),
        ellipsis: true,
      },
      {
        title: 'Repository',
        dataIndex: 'repository_key',
        key: 'repository_key',
        width: 150,
        render: (repoKey: string) => (
          <Space size="small">
            <FolderOutlined style={{ color: colors.primary }} />
            <Text>{repoKey}</Text>
          </Space>
        ),
      },
      {
        title: 'Format',
        dataIndex: 'content_type',
        key: 'content_type',
        width: 120,
        render: (contentType: string) => (
          <Tag color={getFormatColor(contentType)}>
            {contentType.split('/').pop() || contentType}
          </Tag>
        ),
      },
      {
        title: 'Size',
        dataIndex: 'size_bytes',
        key: 'size_bytes',
        sorter: true,
        sortOrder: sortField === 'size_bytes' ? sortOrder : undefined,
        width: 100,
        align: 'right',
        render: (sizeBytes: number) => (
          <Text type="secondary">{formatFileSize(sizeBytes)}</Text>
        ),
      },
      {
        title: 'Date',
        dataIndex: 'created_at',
        key: 'created_at',
        sorter: true,
        sortOrder: sortField === 'created_at' ? sortOrder : undefined,
        width: 140,
        render: (dateString: string) => {
          const fullDate = new Date(dateString).toLocaleString();
          return (
            <Tooltip title={fullDate}>
              <Text type="secondary">{formatRelativeTime(dateString)}</Text>
            </Tooltip>
          );
        },
      },
      {
        title: 'Actions',
        key: 'actions',
        width: 80,
        align: 'center',
        render: (_, result) => (
          <Tooltip title="Download">
            <Button
              type="text"
              icon={<DownloadOutlined />}
              onClick={(e) => handleDownload(result, e)}
              aria-label={`Download ${result.name}`}
            />
          </Tooltip>
        ),
      },
    ],
    [sortField, sortOrder, handleDownload]
  );

  const tablePagination: TablePaginationConfig | false = pagination
    ? {
        current: pagination.current,
        pageSize: pagination.pageSize,
        total: pagination.total,
        onChange: pagination.onChange,
        showSizeChanger: true,
        showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} results`,
        pageSizeOptions: ['10', '20', '50', '100'],
      }
    : false;

  const sortedResults = useMemo(() => {
    if (onSortChange) {
      return results;
    }

    return [...results].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'created_at':
          comparison = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
          break;
        case 'size_bytes':
          comparison = a.size_bytes - b.size_bytes;
          break;
      }
      return sortOrder === 'ascend' ? comparison : -comparison;
    });
  }, [results, sortField, sortOrder, onSortChange]);

  const renderGridItem = useCallback(
    (result: ArtifactSearchHit) => (
      <List.Item style={{ padding: spacing.xs }}>
        <Card
          hoverable
          onClick={() => handleResultClick(result)}
          style={{
            width: '100%',
            borderRadius: borderRadius.md,
          }}
          styles={{ body: { padding: spacing.md } }}
          actions={[
            <Tooltip key="download" title="Download">
              <Button
                type="text"
                icon={<DownloadOutlined />}
                onClick={(e) => handleDownload(result, e)}
              />
            </Tooltip>,
          ]}
        >
          <Card.Meta
            avatar={
              <FileOutlined style={{ fontSize: 32, color: colors.textSecondary }} />
            }
            title={
              <Space orientation="vertical" size={0}>
                <Text
                  strong
                  ellipsis
                  dangerouslySetInnerHTML={{
                    __html: result.name_highlighted || result.name,
                  }}
                />
                {result.version && (
                  <Tag>v{result.version}</Tag>
                )}
              </Space>
            }
            description={
              <Space orientation="vertical" size={4} style={{ width: '100%' }}>
                <Tooltip title={result.path}>
                  <Text
                    type="secondary"
                    ellipsis
                    style={{ fontSize: 12 }}
                    dangerouslySetInnerHTML={{
                      __html: result.path_highlighted || result.path,
                    }}
                  />
                </Tooltip>
                <Space size="small">
                  <FolderOutlined style={{ color: colors.primary, fontSize: 12 }} />
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {result.repository_key}
                  </Text>
                </Space>
                <Space split={<Text type="secondary">|</Text>} size={4}>
                  <Tag color={getFormatColor(result.content_type)} style={{ margin: 0 }}>
                    {result.content_type.split('/').pop()}
                  </Tag>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {formatFileSize(result.size_bytes)}
                  </Text>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {formatRelativeTime(result.created_at)}
                  </Text>
                </Space>
              </Space>
            }
          />
        </Card>
      </List.Item>
    ),
    [handleResultClick, handleDownload]
  );

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          padding: spacing.xxl,
        }}
      >
        <Spin size="large" />
      </div>
    );
  }

  if (results.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="No results found"
        style={{ padding: spacing.xxl }}
      >
        <Text type="secondary">
          Try adjusting your search criteria or filters
        </Text>
      </Empty>
    );
  }

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: spacing.md,
          padding: `${spacing.sm}px 0`,
        }}
      >
        <Space>
          <Title level={5} style={{ margin: 0 }}>
            {pagination?.total ?? results.length} results
          </Title>
        </Space>

        <Space size="middle">
          <Space size="small">
            <SortAscendingOutlined style={{ color: colors.textSecondary }} />
            <Select
              value={sortField}
              onChange={(value) => handleSortChange(value, sortOrder)}
              style={{ width: 120 }}
              options={[
                { label: 'Name', value: 'name' },
                { label: 'Date', value: 'created_at' },
                { label: 'Size', value: 'size_bytes' },
              ]}
            />
            <Select
              value={sortOrder}
              onChange={(value) => handleSortChange(sortField, value)}
              style={{ width: 120 }}
              options={[
                { label: 'Ascending', value: 'ascend' },
                { label: 'Descending', value: 'descend' },
              ]}
            />
          </Space>

          <Radio.Group
            value={viewMode}
            onChange={(e) => handleViewModeChange(e.target.value)}
            optionType="button"
            buttonStyle="solid"
          >
            <Radio.Button value="list">
              <UnorderedListOutlined />
            </Radio.Button>
            <Radio.Button value="grid">
              <AppstoreOutlined />
            </Radio.Button>
          </Radio.Group>
        </Space>
      </div>

      {viewMode === 'list' ? (
        <Table<ArtifactSearchHit>
          columns={columns}
          dataSource={sortedResults}
          rowKey="id"
          loading={loading}
          pagination={tablePagination}
          onChange={handleTableChange}
          onRow={(result) => ({
            onClick: () => handleResultClick(result),
            style: {
              cursor: 'pointer',
            },
          })}
          size="middle"
          style={{
            backgroundColor: colors.bgContainer,
          }}
        />
      ) : (
        <>
          <List
            grid={{
              gutter: spacing.md,
              xs: 1,
              sm: 2,
              md: 2,
              lg: 3,
              xl: 4,
              xxl: 4,
            }}
            dataSource={sortedResults}
            renderItem={renderGridItem}
            style={{
              backgroundColor: colors.bgContainer,
              padding: spacing.sm,
              borderRadius: borderRadius.md,
            }}
          />
          {pagination && (
            <div
              style={{
                display: 'flex',
                justifyContent: 'flex-end',
                marginTop: spacing.md,
                padding: `${spacing.sm}px 0`,
              }}
            >
              <Pagination
                current={pagination.current}
                pageSize={pagination.pageSize}
                total={pagination.total}
                onChange={pagination.onChange}
                showSizeChanger
                showTotal={(total, range) => `${range[0]}-${range[1]} of ${total} results`}
                pageSizeOptions={['10', '20', '50', '100']}
              />
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default SearchResults;
