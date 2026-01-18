import React, { useMemo, useState, useCallback } from 'react';
import {
  Table,
  Tag,
  Button,
  Dropdown,
  Space,
  Input,
  Tooltip,
  Typography,
  Result,
} from 'antd';
import type { ColumnsType, TablePaginationConfig } from 'antd/es/table';
import type { SorterResult, FilterValue } from 'antd/es/table/interface';
import type { MenuProps } from 'antd';
import {
  EditOutlined,
  DeleteOutlined,
  EllipsisOutlined,
  SearchOutlined,
  PlusOutlined,
  TeamOutlined,
  UserAddOutlined,
} from '@ant-design/icons';
import type { Group } from '../../../types';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;

export interface GroupTableProps {
  groups: Group[];
  loading?: boolean;
  onEdit: (group: Group) => void;
  onDelete: (group: Group) => void;
  onManageMembers: (group: Group) => void;
  onCreate?: () => void;
}

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

export const GroupTable: React.FC<GroupTableProps> = ({
  groups,
  loading = false,
  onEdit,
  onDelete,
  onManageMembers,
  onCreate,
}) => {
  const [searchText, setSearchText] = useState('');
  const [sortedInfo, setSortedInfo] = useState<SorterResult<Group>>({});

  const handleSearch = useCallback((value: string) => {
    setSearchText(value);
  }, []);

  const handleTableChange = useCallback(
    (
      _pagination: TablePaginationConfig,
      _filters: Record<string, FilterValue | null>,
      sorter: SorterResult<Group> | SorterResult<Group>[]
    ) => {
      if (!Array.isArray(sorter)) {
        setSortedInfo(sorter);
      }
    },
    []
  );

  const filteredGroups = useMemo(() => {
    return groups.filter((group) => {
      const matchesSearch =
        searchText === '' ||
        group.name.toLowerCase().includes(searchText.toLowerCase()) ||
        (group.description?.toLowerCase().includes(searchText.toLowerCase()) ?? false);

      return matchesSearch;
    });
  }, [groups, searchText]);

  const getActionMenuItems = useCallback(
    (group: Group): MenuProps['items'] => {
      return [
        {
          key: 'edit',
          label: 'Edit',
          icon: <EditOutlined />,
          onClick: () => onEdit(group),
        },
        {
          key: 'manage-members',
          label: 'Manage Members',
          icon: <UserAddOutlined />,
          onClick: () => onManageMembers(group),
        },
        { type: 'divider' },
        {
          key: 'delete',
          label: 'Delete',
          icon: <DeleteOutlined />,
          danger: true,
          onClick: () => onDelete(group),
        },
      ];
    },
    [onEdit, onManageMembers, onDelete]
  );

  const columns: ColumnsType<Group> = useMemo(
    () => [
      {
        title: 'Name',
        dataIndex: 'name',
        key: 'name',
        sorter: (a, b) => a.name.localeCompare(b.name),
        sortOrder: sortedInfo.columnKey === 'name' ? sortedInfo.order : null,
        ellipsis: true,
        render: (name: string, record) => (
          <Space>
            <TeamOutlined style={{ color: colors.primary }} />
            <Text strong style={{ color: colors.primary }}>
              {name}
            </Text>
            {record.is_external && (
              <Tag color="purple" style={{ marginLeft: 4 }}>
                External
              </Tag>
            )}
          </Space>
        ),
      },
      {
        title: 'Description',
        dataIndex: 'description',
        key: 'description',
        ellipsis: true,
        render: (description: string) => (
          <Tooltip title={description}>
            <Text type="secondary">{description || '-'}</Text>
          </Tooltip>
        ),
      },
      {
        title: 'Member Count',
        dataIndex: 'member_count',
        key: 'member_count',
        width: 120,
        sorter: (a, b) => a.member_count - b.member_count,
        sortOrder: sortedInfo.columnKey === 'member_count' ? sortedInfo.order : null,
        align: 'center',
        render: (count: number) => (
          <Tag color={count > 0 ? 'blue' : 'default'}>{count}</Tag>
        ),
      },
      {
        title: 'Auto-Join',
        dataIndex: 'auto_join',
        key: 'auto_join',
        width: 100,
        render: (autoJoin: boolean) => (
          <Tag color={autoJoin ? 'green' : 'default'}>
            {autoJoin ? 'Yes' : 'No'}
          </Tag>
        ),
      },
      {
        title: 'Created',
        dataIndex: 'created_at',
        key: 'created_at',
        width: 120,
        sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
        sortOrder: sortedInfo.columnKey === 'created_at' ? sortedInfo.order : null,
        render: (date: string) => (
          <Tooltip title={new Date(date).toLocaleString()}>
            <Text type="secondary">{formatDate(date)}</Text>
          </Tooltip>
        ),
      },
      {
        title: 'Actions',
        key: 'actions',
        width: 80,
        align: 'center',
        fixed: 'right',
        render: (_, record) => (
          <Dropdown
            menu={{ items: getActionMenuItems(record) }}
            trigger={['click']}
            placement="bottomRight"
          >
            <Button type="text" icon={<EllipsisOutlined />} />
          </Dropdown>
        ),
      },
    ],
    [sortedInfo, getActionMenuItems]
  );

  if (!loading && groups.length === 0) {
    return (
      <Result
        icon={<TeamOutlined style={{ fontSize: 64, color: colors.textTertiary }} />}
        title="No groups yet"
        subTitle="Create your first group to start managing user access."
        extra={
          onCreate && (
            <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
              Create Group
            </Button>
          )
        }
        style={{
          padding: spacing.xxl,
          backgroundColor: colors.bgContainer,
        }}
      />
    );
  }

  return (
    <div style={{ backgroundColor: colors.bgContainer }}>
      <div
        style={{
          padding: spacing.md,
          display: 'flex',
          flexWrap: 'wrap',
          gap: spacing.sm,
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: `1px solid ${colors.borderLight}`,
        }}
      >
        <Space wrap>
          <Input
            placeholder="Search groups..."
            prefix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => handleSearch(e.target.value)}
            style={{ width: 240 }}
            allowClear
          />
        </Space>

        <Space>
          {onCreate && (
            <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
              Create Group
            </Button>
          )}
        </Space>
      </div>

      <Table<Group>
        columns={columns}
        dataSource={filteredGroups}
        rowKey="id"
        loading={loading}
        onChange={handleTableChange}
        pagination={{
          showSizeChanger: true,
          showTotal: (total, range) =>
            `${range[0]}-${range[1]} of ${total} groups`,
          pageSizeOptions: ['10', '20', '50', '100'],
          defaultPageSize: 20,
        }}
        scroll={{ x: 800 }}
        size="middle"
        locale={{
          emptyText: (
            <Result
              icon={<SearchOutlined style={{ fontSize: 48, color: colors.textTertiary }} />}
              title="No matching groups"
              subTitle="Try adjusting your search criteria."
              style={{ padding: spacing.lg }}
            />
          ),
        }}
      />
    </div>
  );
};

export default GroupTable;
