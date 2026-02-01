import React, { useState, useMemo, useCallback } from 'react';
import {
  Card,
  Checkbox,
  Select,
  Space,
  Typography,
  Tag,
  Table,
  Divider,
  Alert,
  Empty,
  Tooltip,
  Tree,
} from 'antd';
import type { CheckboxProps } from 'antd';
import type { DataNode } from 'antd/es/tree';
import {
  UserOutlined,
  TeamOutlined,
  LockOutlined,
  SafetyCertificateOutlined,
  InfoCircleOutlined,
} from '@ant-design/icons';
import { colors, spacing } from '../../../styles/tokens';
import type { Group, PermissionAction } from '../../../api';
import type { User } from '../../../types';

const { Text } = Typography;

export interface PermissionAssignment {
  principalType: 'user' | 'group';
  principalId: string;
  principalName: string;
  actions: PermissionAction[];
}

export interface PermissionAssignerValue {
  actions: PermissionAction[];
  assignments: PermissionAssignment[];
}

export interface PermissionAssignerProps {
  value?: PermissionAssignerValue;
  onChange?: (value: PermissionAssignerValue) => void;
  users: User[];
  groups: Group[];
}

interface ActionDefinition {
  key: PermissionAction;
  label: string;
  description: string;
  color: string;
}

const ACTIONS: ActionDefinition[] = [
  {
    key: 'read',
    label: 'Read',
    description: 'View and download artifacts',
    color: colors.info,
  },
  {
    key: 'write',
    label: 'Deploy / Write',
    description: 'Upload and modify artifacts',
    color: colors.success,
  },
  {
    key: 'delete',
    label: 'Delete',
    description: 'Remove artifacts and versions',
    color: colors.error,
  },
  {
    key: 'admin',
    label: 'Manage',
    description: 'Full administrative access',
    color: colors.warning,
  },
];

export const PermissionAssigner: React.FC<PermissionAssignerProps> = ({
  value,
  onChange,
  users,
  groups,
}) => {
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [selectedGroupIds, setSelectedGroupIds] = useState<string[]>([]);

  const currentValue: PermissionAssignerValue = value || {
    actions: [],
    assignments: [],
  };

  const handleChange = useCallback(
    (updates: Partial<PermissionAssignerValue>) => {
      onChange?.({
        ...currentValue,
        ...updates,
      });
    },
    [currentValue, onChange]
  );

  const handleActionChange = useCallback(
    (action: PermissionAction, checked: boolean) => {
      let newActions: PermissionAction[];
      if (checked) {
        newActions = [...currentValue.actions, action];
      } else {
        newActions = currentValue.actions.filter((a) => a !== action);
      }

      const updatedAssignments = currentValue.assignments.map((assignment) => ({
        ...assignment,
        actions: assignment.actions.filter((a) => newActions.includes(a)),
      }));

      handleChange({
        actions: newActions,
        assignments: updatedAssignments,
      });
    },
    [currentValue, handleChange]
  );

  const handleSelectAllActions: CheckboxProps['onChange'] = useCallback(
    (e: Parameters<NonNullable<CheckboxProps['onChange']>>[0]) => {
      if (e.target.checked) {
        handleChange({ actions: ACTIONS.map((a) => a.key) });
      } else {
        handleChange({ actions: [], assignments: [] });
      }
    },
    [handleChange]
  );

  const handleAddUsers = useCallback(() => {
    if (selectedUserIds.length === 0) return;

    const existingUserIds = currentValue.assignments
      .filter((a) => a.principalType === 'user')
      .map((a) => a.principalId);

    const newAssignments: PermissionAssignment[] = selectedUserIds
      .filter((id) => !existingUserIds.includes(id))
      .map((id) => {
        const user = users.find((u) => u.id === id);
        return {
          principalType: 'user' as const,
          principalId: id,
          principalName: user?.display_name || user?.username || id,
          actions: [...currentValue.actions],
        };
      });

    handleChange({
      assignments: [...currentValue.assignments, ...newAssignments],
    });
    setSelectedUserIds([]);
  }, [selectedUserIds, users, currentValue, handleChange]);

  const handleAddGroups = useCallback(() => {
    if (selectedGroupIds.length === 0) return;

    const existingGroupIds = currentValue.assignments
      .filter((a) => a.principalType === 'group')
      .map((a) => a.principalId);

    const newAssignments: PermissionAssignment[] = selectedGroupIds
      .filter((id) => !existingGroupIds.includes(id))
      .map((id) => {
        const group = groups.find((g) => g.id === id);
        return {
          principalType: 'group' as const,
          principalId: id,
          principalName: group?.name || id,
          actions: [...currentValue.actions],
        };
      });

    handleChange({
      assignments: [...currentValue.assignments, ...newAssignments],
    });
    setSelectedGroupIds([]);
  }, [selectedGroupIds, groups, currentValue, handleChange]);

  const handleRemoveAssignment = useCallback(
    (principalType: 'user' | 'group', principalId: string) => {
      handleChange({
        assignments: currentValue.assignments.filter(
          (a) => !(a.principalType === principalType && a.principalId === principalId)
        ),
      });
    },
    [currentValue, handleChange]
  );

  const handleAssignmentActionChange = useCallback(
    (principalType: 'user' | 'group', principalId: string, action: PermissionAction, checked: boolean) => {
      handleChange({
        assignments: currentValue.assignments.map((a) => {
          if (a.principalType === principalType && a.principalId === principalId) {
            return {
              ...a,
              actions: checked
                ? [...a.actions, action]
                : a.actions.filter((act) => act !== action),
            };
          }
          return a;
        }),
      });
    },
    [currentValue, handleChange]
  );

  const groupAssignments = useMemo(
    () => currentValue.assignments.filter((a) => a.principalType === 'group'),
    [currentValue.assignments]
  );

  const userAssignments = useMemo(
    () => currentValue.assignments.filter((a) => a.principalType === 'user'),
    [currentValue.assignments]
  );

  const inheritanceTree: DataNode[] = useMemo(() => {
    return groupAssignments.map((groupAssignment) => {
      const group = groups.find((g) => g.id === groupAssignment.principalId);
      const memberCount = group?.member_count || 0;

      return {
        key: groupAssignment.principalId,
        title: (
          <Space>
            <TeamOutlined />
            <Text strong>{groupAssignment.principalName}</Text>
            <Text type="secondary">({memberCount} members)</Text>
            <Space size={2}>
              {groupAssignment.actions.map((action) => {
                const actionDef = ACTIONS.find((a) => a.key === action);
                return (
                  <Tag key={action} color={actionDef?.color} style={{ margin: 0 }}>
                    {actionDef?.label}
                  </Tag>
                );
              })}
            </Space>
          </Space>
        ),
        children: userAssignments
          .filter(() => {
            return true;
          })
          .slice(0, 3)
          .map((ua) => ({
            key: `${groupAssignment.principalId}-${ua.principalId}`,
            title: (
              <Space>
                <UserOutlined />
                <Text>{ua.principalName}</Text>
                <Tag color="blue">inherits from group</Tag>
              </Space>
            ),
            isLeaf: true,
          })),
      };
    });
  }, [groupAssignments, userAssignments, groups]);

  const allActionsSelected = currentValue.actions.length === ACTIONS.length;
  const someActionsSelected = currentValue.actions.length > 0 && !allActionsSelected;

  return (
    <div>
      <Card
        size="small"
        title={
          <Space>
            <LockOutlined />
            <Text strong>Permission Actions</Text>
          </Space>
        }
        style={{ marginBottom: spacing.md }}
      >
        <div style={{ marginBottom: spacing.sm }}>
          <Checkbox
            indeterminate={someActionsSelected}
            onChange={handleSelectAllActions}
            checked={allActionsSelected}
          >
            Select All Actions
          </Checkbox>
        </div>
        <Divider style={{ margin: `${spacing.sm}px 0` }} />
        <Space orientation="vertical" style={{ width: '100%' }}>
          {ACTIONS.map((action) => (
            <div
              key={action.key}
              style={{
                display: 'flex',
                alignItems: 'center',
                padding: `${spacing.xs}px ${spacing.sm}px`,
                backgroundColor: currentValue.actions.includes(action.key)
                  ? colors.bgContainerLight
                  : 'transparent',
                borderRadius: 4,
              }}
            >
              <Checkbox
                checked={currentValue.actions.includes(action.key)}
                onChange={(e) => handleActionChange(action.key, e.target.checked)}
                style={{ flex: 1 }}
              >
                <Space>
                  <Tag color={action.color} style={{ margin: 0 }}>
                    {action.label}
                  </Tag>
                  <Text type="secondary">{action.description}</Text>
                </Space>
              </Checkbox>
            </div>
          ))}
        </Space>
      </Card>

      <Card
        size="small"
        title={
          <Space>
            <TeamOutlined />
            <Text strong>Group Permissions</Text>
            <Tooltip title="Permissions assigned to groups are inherited by all group members">
              <InfoCircleOutlined style={{ color: colors.textTertiary }} />
            </Tooltip>
          </Space>
        }
        style={{ marginBottom: spacing.md }}
      >
        <Space.Compact style={{ width: '100%', marginBottom: spacing.sm }}>
          <Select
            mode="multiple"
            placeholder="Select groups to add"
            value={selectedGroupIds}
            onChange={setSelectedGroupIds}
            style={{ flex: 1 }}
            optionFilterProp="label"
            showSearch
            options={groups
              .filter(
                (g) =>
                  !currentValue.assignments.some(
                    (a) => a.principalType === 'group' && a.principalId === g.id
                  )
              )
              .map((group) => ({
                value: group.id,
                label: group.name,
              }))}
          />
          <button
            onClick={handleAddGroups}
            disabled={selectedGroupIds.length === 0 || currentValue.actions.length === 0}
            style={{
              padding: `${spacing.xs}px ${spacing.md}px`,
              backgroundColor: colors.primary,
              color: 'white',
              border: 'none',
              cursor: selectedGroupIds.length === 0 || currentValue.actions.length === 0 ? 'not-allowed' : 'pointer',
              opacity: selectedGroupIds.length === 0 || currentValue.actions.length === 0 ? 0.5 : 1,
            }}
          >
            Add
          </button>
        </Space.Compact>

        {groupAssignments.length === 0 ? (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="No groups assigned"
          />
        ) : (
          <Table
            size="small"
            dataSource={groupAssignments}
            rowKey="principalId"
            pagination={false}
            columns={[
              {
                title: 'Group',
                dataIndex: 'principalName',
                key: 'principalName',
                render: (name: string) => (
                  <Space>
                    <TeamOutlined />
                    <Text strong>{name}</Text>
                  </Space>
                ),
              },
              ...ACTIONS.filter((a) => currentValue.actions.includes(a.key)).map((action) => ({
                title: action.label,
                key: action.key,
                width: 80,
                align: 'center' as const,
                render: (_: unknown, record: PermissionAssignment) => (
                  <Checkbox
                    checked={record.actions.includes(action.key)}
                    onChange={(e) =>
                      handleAssignmentActionChange('group', record.principalId, action.key, e.target.checked)
                    }
                  />
                ),
              })),
              {
                title: '',
                key: 'actions',
                width: 50,
                render: (_: unknown, record: PermissionAssignment) => (
                  <a onClick={() => handleRemoveAssignment('group', record.principalId)}>
                    Remove
                  </a>
                ),
              },
            ]}
          />
        )}
      </Card>

      <Card
        size="small"
        title={
          <Space>
            <UserOutlined />
            <Text strong>User Permissions</Text>
          </Space>
        }
        style={{ marginBottom: spacing.md }}
      >
        <Space.Compact style={{ width: '100%', marginBottom: spacing.sm }}>
          <Select
            mode="multiple"
            placeholder="Select users to add"
            value={selectedUserIds}
            onChange={setSelectedUserIds}
            style={{ flex: 1 }}
            optionFilterProp="label"
            showSearch
            options={users
              .filter(
                (u) =>
                  !currentValue.assignments.some(
                    (a) => a.principalType === 'user' && a.principalId === u.id
                  )
              )
              .map((user) => ({
                value: user.id,
                label: user.display_name || user.username,
              }))}
          />
          <button
            onClick={handleAddUsers}
            disabled={selectedUserIds.length === 0 || currentValue.actions.length === 0}
            style={{
              padding: `${spacing.xs}px ${spacing.md}px`,
              backgroundColor: colors.primary,
              color: 'white',
              border: 'none',
              cursor: selectedUserIds.length === 0 || currentValue.actions.length === 0 ? 'not-allowed' : 'pointer',
              opacity: selectedUserIds.length === 0 || currentValue.actions.length === 0 ? 0.5 : 1,
            }}
          >
            Add
          </button>
        </Space.Compact>

        {userAssignments.length === 0 ? (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="No users assigned"
          />
        ) : (
          <Table
            size="small"
            dataSource={userAssignments}
            rowKey="principalId"
            pagination={false}
            columns={[
              {
                title: 'User',
                dataIndex: 'principalName',
                key: 'principalName',
                render: (name: string) => (
                  <Space>
                    <UserOutlined />
                    <Text strong>{name}</Text>
                  </Space>
                ),
              },
              ...ACTIONS.filter((a) => currentValue.actions.includes(a.key)).map((action) => ({
                title: action.label,
                key: action.key,
                width: 80,
                align: 'center' as const,
                render: (_: unknown, record: PermissionAssignment) => (
                  <Checkbox
                    checked={record.actions.includes(action.key)}
                    onChange={(e) =>
                      handleAssignmentActionChange('user', record.principalId, action.key, e.target.checked)
                    }
                  />
                ),
              })),
              {
                title: '',
                key: 'actions',
                width: 50,
                render: (_: unknown, record: PermissionAssignment) => (
                  <a onClick={() => handleRemoveAssignment('user', record.principalId)}>
                    Remove
                  </a>
                ),
              },
            ]}
          />
        )}
      </Card>

      {groupAssignments.length > 0 && (
        <Card
          size="small"
          title={
            <Space>
              <SafetyCertificateOutlined />
              <Text strong>Permission Inheritance</Text>
            </Space>
          }
        >
          <Alert
            message="Group members inherit permissions from their groups"
            description="Users in the assigned groups will automatically receive the group's permissions for the selected repositories."
            type="info"
            showIcon
            style={{ marginBottom: spacing.md }}
          />
          <Tree
            showLine
            defaultExpandAll
            treeData={inheritanceTree}
            selectable={false}
          />
        </Card>
      )}
    </div>
  );
};

export default PermissionAssigner;
