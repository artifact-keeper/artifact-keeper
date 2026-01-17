import React from 'react';
import { Button, Space, Tooltip } from 'antd';
import {
  ThunderboltOutlined,
  UploadOutlined,
  PlusOutlined,
  FolderOpenOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { DashboardWidget } from '../DashboardWidget';
import { useAuth } from '../../../contexts';
import { colors, spacing } from '../../../styles/tokens';

interface QuickAction {
  key: string;
  label: string;
  icon: React.ReactNode;
  tooltip: string;
  onClick: () => void;
  adminOnly?: boolean;
}

export const QuickActionsWidget: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();

  const actions: QuickAction[] = [
    {
      key: 'upload',
      label: 'Upload Artifact',
      icon: <UploadOutlined />,
      tooltip: 'Upload a new artifact to a repository',
      onClick: () => navigate('/artifacts?action=upload'),
    },
    {
      key: 'create-repo',
      label: 'Create Repository',
      icon: <PlusOutlined />,
      tooltip: 'Create a new repository',
      onClick: () => navigate('/repositories?action=create'),
      adminOnly: true,
    },
    {
      key: 'browse',
      label: 'Browse Artifacts',
      icon: <FolderOpenOutlined />,
      tooltip: 'Browse all artifacts in repositories',
      onClick: () => navigate('/artifacts'),
    },
    {
      key: 'search',
      label: 'Search Artifacts',
      icon: <SearchOutlined />,
      tooltip: 'Search for artifacts across repositories',
      onClick: () => navigate('/artifacts?action=search'),
    },
  ];

  const visibleActions = actions.filter(
    (action) => !action.adminOnly || user?.is_admin
  );

  return (
    <DashboardWidget
      title="Quick Actions"
      icon={<ThunderboltOutlined />}
    >
      <Space
        orientation="vertical"
        size={spacing.xs}
        style={{ width: '100%' }}
      >
        {visibleActions.map((action) => (
          <Tooltip key={action.key} title={action.tooltip} placement="right">
            <Button
              block
              icon={action.icon}
              onClick={action.onClick}
              style={{
                textAlign: 'left',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-start',
                height: 40,
              }}
              styles={{
                icon: {
                  color: colors.primary,
                },
              }}
            >
              {action.label}
            </Button>
          </Tooltip>
        ))}
      </Space>
    </DashboardWidget>
  );
};

export default QuickActionsWidget;
