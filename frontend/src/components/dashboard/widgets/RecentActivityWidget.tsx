import React from 'react';
import { Timeline, Typography, Empty } from 'antd';
import {
  HistoryOutlined,
  UploadOutlined,
  DownloadOutlined,
  DeleteOutlined,
  FileOutlined,
} from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { DashboardWidget } from '../DashboardWidget';
import { artifactsApi, repositoriesApi } from '../../../api';
import { colors, spacing } from '../../../styles/tokens';
import { formatRelativeTime } from '../../../utils';
import type { Artifact } from '../../../types';

const { Text, Link } = Typography;

type ActivityType = 'upload' | 'download' | 'delete';

interface ActivityItem {
  id: string;
  type: ActivityType;
  artifactPath: string;
  artifactName: string;
  repositoryKey: string;
  timestamp: string;
}

const activityIcons: Record<ActivityType, React.ReactNode> = {
  upload: <UploadOutlined style={{ color: colors.success }} />,
  download: <DownloadOutlined style={{ color: colors.info }} />,
  delete: <DeleteOutlined style={{ color: colors.error }} />,
};

const activityLabels: Record<ActivityType, string> = {
  upload: 'Uploaded',
  download: 'Downloaded',
  delete: 'Deleted',
};

const activityColors: Record<ActivityType, string> = {
  upload: colors.success,
  download: colors.info,
  delete: colors.error,
};

export const RecentActivityWidget: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const {
    data: repositories,
    isLoading: reposLoading,
    error: reposError,
  } = useQuery({
    queryKey: ['repositories-list'],
    queryFn: () => repositoriesApi.list({ per_page: 10 }),
  });

  const repoKeys = repositories?.items?.map((repo) => repo.key) ?? [];

  const {
    data: artifactsData,
    isLoading: artifactsLoading,
    error: artifactsError,
    isFetching,
  } = useQuery({
    queryKey: ['recent-artifacts', repoKeys],
    queryFn: async () => {
      if (repoKeys.length === 0) return [];

      const results = await Promise.all(
        repoKeys.slice(0, 5).map(async (repoKey) => {
          try {
            const response = await artifactsApi.list(repoKey, { per_page: 3 });
            return response.items.map((artifact) => ({
              ...artifact,
              repositoryKey: repoKey,
            }));
          } catch {
            return [];
          }
        })
      );

      return results.flat();
    },
    enabled: repoKeys.length > 0,
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['repositories-list'] });
    queryClient.invalidateQueries({ queryKey: ['recent-artifacts'] });
  };

  const isLoading = reposLoading || artifactsLoading;
  const error = reposError || artifactsError;

  const activities: ActivityItem[] = React.useMemo(() => {
    if (!artifactsData) return [];

    return (artifactsData as (Artifact & { repositoryKey: string })[])
      .map((artifact) => ({
        id: artifact.id,
        type: 'upload' as ActivityType,
        artifactPath: artifact.path,
        artifactName: artifact.name,
        repositoryKey: artifact.repositoryKey,
        timestamp: artifact.created_at,
      }))
      .sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      )
      .slice(0, 10);
  }, [artifactsData]);

  const handleArtifactClick = (activity: ActivityItem) => {
    navigate(
      `/repositories/${activity.repositoryKey}?path=${encodeURIComponent(
        activity.artifactPath
      )}`
    );
  };

  return (
    <DashboardWidget
      title="Recent Activity"
      icon={<HistoryOutlined />}
      loading={isLoading || isFetching}
      error={error as Error | null}
      onRefresh={handleRefresh}
    >
      {activities.length === 0 ? (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="No recent activity"
          style={{ margin: `${spacing.lg}px 0` }}
        />
      ) : (
        <Timeline
          items={activities.map((activity) => ({
            key: activity.id,
            dot: activityIcons[activity.type],
            color: activityColors[activity.type],
            children: (
              <div>
                <div>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {activityLabels[activity.type]}
                  </Text>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <FileOutlined style={{ fontSize: 12 }} />
                  <Link
                    onClick={() => handleArtifactClick(activity)}
                    style={{ fontSize: 13 }}
                  >
                    {activity.artifactName}
                  </Link>
                </div>
                <div>
                  <Text
                    type="secondary"
                    style={{ fontSize: 11 }}
                  >
                    in {activity.repositoryKey}
                  </Text>
                </div>
                <div>
                  <Text
                    type="secondary"
                    style={{ fontSize: 11, fontStyle: 'italic' }}
                  >
                    {formatRelativeTime(activity.timestamp)}
                  </Text>
                </div>
              </div>
            ),
          }))}
          style={{ marginTop: spacing.sm }}
        />
      )}
    </DashboardWidget>
  );
};

export default RecentActivityWidget;
