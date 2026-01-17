import React from 'react';
import { Row, Col, Statistic, Tag } from 'antd';
import { FileOutlined, DatabaseOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { DashboardWidget } from '../DashboardWidget';
import { adminApi, repositoriesApi } from '../../../api';
import { useAuth } from '../../../contexts';
import { colors, spacing } from '../../../styles/tokens';
import type { RepositoryFormat } from '../../../types';

interface FormatCount {
  format: RepositoryFormat;
  count: number;
}

const formatColors: Record<RepositoryFormat, string> = {
  maven: '#C71A36',
  docker: '#2496ED',
  npm: '#CB3837',
  pypi: '#3776AB',
  helm: '#0F1689',
  rpm: '#EE0000',
  debian: '#A80030',
  go: '#00ADD8',
  nuget: '#004880',
  cargo: '#DEA584',
  generic: colors.textSecondary,
};

const formatLabels: Record<RepositoryFormat, string> = {
  maven: 'Maven',
  docker: 'Docker',
  npm: 'NPM',
  pypi: 'PyPI',
  helm: 'Helm',
  rpm: 'RPM',
  debian: 'Debian',
  go: 'Go',
  nuget: 'NuGet',
  cargo: 'Cargo',
  generic: 'Generic',
};

export const ArtifactCountWidget: React.FC = () => {
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const {
    data: stats,
    isLoading: statsLoading,
    error: statsError,
    isFetching: statsFetching,
  } = useQuery({
    queryKey: ['admin-stats'],
    queryFn: () => adminApi.getStats(),
    enabled: user?.is_admin,
  });

  const {
    data: repositories,
    isLoading: reposLoading,
    error: reposError,
    isFetching: reposFetching,
  } = useQuery({
    queryKey: ['repositories-list'],
    queryFn: () => repositoriesApi.list({ per_page: 100 }),
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['admin-stats'] });
    queryClient.invalidateQueries({ queryKey: ['repositories-list'] });
  };

  const isLoading = statsLoading || reposLoading;
  const isFetching = statsFetching || reposFetching;
  const error = statsError || reposError;

  const formatCounts: FormatCount[] = React.useMemo(() => {
    if (!repositories?.items) return [];

    const counts = repositories.items.reduce((acc, repo) => {
      acc[repo.format] = (acc[repo.format] || 0) + 1;
      return acc;
    }, {} as Record<RepositoryFormat, number>);

    return Object.entries(counts)
      .map(([format, count]) => ({ format: format as RepositoryFormat, count }))
      .sort((a, b) => b.count - a.count);
  }, [repositories?.items]);

  return (
    <DashboardWidget
      title="Artifacts Overview"
      icon={<FileOutlined />}
      loading={isLoading || isFetching}
      error={error as Error | null}
      onRefresh={handleRefresh}
    >
      <Row gutter={[spacing.md, spacing.md]}>
        <Col span={12}>
          <Statistic
            title="Total Artifacts"
            value={stats?.total_artifacts ?? 0}
            prefix={<FileOutlined style={{ color: colors.primary }} />}
            styles={{ content: { color: colors.textPrimary } }}
          />
        </Col>
        <Col span={12}>
          <Statistic
            title="Repositories"
            value={stats?.total_repositories ?? repositories?.pagination?.total ?? 0}
            prefix={<DatabaseOutlined style={{ color: colors.info }} />}
            styles={{ content: { color: colors.textPrimary } }}
          />
        </Col>
      </Row>

      {formatCounts.length > 0 && (
        <div style={{ marginTop: spacing.md }}>
          <div
            style={{
              fontSize: 12,
              color: colors.textSecondary,
              marginBottom: spacing.xs,
            }}
          >
            Repositories by Format
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: spacing.xxs }}>
            {formatCounts.map(({ format, count }) => (
              <Tag
                key={format}
                color={formatColors[format]}
                style={{ margin: 0 }}
              >
                {formatLabels[format]}: {count}
              </Tag>
            ))}
          </div>
        </div>
      )}
    </DashboardWidget>
  );
};

export default ArtifactCountWidget;
