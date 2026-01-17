import React, { useState, useCallback } from 'react';
import {
  Typography,
  Tabs,
  Space,
  Tag,
  Descriptions,
  Card,
  Statistic,
  Row,
  Col,
  Button,
  Skeleton,
} from 'antd';
import type { TabsProps } from 'antd';
import {
  DownloadOutlined,
  ClockCircleOutlined,
  TagOutlined,
  UserOutlined,
  GlobalOutlined,
  CopyOutlined,
  BuildOutlined,
  BoxPlotOutlined,
  CodeOutlined,
  ContainerOutlined,
  CloudServerOutlined,
  AppstoreOutlined,
  BlockOutlined,
  DeploymentUnitOutlined,
  SettingOutlined,
  FileZipOutlined,
  FileOutlined,
} from '@ant-design/icons';
import type { Package, PackageVersion, PackageDependency, PackageType } from '../../../types';
import { VersionHistory } from './VersionHistory';
import { DependencyTree } from './DependencyTree';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import { message } from 'antd';

const { Title, Text, Paragraph, Link } = Typography;

export interface PackageDetailProps {
  package: Package;
  versions?: PackageVersion[];
  dependencies?: PackageDependency[];
  loading?: boolean;
  onVersionSelect?: (version: PackageVersion) => void;
  onDependencySelect?: (dependency: PackageDependency) => void;
}

const packageTypeIcons: Record<PackageType, React.ReactNode> = {
  maven: <BuildOutlined />,
  gradle: <BuildOutlined />,
  npm: <BoxPlotOutlined />,
  pypi: <CodeOutlined />,
  nuget: <AppstoreOutlined />,
  go: <DeploymentUnitOutlined />,
  rubygems: <BlockOutlined />,
  docker: <ContainerOutlined />,
  helm: <CloudServerOutlined />,
  rpm: <SettingOutlined />,
  debian: <FileZipOutlined />,
  conan: <BlockOutlined />,
  cargo: <BlockOutlined />,
  generic: <FileOutlined />,
};

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
    month: 'long',
    day: 'numeric',
  });
};

export const PackageDetail: React.FC<PackageDetailProps> = ({
  package: pkg,
  versions = [],
  dependencies = [],
  loading = false,
  onVersionSelect,
  onDependencySelect,
}) => {
  const [activeTab, setActiveTab] = useState('overview');

  const handleTabChange = useCallback((key: string) => {
    setActiveTab(key);
  }, []);

  const handleCopyName = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(pkg.name);
      message.success('Package name copied to clipboard');
    } catch {
      message.error('Failed to copy package name');
    }
  }, [pkg.name]);

  const icon = packageTypeIcons[pkg.package_type] || <FileOutlined />;
  const typeLabel = packageTypeLabels[pkg.package_type] || pkg.package_type;

  const tabItems: TabsProps['items'] = [
    {
      key: 'overview',
      label: 'Overview',
      children: (
        <div style={{ padding: `${spacing.md}px 0` }}>
          <Row gutter={[spacing.lg, spacing.lg]}>
            <Col xs={24} md={16}>
              <Card
                title="Details"
                style={{ borderRadius: borderRadius.lg }}
                styles={{ body: { padding: spacing.md } }}
              >
                <Descriptions column={{ xs: 1, sm: 2, md: 2 }} size="small">
                  <Descriptions.Item label="Package Type">
                    <Space>
                      {icon}
                      <Text>{typeLabel}</Text>
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="Repository">
                    <Text>{pkg.repository_key}</Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Latest Version">
                    <Tag color="green">{pkg.latest_version || 'N/A'}</Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="Total Versions">
                    <Text>{pkg.version_count}</Text>
                  </Descriptions.Item>
                  {pkg.license && (
                    <Descriptions.Item label="License">
                      <Text>{pkg.license}</Text>
                    </Descriptions.Item>
                  )}
                  {pkg.author && (
                    <Descriptions.Item label="Author">
                      <Space>
                        <UserOutlined />
                        <Text>{pkg.author}</Text>
                      </Space>
                    </Descriptions.Item>
                  )}
                  <Descriptions.Item label="Created">
                    <Space>
                      <ClockCircleOutlined />
                      <Text>{formatDate(pkg.created_at)}</Text>
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="Last Updated">
                    <Space>
                      <ClockCircleOutlined />
                      <Text>{formatDate(pkg.updated_at)}</Text>
                    </Space>
                  </Descriptions.Item>
                </Descriptions>

                {pkg.homepage_url && (
                  <div style={{ marginTop: spacing.md }}>
                    <Space>
                      <GlobalOutlined />
                      <Link href={pkg.homepage_url} target="_blank">
                        {pkg.homepage_url}
                      </Link>
                    </Space>
                  </div>
                )}
              </Card>
            </Col>

            <Col xs={24} md={8}>
              <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
                <Card style={{ borderRadius: borderRadius.lg }}>
                  <Statistic
                    title="Total Downloads"
                    value={pkg.total_downloads}
                    prefix={<DownloadOutlined />}
                    styles={{ content: { color: colors.primary } }}
                  />
                </Card>

                <Card style={{ borderRadius: borderRadius.lg }}>
                  <Statistic
                    title="Total Size"
                    value={formatFileSize(pkg.total_size_bytes)}
                    styles={{ content: { fontSize: 20 } }}
                  />
                </Card>

                <Card style={{ borderRadius: borderRadius.lg }}>
                  <Statistic
                    title="Versions"
                    value={pkg.version_count}
                    prefix={<TagOutlined />}
                  />
                </Card>
              </Space>
            </Col>
          </Row>
        </div>
      ),
    },
    {
      key: 'versions',
      label: `Versions (${versions.length})`,
      children: (
        <div style={{ padding: `${spacing.md}px 0` }}>
          <VersionHistory
            versions={versions}
            onSelect={onVersionSelect}
          />
        </div>
      ),
    },
    {
      key: 'dependencies',
      label: `Dependencies (${dependencies.length})`,
      children: (
        <div style={{ padding: `${spacing.md}px 0` }}>
          <DependencyTree
            dependencies={dependencies}
            onSelect={onDependencySelect}
          />
        </div>
      ),
    },
  ];

  if (loading) {
    return (
      <div style={{ padding: spacing.lg }}>
        <Skeleton active avatar paragraph={{ rows: 4 }} />
        <Skeleton active paragraph={{ rows: 8 }} style={{ marginTop: spacing.lg }} />
      </div>
    );
  }

  return (
    <div>
      <div
        style={{
          backgroundColor: colors.bgContainer,
          padding: spacing.lg,
          borderBottom: `1px solid ${colors.borderLight}`,
        }}
      >
        <Space orientation="vertical" size="small" style={{ width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: spacing.md }}>
            <div
              style={{
                width: 56,
                height: 56,
                borderRadius: borderRadius.lg,
                backgroundColor: colors.bgLayout,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 28,
                color: colors.primary,
                flexShrink: 0,
              }}
            >
              {icon}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <Space align="center" wrap>
                <Title level={3} style={{ margin: 0 }}>
                  {pkg.name}
                </Title>
                <Button
                  type="text"
                  icon={<CopyOutlined />}
                  onClick={handleCopyName}
                  size="small"
                  aria-label="Copy package name"
                />
              </Space>
              {pkg.latest_version && (
                <div style={{ marginTop: spacing.xxs }}>
                  <Tag color="green" icon={<TagOutlined />}>
                    v{pkg.latest_version}
                  </Tag>
                  <Tag>{typeLabel}</Tag>
                </div>
              )}
            </div>
          </div>

          {pkg.description && (
            <Paragraph
              type="secondary"
              style={{ marginBottom: 0, marginTop: spacing.sm }}
            >
              {pkg.description}
            </Paragraph>
          )}
        </Space>
      </div>

      <div style={{ padding: `0 ${spacing.lg}px` }}>
        <Tabs
          activeKey={activeTab}
          onChange={handleTabChange}
          items={tabItems}
        />
      </div>
    </div>
  );
};

export default PackageDetail;
