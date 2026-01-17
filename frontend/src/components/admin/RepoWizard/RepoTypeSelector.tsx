import React from 'react';
import { Card, Typography, Space, Row, Col } from 'antd';
import {
  DatabaseOutlined,
  CloudOutlined,
  ClusterOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { RepositoryType } from '../../../types';

const { Text, Title } = Typography;

export interface RepoTypeSelectorProps {
  value?: RepositoryType;
  onChange: (type: RepositoryType) => void;
}

interface RepoTypeOption {
  type: RepositoryType;
  title: string;
  description: string;
  icon: React.ReactNode;
}

const repoTypeOptions: RepoTypeOption[] = [
  {
    type: 'local',
    title: 'Local Repository',
    description: 'Store artifacts directly in this repository. Ideal for hosting your own packages and artifacts.',
    icon: <DatabaseOutlined style={{ fontSize: 32 }} />,
  },
  {
    type: 'remote',
    title: 'Remote Repository',
    description: 'Proxy and cache artifacts from external repositories. Reduces latency and provides offline access.',
    icon: <CloudOutlined style={{ fontSize: 32 }} />,
  },
  {
    type: 'virtual',
    title: 'Virtual Repository',
    description: 'Aggregate multiple repositories under a single URL. Simplifies client configuration.',
    icon: <ClusterOutlined style={{ fontSize: 32 }} />,
  },
];

export const RepoTypeSelector: React.FC<RepoTypeSelectorProps> = ({
  value,
  onChange,
}) => {
  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Title level={4} style={{ marginBottom: spacing.lg, textAlign: 'center' }}>
        Select Repository Type
      </Title>
      <Row gutter={[spacing.md, spacing.md]} justify="center">
        {repoTypeOptions.map((option) => {
          const isSelected = value === option.type;
          return (
            <Col key={option.type} xs={24} sm={12} md={8}>
              <Card
                hoverable
                onClick={() => onChange(option.type)}
                style={{
                  height: '100%',
                  borderRadius: borderRadius.lg,
                  borderColor: isSelected ? colors.primary : colors.border,
                  borderWidth: isSelected ? 2 : 1,
                  backgroundColor: isSelected ? colors.bgContainerLight : colors.bgContainer,
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                }}
                styles={{
                  body: {
                    padding: spacing.lg,
                    textAlign: 'center',
                    height: '100%',
                  },
                }}
              >
                <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
                  <div
                    style={{
                      width: 64,
                      height: 64,
                      borderRadius: borderRadius.full,
                      backgroundColor: isSelected ? colors.primary : colors.bgLayout,
                      color: isSelected ? '#fff' : colors.textSecondary,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      margin: '0 auto',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    {option.icon}
                  </div>
                  <div>
                    <Text
                      strong
                      style={{
                        fontSize: 16,
                        display: 'block',
                        marginBottom: spacing.xs,
                        color: isSelected ? colors.primary : colors.textPrimary,
                      }}
                    >
                      {option.title}
                    </Text>
                    <Text
                      type="secondary"
                      style={{
                        fontSize: 13,
                        lineHeight: 1.5,
                      }}
                    >
                      {option.description}
                    </Text>
                  </div>
                </Space>
              </Card>
            </Col>
          );
        })}
      </Row>
    </div>
  );
};

export default RepoTypeSelector;
