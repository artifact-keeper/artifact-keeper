import React, { useState, useMemo, useCallback, useEffect } from 'react';
import {
  Card,
  Input,
  Select,
  Space,
  Typography,
  Tag,
  List,
  Switch,
  Divider,
  Alert,
  Empty,
} from 'antd';
import {
  DatabaseOutlined,
  FilterOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { Repository } from '../../../types';

const { Text, Title } = Typography;

export interface PatternValue {
  includePatterns: string[];
  excludePatterns: string[];
  selectedRepositories: string[];
}

export interface RepositoryPatternSelectorProps {
  value?: PatternValue;
  onChange?: (value: PatternValue) => void;
  repositories: Repository[];
}

const matchPattern = (repoKey: string, pattern: string): boolean => {
  if (!pattern) return false;

  const regexPattern = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '{{DOUBLE_STAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/{{DOUBLE_STAR}}/g, '.*');

  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(repoKey);
};

export const RepositoryPatternSelector: React.FC<RepositoryPatternSelectorProps> = ({
  value,
  onChange,
  repositories,
}) => {
  const [includeInput, setIncludeInput] = useState('');
  const [excludeInput, setExcludeInput] = useState('');
  const [usePatternMode, setUsePatternMode] = useState(true);

  const currentValue: PatternValue = value || {
    includePatterns: [],
    excludePatterns: [],
    selectedRepositories: [],
  };

  const handleChange = useCallback(
    (updates: Partial<PatternValue>) => {
      onChange?.({
        ...currentValue,
        ...updates,
      });
    },
    [currentValue, onChange]
  );

  const handleAddIncludePattern = useCallback(() => {
    const trimmed = includeInput.trim();
    if (trimmed && !currentValue.includePatterns.includes(trimmed)) {
      handleChange({
        includePatterns: [...currentValue.includePatterns, trimmed],
      });
      setIncludeInput('');
    }
  }, [includeInput, currentValue.includePatterns, handleChange]);

  const handleAddExcludePattern = useCallback(() => {
    const trimmed = excludeInput.trim();
    if (trimmed && !currentValue.excludePatterns.includes(trimmed)) {
      handleChange({
        excludePatterns: [...currentValue.excludePatterns, trimmed],
      });
      setExcludeInput('');
    }
  }, [excludeInput, currentValue.excludePatterns, handleChange]);

  const handleRemoveIncludePattern = useCallback(
    (pattern: string) => {
      handleChange({
        includePatterns: currentValue.includePatterns.filter((p) => p !== pattern),
      });
    },
    [currentValue.includePatterns, handleChange]
  );

  const handleRemoveExcludePattern = useCallback(
    (pattern: string) => {
      handleChange({
        excludePatterns: currentValue.excludePatterns.filter((p) => p !== pattern),
      });
    },
    [currentValue.excludePatterns, handleChange]
  );

  const handleRepositorySelect = useCallback(
    (selectedKeys: string[]) => {
      handleChange({
        selectedRepositories: selectedKeys,
      });
    },
    [handleChange]
  );

  const matchingRepositories = useMemo(() => {
    if (!usePatternMode) {
      return repositories.filter((repo) =>
        currentValue.selectedRepositories.includes(repo.key)
      );
    }

    if (currentValue.includePatterns.length === 0) {
      return [];
    }

    return repositories.filter((repo) => {
      const isIncluded = currentValue.includePatterns.some((pattern) =>
        matchPattern(repo.key, pattern)
      );
      const isExcluded = currentValue.excludePatterns.some((pattern) =>
        matchPattern(repo.key, pattern)
      );
      return isIncluded && !isExcluded;
    });
  }, [repositories, currentValue, usePatternMode]);

  const excludedRepositories = useMemo(() => {
    if (!usePatternMode || currentValue.excludePatterns.length === 0) {
      return [];
    }

    return repositories.filter((repo) => {
      const isIncluded = currentValue.includePatterns.some((pattern) =>
        matchPattern(repo.key, pattern)
      );
      const isExcluded = currentValue.excludePatterns.some((pattern) =>
        matchPattern(repo.key, pattern)
      );
      return isIncluded && isExcluded;
    });
  }, [repositories, currentValue, usePatternMode]);

  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: spacing.md,
        }}
      >
        <Title level={5} style={{ margin: 0 }}>
          Repository Selection
        </Title>
        <Space>
          <Text type="secondary">Pattern mode</Text>
          <Switch
            checked={usePatternMode}
            onChange={setUsePatternMode}
            checkedChildren="Pattern"
            unCheckedChildren="Select"
          />
        </Space>
      </div>

      {usePatternMode ? (
        <div>
          <Alert
            message="Wildcard Patterns"
            description={
              <div>
                <Text type="secondary">
                  Use <code>*</code> to match any characters within a segment, and{' '}
                  <code>**</code> to match across segments.
                </Text>
                <br />
                <Text type="secondary">
                  Examples: <code>npm-*</code>, <code>docker-prod-*</code>,{' '}
                  <code>**-release</code>
                </Text>
              </div>
            }
            type="info"
            showIcon
            style={{ marginBottom: spacing.md }}
          />

          <Card
            size="small"
            title={
              <Space>
                <CheckCircleOutlined style={{ color: colors.success }} />
                <Text>Include Patterns</Text>
              </Space>
            }
            style={{ marginBottom: spacing.md }}
          >
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Input.Search
                placeholder="Add include pattern (e.g., npm-*)"
                value={includeInput}
                onChange={(e) => setIncludeInput(e.target.value)}
                onSearch={handleAddIncludePattern}
                enterButton="Add"
              />
              <div style={{ minHeight: 32 }}>
                {currentValue.includePatterns.length === 0 ? (
                  <Text type="secondary">No include patterns defined</Text>
                ) : (
                  <Space wrap>
                    {currentValue.includePatterns.map((pattern) => (
                      <Tag
                        key={pattern}
                        closable
                        onClose={() => handleRemoveIncludePattern(pattern)}
                        style={{ fontFamily: 'monospace' }}
                        color="green"
                      >
                        {pattern}
                      </Tag>
                    ))}
                  </Space>
                )}
              </div>
            </Space>
          </Card>

          <Card
            size="small"
            title={
              <Space>
                <CloseCircleOutlined style={{ color: colors.error }} />
                <Text>Exclude Patterns</Text>
              </Space>
            }
            style={{ marginBottom: spacing.md }}
          >
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Input.Search
                placeholder="Add exclude pattern (e.g., *-test)"
                value={excludeInput}
                onChange={(e) => setExcludeInput(e.target.value)}
                onSearch={handleAddExcludePattern}
                enterButton="Add"
              />
              <div style={{ minHeight: 32 }}>
                {currentValue.excludePatterns.length === 0 ? (
                  <Text type="secondary">No exclude patterns defined</Text>
                ) : (
                  <Space wrap>
                    {currentValue.excludePatterns.map((pattern) => (
                      <Tag
                        key={pattern}
                        closable
                        onClose={() => handleRemoveExcludePattern(pattern)}
                        style={{ fontFamily: 'monospace' }}
                        color="red"
                      >
                        {pattern}
                      </Tag>
                    ))}
                  </Space>
                )}
              </div>
            </Space>
          </Card>
        </div>
      ) : (
        <Card size="small" title="Select Repositories">
          <Select
            mode="multiple"
            placeholder="Select repositories"
            value={currentValue.selectedRepositories}
            onChange={handleRepositorySelect}
            style={{ width: '100%' }}
            optionFilterProp="label"
            showSearch
            options={repositories.map((repo) => ({
              value: repo.key,
              label: repo.key,
              description: repo.description,
            }))}
            optionRender={(option) => (
              <Space>
                <DatabaseOutlined />
                <span>{option.data.label}</span>
                {option.data.description && (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    - {option.data.description}
                  </Text>
                )}
              </Space>
            )}
          />
        </Card>
      )}

      <Divider orientation="left">
        <Space>
          <FilterOutlined />
          <Text>Preview: Matching Repositories ({matchingRepositories.length})</Text>
        </Space>
      </Divider>

      <Card
        size="small"
        style={{
          maxHeight: 200,
          overflow: 'auto',
          backgroundColor: colors.bgLayout,
        }}
      >
        {matchingRepositories.length === 0 ? (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description={
              usePatternMode
                ? 'Add include patterns to see matching repositories'
                : 'Select repositories to include'
            }
          />
        ) : (
          <List
            size="small"
            dataSource={matchingRepositories}
            renderItem={(repo) => (
              <List.Item style={{ padding: `${spacing.xs}px 0` }}>
                <Space>
                  <CheckCircleOutlined style={{ color: colors.success }} />
                  <Text strong>{repo.key}</Text>
                  <Tag>{repo.format.toUpperCase()}</Tag>
                  <Tag color={repo.repo_type === 'local' ? 'green' : 'blue'}>
                    {repo.repo_type}
                  </Tag>
                </Space>
              </List.Item>
            )}
          />
        )}
      </Card>

      {excludedRepositories.length > 0 && (
        <>
          <Divider orientation="left">
            <Space>
              <CloseCircleOutlined style={{ color: colors.error }} />
              <Text type="secondary">
                Excluded Repositories ({excludedRepositories.length})
              </Text>
            </Space>
          </Divider>

          <Card
            size="small"
            style={{
              maxHeight: 150,
              overflow: 'auto',
              backgroundColor: colors.bgLayout,
            }}
          >
            <List
              size="small"
              dataSource={excludedRepositories}
              renderItem={(repo) => (
                <List.Item style={{ padding: `${spacing.xs}px 0` }}>
                  <Space>
                    <CloseCircleOutlined style={{ color: colors.error }} />
                    <Text delete type="secondary">
                      {repo.key}
                    </Text>
                  </Space>
                </List.Item>
              )}
            />
          </Card>
        </>
      )}
    </div>
  );
};

export default RepositoryPatternSelector;
