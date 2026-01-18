import React, { useState, useEffect, useMemo } from 'react';
import { Table, Checkbox, Tag, Input, Space, Typography, Alert, Spin, Tooltip, Badge } from 'antd';
import {
  DatabaseOutlined,
  CloudDownloadOutlined,
  ClusterOutlined,
  SearchOutlined,
  InfoCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { SourceRepository } from '../../types/migration';
import { migrationApi } from '../../api/migration';

const { Text } = Typography;

interface RepositorySelectorProps {
  connectionId: string;
  selectedKeys: string[];
  onSelectionChange: (keys: string[]) => void;
}

const FORMAT_COMPATIBILITY: Record<string, 'full' | 'partial' | 'unsupported'> = {
  maven: 'full',
  npm: 'full',
  docker: 'full',
  pypi: 'full',
  helm: 'full',
  nuget: 'full',
  cargo: 'full',
  go: 'full',
  generic: 'full',
  conan: 'partial',
  conda: 'partial',
  debian: 'partial',
  rpm: 'partial',
};

const getCompatibility = (packageType: string): 'full' | 'partial' | 'unsupported' => {
  return FORMAT_COMPATIBILITY[packageType.toLowerCase()] || 'unsupported';
};

const getRepoTypeIcon = (repoType: string) => {
  switch (repoType.toLowerCase()) {
    case 'local':
      return <DatabaseOutlined />;
    case 'remote':
      return <CloudDownloadOutlined />;
    case 'virtual':
      return <ClusterOutlined />;
    default:
      return <DatabaseOutlined />;
  }
};

const getCompatibilityBadge = (compatibility: 'full' | 'partial' | 'unsupported') => {
  switch (compatibility) {
    case 'full':
      return <Badge status="success" text="Full Support" />;
    case 'partial':
      return (
        <Tooltip title="Will be migrated as Generic format">
          <Badge status="warning" text="Partial Support" />
        </Tooltip>
      );
    case 'unsupported':
      return (
        <Tooltip title="This format cannot be migrated">
          <Badge status="error" text="Unsupported" />
        </Tooltip>
      );
  }
};

export const RepositorySelector: React.FC<RepositorySelectorProps> = ({
  connectionId,
  selectedKeys,
  onSelectionChange,
}) => {
  const [repositories, setRepositories] = useState<SourceRepository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchText, setSearchText] = useState('');
  const [typeFilter, setTypeFilter] = useState<string[]>([]);
  const [formatFilter, setFormatFilter] = useState<string[]>([]);

  useEffect(() => {
    loadRepositories();
  }, [connectionId]);

  const loadRepositories = async () => {
    setLoading(true);
    setError(null);
    try {
      const repos = await migrationApi.listSourceRepositories(connectionId);
      setRepositories(repos);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load repositories');
    } finally {
      setLoading(false);
    }
  };

  const filteredRepositories = useMemo(() => {
    return repositories.filter((repo) => {
      // Search filter
      if (searchText && !repo.key.toLowerCase().includes(searchText.toLowerCase())) {
        return false;
      }
      // Type filter
      if (typeFilter.length > 0 && !typeFilter.includes(repo.type)) {
        return false;
      }
      // Format filter
      if (formatFilter.length > 0 && !formatFilter.includes(repo.package_type.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [repositories, searchText, typeFilter, formatFilter]);

  const uniqueTypes = useMemo(() => {
    return [...new Set(repositories.map((r) => r.type))];
  }, [repositories]);

  const uniqueFormats = useMemo(() => {
    return [...new Set(repositories.map((r) => r.package_type.toLowerCase()))].sort();
  }, [repositories]);

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      const selectableKeys = filteredRepositories
        .filter((r) => getCompatibility(r.package_type) !== 'unsupported')
        .map((r) => r.key);
      onSelectionChange(selectableKeys);
    } else {
      onSelectionChange([]);
    }
  };

  const handleRowSelect = (key: string, checked: boolean) => {
    if (checked) {
      onSelectionChange([...selectedKeys, key]);
    } else {
      onSelectionChange(selectedKeys.filter((k) => k !== key));
    }
  };

  const columns: ColumnsType<SourceRepository> = [
    {
      title: (
        <Checkbox
          checked={selectedKeys.length > 0 && selectedKeys.length === filteredRepositories.filter(r => getCompatibility(r.package_type) !== 'unsupported').length}
          indeterminate={selectedKeys.length > 0 && selectedKeys.length < filteredRepositories.filter(r => getCompatibility(r.package_type) !== 'unsupported').length}
          onChange={(e) => handleSelectAll(e.target.checked)}
        />
      ),
      dataIndex: 'key',
      key: 'select',
      width: 50,
      render: (_: unknown, record: SourceRepository) => {
        const compatibility = getCompatibility(record.package_type);
        return (
          <Checkbox
            checked={selectedKeys.includes(record.key)}
            disabled={compatibility === 'unsupported'}
            onChange={(e) => handleRowSelect(record.key, e.target.checked)}
          />
        );
      },
    },
    {
      title: 'Repository',
      dataIndex: 'key',
      key: 'key',
      sorter: (a, b) => a.key.localeCompare(b.key),
      render: (key: string, record: SourceRepository) => (
        <Space>
          {getRepoTypeIcon(record.type)}
          <Text strong>{key}</Text>
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      filters: uniqueTypes.map((t) => ({ text: t, value: t })),
      onFilter: (value, record) => record.type === value,
      render: (type: string) => {
        const color = type === 'local' ? 'blue' : type === 'remote' ? 'green' : 'purple';
        return <Tag color={color}>{type}</Tag>;
      },
    },
    {
      title: 'Format',
      dataIndex: 'package_type',
      key: 'package_type',
      width: 120,
      filters: uniqueFormats.map((f) => ({ text: f, value: f })),
      onFilter: (value, record) => record.package_type.toLowerCase() === value,
      render: (packageType: string) => <Tag>{packageType}</Tag>,
    },
    {
      title: 'Compatibility',
      key: 'compatibility',
      width: 150,
      render: (_: unknown, record: SourceRepository) => {
        const compatibility = getCompatibility(record.package_type);
        return getCompatibilityBadge(compatibility);
      },
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (desc: string | undefined) => desc || <Text type="secondary">-</Text>,
    },
  ];

  const summary = useMemo(() => {
    const total = repositories.length;
    const selected = selectedKeys.length;
    const supported = repositories.filter(
      (r) => getCompatibility(r.package_type) !== 'unsupported'
    ).length;
    const unsupported = total - supported;
    return { total, selected, supported, unsupported };
  }, [repositories, selectedKeys]);

  if (error) {
    return (
      <Alert
        type="error"
        message="Failed to load repositories"
        description={error}
        showIcon
      />
    );
  }

  return (
    <div>
      <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }}>
        <Input
          placeholder="Search repositories..."
          prefix={<SearchOutlined />}
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          style={{ width: 300 }}
          allowClear
        />
        <Space>
          <Text>
            {summary.selected} of {summary.supported} repositories selected
          </Text>
          {summary.unsupported > 0 && (
            <Tooltip title={`${summary.unsupported} repositories have unsupported formats and cannot be migrated`}>
              <InfoCircleOutlined style={{ color: '#faad14' }} />
            </Tooltip>
          )}
        </Space>
      </Space>

      <Spin spinning={loading}>
        <Table
          columns={columns}
          dataSource={filteredRepositories}
          rowKey="key"
          size="middle"
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `${total} repositories`,
          }}
          scroll={{ x: 800 }}
        />
      </Spin>
    </div>
  );
};

export default RepositorySelector;
