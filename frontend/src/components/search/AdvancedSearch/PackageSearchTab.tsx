import React from 'react';
import { Form, Input, Select, Space } from 'antd';
import type { FormInstance } from 'antd';
import { colors, spacing } from '../../../styles/tokens';
import type { RepositoryFormat } from '../../../types';

const { Option } = Select;

export interface PackageSearchTabProps {
  form: FormInstance;
}

const formatOptions: { value: RepositoryFormat; label: string }[] = [
  { value: 'maven', label: 'Maven' },
  { value: 'npm', label: 'npm' },
  { value: 'pypi', label: 'PyPI' },
  { value: 'docker', label: 'Docker' },
  { value: 'helm', label: 'Helm' },
  { value: 'nuget', label: 'NuGet' },
  { value: 'cargo', label: 'Cargo' },
  { value: 'go', label: 'Go' },
  { value: 'rpm', label: 'RPM' },
  { value: 'debian', label: 'Debian' },
  { value: 'generic', label: 'Generic' },
];

export const PackageSearchTab: React.FC<PackageSearchTabProps> = ({ form }) => {
  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        <Form.Item
          name={['package', 'name']}
          label="Package Name"
          style={{ marginBottom: 0 }}
        >
          <Input
            placeholder="Enter package name (supports wildcards)"
            allowClear
          />
        </Form.Item>

        <Form.Item
          name={['package', 'version']}
          label="Version"
          style={{ marginBottom: 0 }}
        >
          <Input
            placeholder="Enter version (e.g., 1.0.0, 1.*, >=2.0.0)"
            allowClear
          />
        </Form.Item>

        <Form.Item
          name={['package', 'repository']}
          label="Repository"
          style={{ marginBottom: 0 }}
        >
          <Select
            placeholder="Select repository (optional)"
            allowClear
            showSearch
            optionFilterProp="children"
          >
            <Option value="">All Repositories</Option>
          </Select>
        </Form.Item>

        <Form.Item
          name={['package', 'format']}
          label="Package Format"
          style={{ marginBottom: 0 }}
        >
          <Select
            placeholder="Select format type (optional)"
            allowClear
            showSearch
            optionFilterProp="label"
            options={formatOptions}
          />
        </Form.Item>
      </Space>
    </div>
  );
};

export default PackageSearchTab;
