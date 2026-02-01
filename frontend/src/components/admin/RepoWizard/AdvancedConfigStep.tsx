import React from 'react';
import { Form, Input, InputNumber, Select, Switch, Typography, Space, Collapse, Divider } from 'antd';
import type { FormInstance } from 'antd';
import {
  HddOutlined,
  DeleteOutlined,
  FilterOutlined,
  SettingOutlined,
  FileSearchOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { RepositoryType } from '../../../types';

const { Title, Text } = Typography;
const { TextArea } = Input;

export interface AdvancedConfigFormValues {
  quota_bytes?: number;
  cleanup_enabled?: boolean;
  cleanup_retention_days?: number;
  cleanup_max_versions?: number;
  include_patterns?: string;
  exclude_patterns?: string;
  handle_releases?: boolean;
  handle_snapshots?: boolean;
  suppress_pom_checks?: boolean;
  calculate_checksums?: boolean;
}

export interface AdvancedConfigStepProps {
  form: FormInstance<AdvancedConfigFormValues>;
  repoType?: RepositoryType;
}

const storageSizeOptions = [
  { label: 'No limit', value: 0 },
  { label: '1 GB', value: 1073741824 },
  { label: '5 GB', value: 5368709120 },
  { label: '10 GB', value: 10737418240 },
  { label: '50 GB', value: 53687091200 },
  { label: '100 GB', value: 107374182400 },
  { label: 'Custom', value: -1 },
];

export const AdvancedConfigStep: React.FC<AdvancedConfigStepProps> = ({
  form,
  repoType,
}) => {
  const [customQuota, setCustomQuota] = React.useState(false);
  const cleanupEnabled = Form.useWatch('cleanup_enabled', form);

  const handleQuotaSelectChange = (value: number) => {
    if (value === -1) {
      setCustomQuota(true);
      form.setFieldValue('quota_bytes', undefined);
    } else {
      setCustomQuota(false);
      form.setFieldValue('quota_bytes', value === 0 ? undefined : value);
    }
  };

  const collapseItems = [
    {
      key: 'storage',
      label: (
        <Space>
          <HddOutlined />
          <span>Storage Settings</span>
        </Space>
      ),
      children: (
        <div style={{ padding: `${spacing.sm}px 0` }}>
          <Form.Item
            label="Storage Quota"
            extra="Maximum storage space allowed for this repository."
          >
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Select
                style={{ width: '100%' }}
                placeholder="Select quota"
                options={storageSizeOptions}
                onChange={handleQuotaSelectChange}
                defaultValue={0}
              />
              {customQuota && (
                <Form.Item
                  name="quota_bytes"
                  noStyle
                  rules={[
                    { required: customQuota, message: 'Please enter a custom quota' },
                  ]}
                >
                  <InputNumber
                    style={{ width: '100%' }}
                    placeholder="Enter quota in bytes"
                    min={1048576}
                    formatter={((value: string | undefined) =>
                      value ? `${Math.round(Number(value) / 1073741824 * 100) / 100} GB` : '') as never
                    }
                    parser={((value: string | undefined) =>
                      value ? Number(value?.replace(/[^\d.]/g, '')) * 1073741824 : 0) as never
                    }
                  />
                </Form.Item>
              )}
            </Space>
          </Form.Item>
        </div>
      ),
    },
    {
      key: 'cleanup',
      label: (
        <Space>
          <DeleteOutlined />
          <span>Cleanup Policies</span>
        </Space>
      ),
      children: (
        <div style={{ padding: `${spacing.sm}px 0` }}>
          <Form.Item
            name="cleanup_enabled"
            valuePropName="checked"
            extra="Enable automatic cleanup of old artifacts."
          >
            <Switch checkedChildren="Enabled" unCheckedChildren="Disabled" />
          </Form.Item>

          {cleanupEnabled && (
            <>
              <Form.Item
                name="cleanup_retention_days"
                label="Retention Period (days)"
                extra="Delete artifacts older than this many days."
                rules={[{ type: 'number', min: 1, message: 'Must be at least 1 day' }]}
              >
                <InputNumber
                  style={{ width: '100%' }}
                  placeholder="90"
                  min={1}
                  max={3650}
                />
              </Form.Item>

              <Form.Item
                name="cleanup_max_versions"
                label="Maximum Versions"
                extra="Keep only the most recent N versions per artifact."
                rules={[{ type: 'number', min: 1, message: 'Must be at least 1 version' }]}
              >
                <InputNumber
                  style={{ width: '100%' }}
                  placeholder="10"
                  min={1}
                  max={1000}
                />
              </Form.Item>
            </>
          )}
        </div>
      ),
    },
    {
      key: 'patterns',
      label: (
        <Space>
          <FilterOutlined />
          <span>Include/Exclude Patterns</span>
        </Space>
      ),
      children: (
        <div style={{ padding: `${spacing.sm}px 0` }}>
          <Form.Item
            name="include_patterns"
            label="Include Patterns"
            extra="Only artifacts matching these patterns will be stored. One pattern per line. Supports wildcards (*). Leave empty to include all."
          >
            <TextArea
              placeholder="**/*.jar&#10;**/*.pom&#10;com/mycompany/**"
              rows={3}
              style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>

          <Form.Item
            name="exclude_patterns"
            label="Exclude Patterns"
            extra="Artifacts matching these patterns will be rejected. One pattern per line. Supports wildcards (*)."
          >
            <TextArea
              placeholder="**/*-SNAPSHOT/**&#10;**/temp/**"
              rows={3}
              style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>
        </div>
      ),
    },
    {
      key: 'metadata',
      label: (
        <Space>
          <FileSearchOutlined />
          <span>Metadata Handling</span>
        </Space>
      ),
      children: (
        <div style={{ padding: `${spacing.sm}px 0` }}>
          {repoType === 'local' && (
            <>
              <Form.Item
                name="handle_releases"
                valuePropName="checked"
                extra="Allow release artifacts to be deployed to this repository."
              >
                <Space>
                  <Switch defaultChecked />
                  <Text>Handle Releases</Text>
                </Space>
              </Form.Item>

              <Form.Item
                name="handle_snapshots"
                valuePropName="checked"
                extra="Allow snapshot artifacts to be deployed to this repository."
              >
                <Space>
                  <Switch defaultChecked />
                  <Text>Handle Snapshots</Text>
                </Space>
              </Form.Item>

              <Divider style={{ margin: `${spacing.sm}px 0` }} />
            </>
          )}

          <Form.Item
            name="suppress_pom_checks"
            valuePropName="checked"
            extra="Suppress POM consistency checks for Maven artifacts."
          >
            <Space>
              <Switch />
              <Text>Suppress POM Consistency Checks</Text>
            </Space>
          </Form.Item>

          <Form.Item
            name="calculate_checksums"
            valuePropName="checked"
            extra="Automatically calculate and verify checksums for artifacts."
          >
            <Space>
              <Switch defaultChecked />
              <Text>Calculate Checksums</Text>
            </Space>
          </Form.Item>
        </div>
      ),
    },
  ];

  return (
    <div style={{ padding: `${spacing.md}px 0`, maxWidth: 700, margin: '0 auto' }}>
      <Title level={4} style={{ marginBottom: spacing.lg, textAlign: 'center' }}>
        <Space>
          <SettingOutlined />
          <span>Advanced Settings</span>
        </Space>
      </Title>

      <Text type="secondary" style={{ display: 'block', textAlign: 'center', marginBottom: spacing.lg }}>
        Configure optional advanced settings for your repository. These can be modified later.
      </Text>

      <Form
        form={form}
        layout="vertical"
        initialValues={{
          cleanup_enabled: false,
          handle_releases: true,
          handle_snapshots: true,
          calculate_checksums: true,
          suppress_pom_checks: false,
        }}
      >
        <Collapse
          items={collapseItems}
          defaultActiveKey={['storage']}
          style={{
            backgroundColor: colors.bgContainer,
            borderRadius: borderRadius.lg,
          }}
        />
      </Form>
    </div>
  );
};

export default AdvancedConfigStep;
