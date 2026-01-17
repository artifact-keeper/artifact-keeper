import React from 'react';
import { Form, Input, InputNumber, Switch, Typography, Space, Alert, Collapse } from 'antd';
import type { FormInstance } from 'antd';
import {
  LinkOutlined,
  UserOutlined,
  LockOutlined,
  ClockCircleOutlined,
  SaveOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';

const { Title, Text, Paragraph } = Typography;
const { Password } = Input;

export interface RemoteRepoConfigFormValues {
  remote_url: string;
  remote_username?: string;
  remote_password?: string;
  cache_timeout_seconds?: number;
  store_locally?: boolean;
  offline_mode?: boolean;
  socket_timeout_ms?: number;
  enable_token_auth?: boolean;
  query_params?: string;
}

export interface RemoteRepoConfigProps {
  form: FormInstance<RemoteRepoConfigFormValues>;
}

export const RemoteRepoConfig: React.FC<RemoteRepoConfigProps> = ({ form }) => {
  const storeLocally = Form.useWatch('store_locally', form);

  const collapseItems = [
    {
      key: 'advanced',
      label: (
        <Space>
          <SettingOutlined />
          <span>Advanced Remote Settings</span>
        </Space>
      ),
      children: (
        <div style={{ padding: `${spacing.sm}px 0` }}>
          <Form.Item
            name="socket_timeout_ms"
            label="Socket Timeout (ms)"
            extra="Timeout for remote server connections. Default: 15000ms."
          >
            <InputNumber
              style={{ width: '100%' }}
              placeholder="15000"
              min={1000}
              max={300000}
            />
          </Form.Item>

          <Form.Item
            name="offline_mode"
            valuePropName="checked"
            extra="When enabled, only cached artifacts will be served. Remote server will not be contacted."
          >
            <Space>
              <Switch />
              <Text>Offline Mode</Text>
            </Space>
          </Form.Item>

          <Form.Item
            name="enable_token_auth"
            valuePropName="checked"
            extra="Enable token-based authentication for remote repository access."
          >
            <Space>
              <Switch />
              <Text>Enable Token Authentication</Text>
            </Space>
          </Form.Item>

          <Form.Item
            name="query_params"
            label="Query Parameters"
            extra="Additional query parameters to append to all remote requests."
          >
            <Input
              placeholder="key1=value1&key2=value2"
              style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>
        </div>
      ),
    },
  ];

  return (
    <div style={{ padding: `${spacing.md}px 0`, maxWidth: 600, margin: '0 auto' }}>
      <Title level={4} style={{ marginBottom: spacing.lg, textAlign: 'center' }}>
        <Space>
          <LinkOutlined />
          <span>Remote Repository Settings</span>
        </Space>
      </Title>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: spacing.lg }}
        message="Remote Repository Configuration"
        description={
          <Paragraph style={{ marginBottom: 0 }}>
            A remote repository acts as a caching proxy for an external repository.
            Artifacts are fetched from the remote URL on demand and cached locally.
          </Paragraph>
        }
      />

      <Form
        form={form}
        layout="vertical"
        initialValues={{
          store_locally: true,
          cache_timeout_seconds: 3600,
          socket_timeout_ms: 15000,
          offline_mode: false,
          enable_token_auth: false,
        }}
      >
        <Form.Item
          name="remote_url"
          label={
            <Space>
              <LinkOutlined />
              <span>Remote URL</span>
            </Space>
          }
          rules={[
            { required: true, message: 'Please enter the remote repository URL' },
            { type: 'url', message: 'Please enter a valid URL' },
          ]}
          extra="The URL of the external repository to proxy."
        >
          <Input
            placeholder="https://repo.maven.apache.org/maven2"
            prefix={<LinkOutlined style={{ color: colors.textTertiary }} />}
          />
        </Form.Item>

        <Space orientation="vertical" style={{ width: '100%', marginBottom: spacing.lg }}>
          <Text strong>Authentication (Optional)</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            Provide credentials if the remote repository requires authentication.
          </Text>
        </Space>

        <Form.Item
          name="remote_username"
          label={
            <Space>
              <UserOutlined />
              <span>Username</span>
            </Space>
          }
          extra="Username for remote repository authentication."
        >
          <Input
            placeholder="username"
            prefix={<UserOutlined style={{ color: colors.textTertiary }} />}
            autoComplete="off"
          />
        </Form.Item>

        <Form.Item
          name="remote_password"
          label={
            <Space>
              <LockOutlined />
              <span>Password / Token</span>
            </Space>
          }
          extra="Password or access token for remote repository authentication."
        >
          <Password
            placeholder="Password or token"
            prefix={<LockOutlined style={{ color: colors.textTertiary }} />}
            autoComplete="new-password"
          />
        </Form.Item>

        <Space orientation="vertical" style={{ width: '100%', marginTop: spacing.lg, marginBottom: spacing.md }}>
          <Text strong>Caching Settings</Text>
        </Space>

        <Form.Item
          name="cache_timeout_seconds"
          label={
            <Space>
              <ClockCircleOutlined />
              <span>Cache Timeout (seconds)</span>
            </Space>
          }
          extra="How long to cache metadata and artifact listings. Set to 0 to disable caching."
          rules={[
            { type: 'number', min: 0, message: 'Must be a non-negative number' },
          ]}
        >
          <InputNumber
            style={{ width: '100%' }}
            placeholder="3600"
            min={0}
            max={604800}
            formatter={(value) => {
              if (value === 0) return '0 (disabled)';
              if (value && value >= 3600) return `${value} (${Math.round(Number(value) / 3600)}h)`;
              if (value && value >= 60) return `${value} (${Math.round(Number(value) / 60)}m)`;
              return String(value);
            }}
          />
        </Form.Item>

        <Form.Item
          name="store_locally"
          valuePropName="checked"
          extra={
            storeLocally
              ? 'Downloaded artifacts will be stored locally for faster subsequent access.'
              : 'Artifacts will be fetched from remote on every request. Not recommended for production.'
          }
        >
          <Space>
            <Switch defaultChecked />
            <Space>
              <SaveOutlined />
              <Text>Store Artifacts Locally</Text>
            </Space>
          </Space>
        </Form.Item>

        {!storeLocally && (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: spacing.md }}
            message="Performance Warning"
            description="Disabling local storage will result in slower artifact access and increased bandwidth usage."
          />
        )}

        <Collapse
          items={collapseItems}
          style={{
            backgroundColor: colors.bgContainer,
            borderRadius: borderRadius.lg,
            marginTop: spacing.lg,
          }}
        />
      </Form>
    </div>
  );
};

export default RemoteRepoConfig;
