import React, { useState } from 'react';
import { Form, Input, Select, Button, Alert, Space } from 'antd';
import { LockOutlined, UserOutlined, KeyOutlined } from '@ant-design/icons';
import type { SourceConnection, ConnectionCredentials, ConnectionTestResult } from '../../types/migration';
import { migrationApi } from '../../api/migration';

const { Option } = Select;

interface SourceConnectionFormProps {
  initialValues?: Partial<SourceConnection & { credentials: ConnectionCredentials }>;
  onSuccess?: (connection: SourceConnection) => void;
  onCancel?: () => void;
  mode?: 'create' | 'edit';
}

interface FormValues {
  name: string;
  url: string;
  auth_type: 'api_token' | 'basic_auth';
  token?: string;
  username?: string;
  password?: string;
}

export const SourceConnectionForm: React.FC<SourceConnectionFormProps> = ({
  initialValues,
  onSuccess,
  onCancel,
  mode = 'create',
}) => {
  const [form] = Form.useForm<FormValues>();
  const [loading, setLoading] = useState(false);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [authType, setAuthType] = useState<'api_token' | 'basic_auth'>(
    initialValues?.auth_type as 'api_token' | 'basic_auth' || 'api_token'
  );

  const handleAuthTypeChange = (value: 'api_token' | 'basic_auth') => {
    setAuthType(value);
    setTestResult(null);
  };

  const handleSubmit = async (values: FormValues) => {
    setLoading(true);
    try {
      const credentials: ConnectionCredentials = {
        token: values.auth_type === 'api_token' ? values.token : undefined,
        username: values.auth_type === 'basic_auth' ? values.username : undefined,
        password: values.auth_type === 'basic_auth' ? values.password : undefined,
      };

      const connection = await migrationApi.createConnection({
        name: values.name,
        url: values.url,
        auth_type: values.auth_type,
        credentials,
      });

      onSuccess?.(connection);
    } catch (error) {
      console.error('Failed to create connection:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleTest = async () => {
    try {
      await form.validateFields();
    } catch {
      return;
    }

    setTestLoading(true);
    setTestResult(null);

    try {
      const values = form.getFieldsValue();
      const credentials: ConnectionCredentials = {
        token: values.auth_type === 'api_token' ? values.token : undefined,
        username: values.auth_type === 'basic_auth' ? values.username : undefined,
        password: values.auth_type === 'basic_auth' ? values.password : undefined,
      };

      // First create a temporary connection to test
      const connection = await migrationApi.createConnection({
        name: `test-${Date.now()}`,
        url: values.url,
        auth_type: values.auth_type,
        credentials,
      });

      // Test the connection
      const result = await migrationApi.testConnection(connection.id);
      setTestResult(result);

      // Delete the temporary connection
      await migrationApi.deleteConnection(connection.id);
    } catch (error) {
      setTestResult({
        success: false,
        message: error instanceof Error ? error.message : 'Connection test failed',
      });
    } finally {
      setTestLoading(false);
    }
  };

  return (
    <Form
      form={form}
      layout="vertical"
      initialValues={{
        name: initialValues?.name || '',
        url: initialValues?.url || '',
        auth_type: initialValues?.auth_type || 'api_token',
        token: initialValues?.credentials?.token || '',
        username: initialValues?.credentials?.username || '',
        password: '',
      }}
      onFinish={handleSubmit}
    >
      <Form.Item
        name="name"
        label="Connection Name"
        rules={[{ required: true, message: 'Please enter a connection name' }]}
      >
        <Input placeholder="My Artifactory Server" />
      </Form.Item>

      <Form.Item
        name="url"
        label="Artifactory URL"
        rules={[
          { required: true, message: 'Please enter the Artifactory URL' },
          { type: 'url', message: 'Please enter a valid URL' },
        ]}
        help="e.g., https://artifactory.example.com/artifactory"
      >
        <Input placeholder="https://artifactory.example.com/artifactory" />
      </Form.Item>

      <Form.Item
        name="auth_type"
        label="Authentication Type"
        rules={[{ required: true }]}
      >
        <Select onChange={handleAuthTypeChange}>
          <Option value="api_token">API Token</Option>
          <Option value="basic_auth">Username & Password</Option>
        </Select>
      </Form.Item>

      {authType === 'api_token' && (
        <Form.Item
          name="token"
          label="API Token"
          rules={[{ required: true, message: 'Please enter your API token' }]}
        >
          <Input.Password
            prefix={<KeyOutlined />}
            placeholder="Enter your Artifactory API token"
          />
        </Form.Item>
      )}

      {authType === 'basic_auth' && (
        <>
          <Form.Item
            name="username"
            label="Username"
            rules={[{ required: true, message: 'Please enter your username' }]}
          >
            <Input prefix={<UserOutlined />} placeholder="Username" />
          </Form.Item>
          <Form.Item
            name="password"
            label="Password"
            rules={[{ required: true, message: 'Please enter your password' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Password" />
          </Form.Item>
        </>
      )}

      {testResult && (
        <Form.Item>
          <Alert
            type={testResult.success ? 'success' : 'error'}
            message={testResult.success ? 'Connection Successful' : 'Connection Failed'}
            description={
              <>
                <div>{testResult.message}</div>
                {testResult.artifactory_version && (
                  <div>Artifactory Version: {testResult.artifactory_version}</div>
                )}
                {testResult.license_type && (
                  <div>License: {testResult.license_type}</div>
                )}
              </>
            }
            showIcon
          />
        </Form.Item>
      )}

      <Form.Item>
        <Space>
          <Button type="primary" htmlType="submit" loading={loading}>
            {mode === 'create' ? 'Create Connection' : 'Save Changes'}
          </Button>
          <Button onClick={handleTest} loading={testLoading}>
            Test Connection
          </Button>
          {onCancel && (
            <Button onClick={onCancel}>
              Cancel
            </Button>
          )}
        </Space>
      </Form.Item>
    </Form>
  );
};

export default SourceConnectionForm;
