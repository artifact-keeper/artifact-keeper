import React, { useState, useEffect, useCallback } from 'react';
import { Card, Tabs, Spin, Alert, Space, Form, Input, Button, message } from 'antd';
import {
  UserOutlined,
  KeyOutlined,
  SafetyOutlined,
  LockOutlined,
} from '@ant-design/icons';
import { useAuth } from '../contexts';
import { profileApi } from '../api';
import type { ApiKey, AccessToken, CreateApiKeyRequest, CreateAccessTokenRequest } from '../api';
import {
  ProfileHeader,
  ProfileForm,
  ApiKeyManager,
  AccessTokenManager,
} from '../components/profile';
import { useDocumentTitle } from '../hooks';
import { colors } from '../styles/tokens';

const Profile: React.FC = () => {
  useDocumentTitle('Profile');
  const { user, refreshUser, changePassword } = useAuth();

  // Loading states
  const [profileLoading, setProfileLoading] = useState(false);
  const [apiKeysLoading, setApiKeysLoading] = useState(true);
  const [accessTokensLoading, setAccessTokensLoading] = useState(true);
  const [securityLoading, setSecurityLoading] = useState(false);

  // Data states
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [accessTokens, setAccessTokens] = useState<AccessToken[]>([]);

  // Security form
  const [securityForm] = Form.useForm();

  // Fetch API keys
  const fetchApiKeys = useCallback(async () => {
    setApiKeysLoading(true);
    try {
      const keys = await profileApi.listApiKeys();
      setApiKeys(keys);
    } catch (error) {
      message.error('Failed to load API keys');
    } finally {
      setApiKeysLoading(false);
    }
  }, []);

  // Fetch access tokens
  const fetchAccessTokens = useCallback(async () => {
    setAccessTokensLoading(true);
    try {
      const tokens = await profileApi.listAccessTokens();
      setAccessTokens(tokens);
    } catch (error) {
      message.error('Failed to load access tokens');
    } finally {
      setAccessTokensLoading(false);
    }
  }, []);

  // Initial data fetch
  useEffect(() => {
    fetchApiKeys();
    fetchAccessTokens();
  }, [fetchApiKeys, fetchAccessTokens]);

  // Profile update handler
  const handleProfileSave = async (values: { display_name?: string; email?: string }) => {
    setProfileLoading(true);
    try {
      await profileApi.update(values);
      await refreshUser();
    } finally {
      setProfileLoading(false);
    }
  };

  // API Key handlers
  const handleCreateApiKey = async (data: CreateApiKeyRequest): Promise<{ key: string; api_key: ApiKey }> => {
    const result = await profileApi.createApiKey(data);
    await fetchApiKeys();
    return result;
  };

  const handleRevokeApiKey = async (keyId: string) => {
    await profileApi.deleteApiKey(keyId);
    await fetchApiKeys();
  };

  // Access Token handlers
  const handleCreateAccessToken = async (
    data: CreateAccessTokenRequest
  ): Promise<{ token: string; access_token: AccessToken }> => {
    const result = await profileApi.createAccessToken(data);
    await fetchAccessTokens();
    return result;
  };

  const handleRevokeAccessToken = async (tokenId: string) => {
    await profileApi.deleteAccessToken(tokenId);
    await fetchAccessTokens();
  };

  // Security: Change password handler
  const handleChangePassword = async (values: {
    current_password: string;
    new_password: string;
  }) => {
    setSecurityLoading(true);
    try {
      await changePassword(values.current_password, values.new_password);
      message.success('Password changed successfully');
      securityForm.resetFields();
    } catch (error) {
      message.error('Failed to change password. Please check your current password.');
    } finally {
      setSecurityLoading(false);
    }
  };

  if (!user) {
    return (
      <div style={{ textAlign: 'center', padding: 48 }}>
        <Spin size="large" />
      </div>
    );
  }

  const tabItems = [
    {
      key: 'general',
      label: (
        <span>
          <UserOutlined />
          General
        </span>
      ),
      children: (
        <Space orientation="vertical" size="large" style={{ width: '100%' }}>
          <Card>
            <ProfileHeader user={user} />
          </Card>
          <ProfileForm
            user={user}
            onSave={handleProfileSave}
            loading={profileLoading}
          />
        </Space>
      ),
    },
    {
      key: 'api-keys',
      label: (
        <span>
          <KeyOutlined />
          API Keys
        </span>
      ),
      children: (
        <ApiKeyManager
          apiKeys={apiKeys}
          onCreate={handleCreateApiKey}
          onRevoke={handleRevokeApiKey}
          loading={apiKeysLoading}
        />
      ),
    },
    {
      key: 'access-tokens',
      label: (
        <span>
          <SafetyOutlined />
          Access Tokens
        </span>
      ),
      children: (
        <AccessTokenManager
          accessTokens={accessTokens}
          onCreate={handleCreateAccessToken}
          onRevoke={handleRevokeAccessToken}
          loading={accessTokensLoading}
        />
      ),
    },
    {
      key: 'security',
      label: (
        <span>
          <LockOutlined />
          Security
        </span>
      ),
      children: (
        <Card title="Security Settings">
          <Alert
            message="Password Requirements"
            description="Your password must be at least 8 characters long. We recommend using a combination of letters, numbers, and special characters."
            type="info"
            showIcon
            style={{ marginBottom: 24 }}
          />
          <Form
            form={securityForm}
            layout="vertical"
            onFinish={handleChangePassword}
            style={{ maxWidth: 400 }}
          >
            <Form.Item
              label="Current Password"
              name="current_password"
              rules={[{ required: true, message: 'Please enter your current password' }]}
            >
              <Input.Password placeholder="Enter current password" />
            </Form.Item>

            <Form.Item
              label="New Password"
              name="new_password"
              rules={[
                { required: true, message: 'Please enter a new password' },
                { min: 8, message: 'Password must be at least 8 characters' },
              ]}
            >
              <Input.Password placeholder="Enter new password" />
            </Form.Item>

            <Form.Item
              label="Confirm New Password"
              name="confirm_password"
              dependencies={['new_password']}
              rules={[
                { required: true, message: 'Please confirm your new password' },
                ({ getFieldValue }) => ({
                  validator(_, value) {
                    if (!value || getFieldValue('new_password') === value) {
                      return Promise.resolve();
                    }
                    return Promise.reject(new Error('Passwords do not match'));
                  },
                }),
              ]}
            >
              <Input.Password placeholder="Confirm new password" />
            </Form.Item>

            <Form.Item style={{ marginTop: 24 }}>
              <Button type="primary" htmlType="submit" loading={securityLoading}>
                Change Password
              </Button>
            </Form.Item>
          </Form>

          <Card
            type="inner"
            title="Sessions"
            style={{ marginTop: 24 }}
          >
            <Alert
              message="Active Sessions"
              description="You are currently logged in from this device. Session management will be available in a future update."
              type="info"
              showIcon
            />
          </Card>
        </Card>
      ),
    },
  ];

  return (
    <div>
      <h1 style={{ marginBottom: 24 }}>My Profile</h1>
      <Tabs
        defaultActiveKey="general"
        items={tabItems}
        tabBarStyle={{ marginBottom: 24 }}
      />
    </div>
  );
};

export default Profile;
