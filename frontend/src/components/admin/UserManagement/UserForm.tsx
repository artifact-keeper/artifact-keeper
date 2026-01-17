import React, { useState, useEffect } from 'react';
import {
  Form,
  Input,
  Button,
  Switch,
  Select,
  Space,
  Typography,
  Checkbox,
  Divider,
  Alert,
} from 'antd';
import {
  SaveOutlined,
  CloseOutlined,
  KeyOutlined,
  CopyOutlined,
} from '@ant-design/icons';
import type { User } from '../../../types';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;

export type UserFormMode = 'create' | 'edit';

export interface UserFormValues {
  username: string;
  email: string;
  display_name?: string;
  password?: string;
  confirm_password?: string;
  is_admin: boolean;
  is_active: boolean;
  auto_generate_password?: boolean;
}

export interface UserFormProps {
  onSubmit: (values: UserFormValues) => Promise<void>;
  onCancel?: () => void;
  loading?: boolean;
  initialValues?: Partial<User>;
  mode: UserFormMode;
  generatedPassword?: string;
}

const generateRandomPassword = (): string => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < 16; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
};

export const UserForm: React.FC<UserFormProps> = ({
  onSubmit,
  onCancel,
  loading = false,
  initialValues,
  mode,
  generatedPassword,
}) => {
  const [form] = Form.useForm();
  const [autoGeneratePassword, setAutoGeneratePassword] = useState(false);
  const [previewPassword, setPreviewPassword] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const isCreateMode = mode === 'create';

  useEffect(() => {
    if (initialValues) {
      form.setFieldsValue({
        username: initialValues.username || '',
        email: initialValues.email || '',
        display_name: initialValues.display_name || '',
        is_admin: initialValues.is_admin ?? false,
        is_active: initialValues.is_active ?? true,
      });
    }
  }, [initialValues, form]);

  useEffect(() => {
    if (autoGeneratePassword && isCreateMode) {
      const newPassword = generateRandomPassword();
      setPreviewPassword(newPassword);
      form.setFieldsValue({
        password: newPassword,
        confirm_password: newPassword,
      });
    } else {
      setPreviewPassword(null);
      if (isCreateMode) {
        form.setFieldsValue({
          password: '',
          confirm_password: '',
        });
      }
    }
  }, [autoGeneratePassword, isCreateMode, form]);

  const handleSubmit = async (values: UserFormValues) => {
    await onSubmit({
      ...values,
      auto_generate_password: autoGeneratePassword,
    });
  };

  const handleCopyPassword = () => {
    const password = previewPassword || generatedPassword;
    if (password) {
      navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const displayPassword = generatedPassword || previewPassword;

  return (
    <div style={{ backgroundColor: colors.bgContainer }}>
      {displayPassword && (
        <Alert
          type="info"
          showIcon
          icon={<KeyOutlined />}
          message="Generated Password"
          description={
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Text>
                Please save this password. It will not be shown again.
              </Text>
              <Space>
                <Text code copyable={false} style={{ fontSize: 14 }}>
                  {displayPassword}
                </Text>
                <Button
                  size="small"
                  icon={<CopyOutlined />}
                  onClick={handleCopyPassword}
                >
                  {copied ? 'Copied!' : 'Copy'}
                </Button>
              </Space>
            </Space>
          }
          style={{ marginBottom: spacing.md }}
        />
      )}

      <Form
        form={form}
        layout="vertical"
        onFinish={handleSubmit}
        initialValues={{
          username: initialValues?.username || '',
          email: initialValues?.email || '',
          display_name: initialValues?.display_name || '',
          is_admin: initialValues?.is_admin ?? false,
          is_active: initialValues?.is_active ?? true,
        }}
      >
        <Form.Item
          label="Username"
          name="username"
          rules={[
            { required: true, message: 'Please enter a username' },
            { min: 3, message: 'Username must be at least 3 characters' },
            { max: 50, message: 'Username must be at most 50 characters' },
            {
              pattern: /^[a-zA-Z0-9_-]+$/,
              message: 'Username can only contain letters, numbers, underscores, and hyphens',
            },
          ]}
          extra={!isCreateMode ? 'Username cannot be changed' : undefined}
        >
          <Input
            placeholder="Enter username"
            disabled={!isCreateMode}
            autoComplete="off"
          />
        </Form.Item>

        <Form.Item
          label="Email"
          name="email"
          rules={[
            { required: true, message: 'Please enter an email address' },
            { type: 'email', message: 'Please enter a valid email address' },
          ]}
        >
          <Input placeholder="Enter email address" autoComplete="off" />
        </Form.Item>

        <Form.Item
          label="Display Name"
          name="display_name"
          rules={[
            { max: 100, message: 'Display name must be at most 100 characters' },
          ]}
        >
          <Input placeholder="Enter display name (optional)" />
        </Form.Item>

        {isCreateMode && (
          <>
            <Form.Item>
              <Checkbox
                checked={autoGeneratePassword}
                onChange={(e) => setAutoGeneratePassword(e.target.checked)}
              >
                Auto-generate password
              </Checkbox>
            </Form.Item>

            {!autoGeneratePassword && (
              <>
                <Form.Item
                  label="Password"
                  name="password"
                  rules={[
                    { required: true, message: 'Please enter a password' },
                    { min: 8, message: 'Password must be at least 8 characters' },
                  ]}
                >
                  <Input.Password
                    placeholder="Enter password"
                    autoComplete="new-password"
                  />
                </Form.Item>

                <Form.Item
                  label="Confirm Password"
                  name="confirm_password"
                  dependencies={['password']}
                  rules={[
                    { required: true, message: 'Please confirm the password' },
                    ({ getFieldValue }) => ({
                      validator(_, value) {
                        if (!value || getFieldValue('password') === value) {
                          return Promise.resolve();
                        }
                        return Promise.reject(new Error('Passwords do not match'));
                      },
                    }),
                  ]}
                >
                  <Input.Password
                    placeholder="Confirm password"
                    autoComplete="new-password"
                  />
                </Form.Item>
              </>
            )}
          </>
        )}

        <Divider />

        <Form.Item
          label="Role"
          name="is_admin"
          valuePropName="checked"
          extra="Admins have full access to all repositories and administrative functions"
        >
          <Select
            value={form.getFieldValue('is_admin') ? 'admin' : 'user'}
            onChange={(value) => form.setFieldValue('is_admin', value === 'admin')}
            options={[
              { value: 'user', label: 'User' },
              { value: 'admin', label: 'Admin' },
            ]}
            style={{ width: 200 }}
          />
        </Form.Item>

        <Form.Item
          label="Status"
          name="is_active"
          valuePropName="checked"
          extra="Disabled users cannot log in or access any resources"
        >
          <Switch
            checkedChildren="Active"
            unCheckedChildren="Disabled"
          />
        </Form.Item>

        <Form.Item style={{ marginBottom: 0, marginTop: spacing.lg }}>
          <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
            {onCancel && (
              <Button onClick={onCancel} icon={<CloseOutlined />}>
                Cancel
              </Button>
            )}
            <Button
              type="primary"
              htmlType="submit"
              loading={loading}
              icon={<SaveOutlined />}
            >
              {isCreateMode ? 'Create User' : 'Save Changes'}
            </Button>
          </Space>
        </Form.Item>
      </Form>
    </div>
  );
};

export default UserForm;
