import React, { useEffect } from 'react';
import {
  Form,
  Input,
  Switch,
  Button,
  Space,
  Alert,
} from 'antd';
import { spacing } from '../../../styles/tokens';

const { TextArea } = Input;

export interface GroupFormValues {
  name: string;
  description?: string;
  auto_join: boolean;
  external_id?: string;
}

export interface GroupFormProps {
  onSubmit: (values: GroupFormValues) => void;
  loading?: boolean;
  initialValues?: Partial<GroupFormValues>;
  mode: 'create' | 'edit';
  onCancel?: () => void;
}

export const GroupForm: React.FC<GroupFormProps> = ({
  onSubmit,
  loading = false,
  initialValues,
  mode,
  onCancel,
}) => {
  const [form] = Form.useForm<GroupFormValues>();

  useEffect(() => {
    if (initialValues) {
      form.setFieldsValue(initialValues);
    } else {
      form.resetFields();
    }
  }, [form, initialValues]);

  const handleFinish = (values: GroupFormValues) => {
    onSubmit(values);
  };

  const isEdit = mode === 'edit';

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={handleFinish}
      initialValues={{
        auto_join: false,
        ...initialValues,
      }}
      style={{ maxWidth: 600 }}
    >
      <Form.Item
        name="name"
        label="Group Name"
        rules={[
          { required: true, message: 'Please enter a group name' },
          { min: 2, message: 'Group name must be at least 2 characters' },
          { max: 100, message: 'Group name cannot exceed 100 characters' },
          {
            pattern: /^[a-zA-Z0-9_-]+$/,
            message: 'Group name can only contain letters, numbers, underscores, and hyphens',
          },
        ]}
        extra="Unique identifier for the group. Can only contain letters, numbers, underscores, and hyphens."
      >
        <Input
          placeholder="e.g., developers, release-engineers"
          disabled={isEdit}
        />
      </Form.Item>

      <Form.Item
        name="description"
        label="Description"
        rules={[
          { max: 500, message: 'Description cannot exceed 500 characters' },
        ]}
      >
        <TextArea
          placeholder="Describe the purpose of this group..."
          rows={3}
          showCount
          maxLength={500}
        />
      </Form.Item>

      <Form.Item
        name="auto_join"
        label="Auto-Join"
        valuePropName="checked"
        extra="When enabled, new users will automatically be added to this group upon registration."
      >
        <Switch />
      </Form.Item>

      <Form.Item
        name="external_id"
        label="External Group Linking"
        extra="Link this group to an external identity provider group (e.g., LDAP DN, SAML group name, OAuth group ID)."
      >
        <Input placeholder="e.g., cn=developers,ou=groups,dc=example,dc=com" />
      </Form.Item>

      {initialValues?.external_id && (
        <Alert
          message="External Group"
          description="This group is linked to an external identity provider. Members may be synchronized automatically based on external group membership."
          type="info"
          showIcon
          style={{ marginBottom: spacing.md }}
        />
      )}

      <Form.Item style={{ marginTop: spacing.lg, marginBottom: 0 }}>
        <Space>
          <Button type="primary" htmlType="submit" loading={loading}>
            {isEdit ? 'Save Changes' : 'Create Group'}
          </Button>
          {onCancel && (
            <Button onClick={onCancel} disabled={loading}>
              Cancel
            </Button>
          )}
        </Space>
      </Form.Item>
    </Form>
  );
};

export default GroupForm;
