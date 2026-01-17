import React from 'react';
import { Form, Input, Space, Typography } from 'antd';
import type { FormInstance } from 'antd';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;

export interface GAVCSearchTabProps {
  form: FormInstance;
}

export const GAVCSearchTab: React.FC<GAVCSearchTabProps> = ({ form }) => {
  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        <Form.Item
          name={['gavc', 'groupId']}
          label="Group ID"
          style={{ marginBottom: 0 }}
        >
          <Input
            placeholder="e.g., com.example or com.example.*"
            allowClear
          />
        </Form.Item>

        <Form.Item
          name={['gavc', 'artifactId']}
          label="Artifact ID"
          style={{ marginBottom: 0 }}
        >
          <Input
            placeholder="e.g., my-library or my-*"
            allowClear
          />
        </Form.Item>

        <Form.Item
          name={['gavc', 'version']}
          label="Version"
          style={{ marginBottom: 0 }}
        >
          <Input
            placeholder="e.g., 1.0.0, 1.*, or [1.0,2.0)"
            allowClear
          />
        </Form.Item>

        <Form.Item
          name={['gavc', 'classifier']}
          label="Classifier"
          style={{ marginBottom: 0 }}
        >
          <Input
            placeholder="e.g., sources, javadoc, linux-x86_64"
            allowClear
          />
        </Form.Item>

        <Text type="secondary">
          Use wildcards (*) to match partial values. All fields are optional
          and can be combined for flexible Maven artifact searches.
        </Text>
      </Space>
    </div>
  );
};

export default GAVCSearchTab;
