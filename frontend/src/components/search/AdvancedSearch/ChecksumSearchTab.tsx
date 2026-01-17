import React from 'react';
import { Form, Input, Select, Space, Typography } from 'antd';
import type { FormInstance } from 'antd';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;
const { TextArea } = Input;

export interface ChecksumSearchTabProps {
  form: FormInstance;
}

type ChecksumType = 'md5' | 'sha1' | 'sha256' | 'sha512';

const checksumTypeOptions: { value: ChecksumType; label: string }[] = [
  { value: 'md5', label: 'MD5' },
  { value: 'sha1', label: 'SHA-1' },
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha512', label: 'SHA-512' },
];

export const ChecksumSearchTab: React.FC<ChecksumSearchTabProps> = ({ form }) => {
  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        <Form.Item
          name={['checksum', 'type']}
          label="Checksum Type"
          initialValue="sha256"
          style={{ marginBottom: 0 }}
        >
          <Select
            options={checksumTypeOptions}
            style={{ width: 200 }}
          />
        </Form.Item>

        <Form.Item
          name={['checksum', 'value']}
          label="Checksum Value"
          style={{ marginBottom: 0 }}
          rules={[
            {
              pattern: /^[a-fA-F0-9]+$/,
              message: 'Checksum must contain only hexadecimal characters',
            },
          ]}
        >
          <TextArea
            placeholder="Paste checksum value here (e.g., e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"
            autoSize={{ minRows: 2, maxRows: 4 }}
            style={{ fontFamily: 'monospace' }}
            allowClear
          />
        </Form.Item>

        <Text type="secondary">
          Enter a checksum to find artifacts with matching hash values.
          You can paste checksums directly from command-line tools like sha256sum or md5sum.
        </Text>
      </Space>
    </div>
  );
};

export default ChecksumSearchTab;
