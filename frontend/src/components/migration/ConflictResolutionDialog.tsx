import React from 'react';
import { Modal, Radio, Space, Typography, Alert, Descriptions } from 'antd';
import {
  ExclamationCircleOutlined,
  FileOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import type { RadioChangeEvent } from 'antd';

const { Text, Paragraph } = Typography;

export type ConflictResolutionStrategy = 'skip' | 'overwrite' | 'rename';

interface ConflictInfo {
  sourcePath: string;
  targetPath: string;
  sourceChecksum?: string;
  targetChecksum?: string;
  sourceSize?: number;
  targetSize?: number;
  message?: string;
}

interface ConflictResolutionDialogProps {
  open: boolean;
  conflict?: ConflictInfo;
  applyToAll: boolean;
  onResolve: (strategy: ConflictResolutionStrategy, applyToAll: boolean) => void;
  onCancel: () => void;
}

export const ConflictResolutionDialog: React.FC<ConflictResolutionDialogProps> = ({
  open,
  conflict,
  applyToAll: initialApplyToAll,
  onResolve,
  onCancel,
}) => {
  const [strategy, setStrategy] = React.useState<ConflictResolutionStrategy>('skip');
  const [applyToAll, setApplyToAll] = React.useState(initialApplyToAll);

  const handleStrategyChange = (e: RadioChangeEvent) => {
    setStrategy(e.target.value);
  };

  const handleOk = () => {
    onResolve(strategy, applyToAll);
  };

  const formatBytes = (bytes?: number): string => {
    if (bytes === undefined) return 'Unknown';
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const checksumMatch = conflict?.sourceChecksum && conflict?.targetChecksum
    ? conflict.sourceChecksum === conflict.targetChecksum
    : undefined;

  return (
    <Modal
      title={
        <Space>
          <ExclamationCircleOutlined style={{ color: '#faad14' }} />
          <span>Conflict Detected</span>
        </Space>
      }
      open={open}
      onOk={handleOk}
      onCancel={onCancel}
      okText="Apply"
      cancelText="Cancel Migration"
      width={600}
    >
      {conflict && (
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <Alert
            type="warning"
            message={conflict.message || "An artifact with the same path already exists in the destination."}
            showIcon
          />

          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="Source Path">
              <Space>
                <FileOutlined />
                <Text code>{conflict.sourcePath}</Text>
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="Target Path">
              <Space>
                <FileOutlined />
                <Text code>{conflict.targetPath}</Text>
              </Space>
            </Descriptions.Item>
            {conflict.sourceSize !== undefined && (
              <Descriptions.Item label="Source Size">
                {formatBytes(conflict.sourceSize)}
              </Descriptions.Item>
            )}
            {conflict.targetSize !== undefined && (
              <Descriptions.Item label="Target Size">
                {formatBytes(conflict.targetSize)}
              </Descriptions.Item>
            )}
            {checksumMatch !== undefined && (
              <Descriptions.Item label="Checksum">
                {checksumMatch ? (
                  <Space>
                    <CheckCircleOutlined style={{ color: '#52c41a' }} />
                    <Text type="success">Checksums match</Text>
                  </Space>
                ) : (
                  <Space>
                    <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />
                    <Text type="danger">Checksums differ</Text>
                  </Space>
                )}
              </Descriptions.Item>
            )}
          </Descriptions>

          <div>
            <Paragraph strong>How would you like to resolve this conflict?</Paragraph>
            <Radio.Group onChange={handleStrategyChange} value={strategy}>
              <Space direction="vertical">
                <Radio value="skip">
                  <Text strong>Skip</Text>
                  <br />
                  <Text type="secondary">
                    Keep the existing artifact and skip importing this one.
                    {checksumMatch === true && ' (Recommended - files are identical)'}
                  </Text>
                </Radio>
                <Radio value="overwrite">
                  <Text strong>Overwrite</Text>
                  <br />
                  <Text type="secondary">
                    Replace the existing artifact with the one from Artifactory.
                    {checksumMatch === false && ' (Warning: files have different content)'}
                  </Text>
                </Radio>
                <Radio value="rename">
                  <Text strong>Rename</Text>
                  <br />
                  <Text type="secondary">
                    Import with a modified name (e.g., artifact_migrated.jar).
                  </Text>
                </Radio>
              </Space>
            </Radio.Group>
          </div>

          <div style={{ marginTop: 16 }}>
            <label>
              <input
                type="checkbox"
                checked={applyToAll}
                onChange={(e) => setApplyToAll(e.target.checked)}
              />{' '}
              Apply this resolution to all future conflicts
            </label>
          </div>
        </Space>
      )}
    </Modal>
  );
};

export default ConflictResolutionDialog;
