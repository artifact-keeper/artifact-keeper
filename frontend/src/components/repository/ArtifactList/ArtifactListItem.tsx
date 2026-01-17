import React, { useCallback } from 'react';
import { Button, Space, Tooltip, Typography, message } from 'antd';
import {
  DownloadOutlined,
  CopyOutlined,
  DeleteOutlined,
  FileOutlined,
  FileImageOutlined,
  FileZipOutlined,
  FileTextOutlined,
  FilePdfOutlined,
  CodeOutlined,
} from '@ant-design/icons';
import type { Artifact } from '../../../types';
import { colors } from '../../../styles/tokens';
import {
  formatFileSize as formatFileSizeUtil,
  formatRelativeTime as formatRelativeTimeUtil,
} from '../../../utils';

const { Text } = Typography;

// Re-export for backward compatibility with existing imports
export const formatFileSize = formatFileSizeUtil;
export const formatRelativeTime = formatRelativeTimeUtil;

/**
 * Get appropriate file icon based on content type
 */
export const getFileIcon = (contentType: string): React.ReactNode => {
  const iconStyle = { fontSize: 20, color: colors.textSecondary };

  if (contentType.startsWith('image/')) {
    return <FileImageOutlined style={iconStyle} />;
  }
  if (contentType.includes('zip') || contentType.includes('tar') || contentType.includes('gzip') || contentType.includes('compressed')) {
    return <FileZipOutlined style={iconStyle} />;
  }
  if (contentType.includes('pdf')) {
    return <FilePdfOutlined style={iconStyle} />;
  }
  if (contentType.includes('text') || contentType.includes('xml') || contentType.includes('json')) {
    return <FileTextOutlined style={iconStyle} />;
  }
  if (contentType.includes('javascript') || contentType.includes('typescript') || contentType.includes('java') || contentType.includes('python')) {
    return <CodeOutlined style={iconStyle} />;
  }

  return <FileOutlined style={iconStyle} />;
};

export interface ArtifactListItemProps {
  artifact: Artifact;
  onDownload: (artifact: Artifact) => void;
  onDelete: (artifact: Artifact) => void;
  disabled?: boolean;
}

export const ArtifactListItem: React.FC<ArtifactListItemProps> = ({
  artifact,
  onDownload,
  onDelete,
  disabled = false,
}) => {
  const handleCopyPath = useCallback(async () => {
    const fullPath = `${artifact.repository_key}/${artifact.path}`;
    try {
      await navigator.clipboard.writeText(fullPath);
      message.success('Path copied to clipboard');
    } catch {
      message.error('Failed to copy path');
    }
  }, [artifact]);

  const handleDownload = useCallback(() => {
    onDownload(artifact);
  }, [artifact, onDownload]);

  const handleDelete = useCallback(() => {
    onDelete(artifact);
  }, [artifact, onDelete]);

  return (
    <Space size="small">
      <Tooltip title="Download">
        <Button
          type="text"
          icon={<DownloadOutlined />}
          onClick={handleDownload}
          disabled={disabled}
          aria-label={`Download ${artifact.name}`}
        />
      </Tooltip>
      <Tooltip title="Copy Path">
        <Button
          type="text"
          icon={<CopyOutlined />}
          onClick={handleCopyPath}
          disabled={disabled}
          aria-label={`Copy path for ${artifact.name}`}
        />
      </Tooltip>
      <Tooltip title="Delete">
        <Button
          type="text"
          danger
          icon={<DeleteOutlined />}
          onClick={handleDelete}
          disabled={disabled}
          aria-label={`Delete ${artifact.name}`}
        />
      </Tooltip>
    </Space>
  );
};

/**
 * Render artifact name with icon
 */
export const renderArtifactName = (artifact: Artifact): React.ReactNode => {
  return (
    <Space>
      {getFileIcon(artifact.content_type)}
      <Text strong style={{ color: colors.textPrimary }}>
        {artifact.name}
      </Text>
    </Space>
  );
};

/**
 * Render formatted file size
 */
export const renderFileSize = (sizeBytes: number): React.ReactNode => {
  return <Text type="secondary">{formatFileSize(sizeBytes)}</Text>;
};

/**
 * Render relative time with tooltip showing full date
 */
export const renderRelativeTime = (dateString: string): React.ReactNode => {
  const fullDate = new Date(dateString).toLocaleString();
  return (
    <Tooltip title={fullDate}>
      <Text type="secondary">{formatRelativeTime(dateString)}</Text>
    </Tooltip>
  );
};

export default ArtifactListItem;
