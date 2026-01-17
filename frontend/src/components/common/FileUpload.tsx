import { useState, useCallback } from 'react';
import { Upload, Progress, Button, Space, Typography, message, Alert } from 'antd';
import {
  InboxOutlined,
  UploadOutlined,
  DeleteOutlined,
  FileOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
} from '@ant-design/icons';
import type { UploadFile, UploadProps, RcFile } from 'antd/es/upload/interface';
import { artifactsApi } from '../../api';
import type { Artifact } from '../../types';

const { Dragger } = Upload;
const { Text } = Typography;

export interface FileUploadProps {
  /** Repository key for artifact upload */
  repositoryKey: string;
  /** Custom path for the artifact (optional) */
  artifactPath?: string;
  /** Allow multiple file selection */
  multiple?: boolean;
  /** Maximum file size in bytes (default: 1GB) */
  maxFileSize?: number;
  /** Accepted file types (e.g., '.jar,.zip,.tar.gz') */
  accept?: string;
  /** Callback when upload succeeds */
  onUploadSuccess?: (artifact: Artifact, file: UploadFile) => void;
  /** Callback when upload fails */
  onUploadError?: (error: Error, file: UploadFile) => void;
  /** Callback when all uploads complete */
  onUploadComplete?: (results: UploadResult[]) => void;
  /** Custom path resolver for each file */
  getArtifactPath?: (file: RcFile) => string | undefined;
  /** Whether to show the upload button (default: true) */
  showUploadButton?: boolean;
  /** Custom upload button text */
  uploadButtonText?: string;
  /** Whether to auto-upload on file selection (default: false) */
  autoUpload?: boolean;
  /** Whether the component is disabled */
  disabled?: boolean;
  /** Custom class name */
  className?: string;
  /** Custom style */
  style?: React.CSSProperties;
}

interface UploadResult {
  file: UploadFile;
  success: boolean;
  artifact?: Artifact;
  error?: Error;
}

interface FileProgress {
  [uid: string]: {
    percent: number;
    status: 'uploading' | 'done' | 'error';
    error?: string;
  };
}

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const FileUpload: React.FC<FileUploadProps> = ({
  repositoryKey,
  artifactPath,
  multiple = false,
  maxFileSize = 1024 * 1024 * 1024, // 1GB default
  accept,
  onUploadSuccess,
  onUploadError,
  onUploadComplete,
  getArtifactPath,
  showUploadButton = true,
  uploadButtonText = 'Upload',
  autoUpload = false,
  disabled = false,
  className,
  style,
}) => {
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState<FileProgress>({});

  const validateFile = useCallback(
    (file: RcFile): string | null => {
      if (file.size > maxFileSize) {
        return `File "${file.name}" exceeds maximum size of ${formatBytes(maxFileSize)}`;
      }
      return null;
    },
    [maxFileSize]
  );

  const handleBeforeUpload = useCallback(
    (file: RcFile): boolean => {
      const error = validateFile(file);
      if (error) {
        message.error(error);
        return false;
      }

      if (!multiple) {
        setFileList([file as unknown as UploadFile]);
      } else {
        setFileList((prev) => [...prev, file as unknown as UploadFile]);
      }

      if (autoUpload) {
        // Auto upload will be handled in a separate effect
        uploadSingleFile(file as unknown as UploadFile);
      }

      return false; // Prevent default upload behavior
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [multiple, autoUpload, validateFile]
  );

  const handleRemove = useCallback((file: UploadFile) => {
    setFileList((prev) => prev.filter((f) => f.uid !== file.uid));
    setProgress((prev) => {
      const newProgress = { ...prev };
      delete newProgress[file.uid];
      return newProgress;
    });
  }, []);

  const uploadSingleFile = async (file: UploadFile): Promise<UploadResult> => {
    const actualFile = file.originFileObj || (file as unknown as File);

    // Determine the artifact path
    let path = artifactPath;
    if (getArtifactPath && file.originFileObj) {
      path = getArtifactPath(file.originFileObj as RcFile);
    }

    setProgress((prev) => ({
      ...prev,
      [file.uid]: { percent: 0, status: 'uploading' },
    }));

    try {
      const artifact = await artifactsApi.upload(
        repositoryKey,
        actualFile as File,
        path,
        (percent) => {
          setProgress((prev) => ({
            ...prev,
            [file.uid]: { percent, status: 'uploading' },
          }));
        }
      );

      setProgress((prev) => ({
        ...prev,
        [file.uid]: { percent: 100, status: 'done' },
      }));

      setFileList((prev) =>
        prev.map((f) =>
          f.uid === file.uid ? { ...f, status: 'done' } : f
        )
      );

      onUploadSuccess?.(artifact, file);
      return { file, success: true, artifact };
    } catch (err) {
      const error = err as Error;
      setProgress((prev) => ({
        ...prev,
        [file.uid]: { percent: 0, status: 'error', error: error.message },
      }));

      setFileList((prev) =>
        prev.map((f) =>
          f.uid === file.uid ? { ...f, status: 'error' } : f
        )
      );

      onUploadError?.(error, file);
      return { file, success: false, error };
    }
  };

  const handleUpload = async () => {
    if (fileList.length === 0) {
      message.warning('Please select files to upload');
      return;
    }

    setUploading(true);
    const results: UploadResult[] = [];

    for (const file of fileList) {
      if (progress[file.uid]?.status === 'done') {
        continue; // Skip already uploaded files
      }
      const result = await uploadSingleFile(file);
      results.push(result);
    }

    setUploading(false);

    const successCount = results.filter((r) => r.success).length;
    const failCount = results.filter((r) => !r.success).length;

    if (failCount === 0 && successCount > 0) {
      message.success(
        `Successfully uploaded ${successCount} file${successCount > 1 ? 's' : ''}`
      );
      // Clear completed files
      setFileList((prev) =>
        prev.filter((f) => progress[f.uid]?.status !== 'done')
      );
    } else if (failCount > 0) {
      message.error(
        `${failCount} file${failCount > 1 ? 's' : ''} failed to upload`
      );
    }

    onUploadComplete?.(results);
  };

  const handleClearAll = () => {
    setFileList([]);
    setProgress({});
  };

  const uploadProps: UploadProps = {
    fileList,
    beforeUpload: handleBeforeUpload,
    onRemove: handleRemove,
    multiple,
    accept,
    disabled: disabled || uploading,
    showUploadList: false, // We render our own list
  };

  const getStatusIcon = (file: UploadFile) => {
    const fileProgress = progress[file.uid];
    if (!fileProgress) return <FileOutlined />;

    switch (fileProgress.status) {
      case 'uploading':
        return <LoadingOutlined spin />;
      case 'done':
        return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
      case 'error':
        return <CloseCircleOutlined style={{ color: '#ff4d4f' }} />;
      default:
        return <FileOutlined />;
    }
  };

  return (
    <div className={className} style={style}>
      <Dragger {...uploadProps}>
        <p className="ant-upload-drag-icon">
          <InboxOutlined />
        </p>
        <p className="ant-upload-text">
          Click or drag file{multiple ? 's' : ''} to this area to upload
        </p>
        <p className="ant-upload-hint">
          {multiple
            ? 'Support for multiple file upload. '
            : 'Upload a single file. '}
          Maximum file size: {formatBytes(maxFileSize)}
        </p>
        {accept && (
          <p className="ant-upload-hint">
            Accepted formats: {accept}
          </p>
        )}
      </Dragger>

      {fileList.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 8,
            }}
          >
            <Text strong>
              Selected Files ({fileList.length})
            </Text>
            <Button
              type="text"
              size="small"
              danger
              onClick={handleClearAll}
              disabled={uploading}
            >
              Clear All
            </Button>
          </div>

          <div
            style={{
              maxHeight: 300,
              overflowY: 'auto',
              border: '1px solid #f0f0f0',
              borderRadius: 8,
              padding: 8,
            }}
          >
            {fileList.map((file) => {
              const fileProgress = progress[file.uid];
              return (
                <div
                  key={file.uid}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '8px 12px',
                    borderRadius: 6,
                    marginBottom: 4,
                    background:
                      fileProgress?.status === 'error'
                        ? '#fff2f0'
                        : fileProgress?.status === 'done'
                        ? '#f6ffed'
                        : '#fafafa',
                  }}
                >
                  <span style={{ marginRight: 8 }}>{getStatusIcon(file)}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <Text
                        ellipsis={{ tooltip: file.name }}
                        style={{ maxWidth: '70%' }}
                      >
                        {file.name}
                      </Text>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {formatBytes(file.size || 0)}
                      </Text>
                    </div>
                    {fileProgress?.status === 'uploading' && (
                      <Progress
                        percent={fileProgress.percent}
                        size="small"
                        status="active"
                        style={{ marginBottom: 0 }}
                      />
                    )}
                    {fileProgress?.status === 'error' && (
                      <Text type="danger" style={{ fontSize: 12 }}>
                        {fileProgress.error || 'Upload failed'}
                      </Text>
                    )}
                  </div>
                  {!uploading && fileProgress?.status !== 'uploading' && (
                    <Button
                      type="text"
                      size="small"
                      icon={<DeleteOutlined />}
                      onClick={() => handleRemove(file)}
                      style={{ marginLeft: 8 }}
                    />
                  )}
                </div>
              );
            })}
          </div>

          {showUploadButton && (
            <Space style={{ marginTop: 16, width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={handleClearAll} disabled={uploading}>
                Cancel
              </Button>
              <Button
                type="primary"
                icon={<UploadOutlined />}
                onClick={handleUpload}
                loading={uploading}
                disabled={
                  fileList.length === 0 ||
                  fileList.every((f) => progress[f.uid]?.status === 'done')
                }
              >
                {uploading
                  ? 'Uploading...'
                  : uploadButtonText}
              </Button>
            </Space>
          )}
        </div>
      )}

      {uploading && fileList.length > 1 && (
        <Alert
          message="Upload in Progress"
          description={`Uploading ${fileList.filter((f) => progress[f.uid]?.status === 'uploading').length} of ${fileList.length} files...`}
          type="info"
          showIcon
          style={{ marginTop: 16 }}
        />
      )}
    </div>
  );
};

export default FileUpload;
