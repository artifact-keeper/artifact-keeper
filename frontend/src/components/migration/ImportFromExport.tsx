import React, { useState, useCallback } from 'react';
import {
  Card,
  Upload,
  Button,
  Form,
  Input,
  Space,
  Typography,
  Alert,
  Progress,
  Table,
  Checkbox,
  Steps,
  message,
  Tag,
  Divider,
  Descriptions,
} from 'antd';
import {
  UploadOutlined,
  FolderOpenOutlined,
  CheckCircleOutlined,
  LoadingOutlined,
  ExclamationCircleOutlined,
} from '@ant-design/icons';
import type { UploadFile, UploadProps } from 'antd/es/upload/interface';
import type { ColumnsType } from 'antd/es/table';

const { Title, Text, Paragraph } = Typography;
// Steps.Step was removed in Ant Design 6; use `items` prop instead

interface ExportMetadata {
  version: string;
  export_time?: string;
  artifactory_version?: string;
  repositories: string[];
  has_security: boolean;
  total_artifacts: number;
  total_size_bytes: number;
}

interface ImportedRepository {
  key: string;
  repo_type: string;
  package_type: string;
  description?: string;
  artifact_count?: number;
  selected: boolean;
}

interface ImportProgress {
  phase: string;
  current: number;
  total: number;
  current_item?: string;
  message: string;
}

interface ImportResult {
  imported: number;
  failed: number;
  skipped: number;
  errors: string[];
}

interface ImportFromExportProps {
  onComplete?: (result: ImportResult) => void;
  onCancel?: () => void;
}

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const ImportFromExport: React.FC<ImportFromExportProps> = ({
  onComplete,
  onCancel,
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [uploadMethod, setUploadMethod] = useState<'upload' | 'path'>('path');
  const [exportPath, setExportPath] = useState('');
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [metadata, setMetadata] = useState<ExportMetadata | null>(null);
  const [repositories, setRepositories] = useState<ImportedRepository[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<ImportProgress | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [importOptions, setImportOptions] = useState({
    includeUsers: true,
    includeGroups: true,
    includePermissions: true,
    dryRun: false,
  });

  const handleAnalyzeExport = useCallback(async () => {
    setLoading(true);
    try {
      // In a real implementation, this would call the backend API
      // For now, we'll simulate the analysis
      const mockMetadata: ExportMetadata = {
        version: '7.x',
        export_time: new Date().toISOString(),
        artifactory_version: '7.41.7',
        repositories: ['libs-release', 'libs-snapshot', 'plugins-release'],
        has_security: true,
        total_artifacts: 1234,
        total_size_bytes: 1024 * 1024 * 500, // 500 MB
      };

      const mockRepos: ImportedRepository[] = mockMetadata.repositories.map(
        (key) => ({
          key,
          repo_type: key.includes('release') ? 'local' : 'local',
          package_type: 'maven',
          artifact_count: Math.floor(Math.random() * 500),
          selected: true,
        })
      );

      setMetadata(mockMetadata);
      setRepositories(mockRepos);
      message.success('Export analyzed successfully');
      setCurrentStep(1);
    } catch (error) {
      message.error('Failed to analyze export');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [exportPath, fileList, uploadMethod]);

  const handleSelectAllRepos = (selected: boolean) => {
    setRepositories((repos) =>
      repos.map((repo) => ({ ...repo, selected }))
    );
  };

  const handleToggleRepo = (key: string) => {
    setRepositories((repos) =>
      repos.map((repo) =>
        repo.key === key ? { ...repo, selected: !repo.selected } : repo
      )
    );
  };

  const handleStartImport = async () => {
    setLoading(true);
    setCurrentStep(3);

    const selectedRepos = repositories.filter((r) => r.selected);

    try {
      // Simulate import progress
      for (let i = 0; i < selectedRepos.length; i++) {
        const repo = selectedRepos[i];
        setProgress({
          phase: 'importing',
          current: i + 1,
          total: selectedRepos.length,
          current_item: repo.key,
          message: `Importing repository: ${repo.key}`,
        });

        // Simulate delay
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }

      const importResult: ImportResult = {
        imported: selectedRepos.length,
        failed: 0,
        skipped: 0,
        errors: [],
      };

      setResult(importResult);
      setCurrentStep(4);
      message.success('Import completed successfully!');
      onComplete?.(importResult);
    } catch (error) {
      message.error('Import failed');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const uploadProps: UploadProps = {
    fileList,
    beforeUpload: (file) => {
      setFileList([file]);
      return false;
    },
    onRemove: () => {
      setFileList([]);
    },
    accept: '.zip,.tar.gz,.tgz',
    maxCount: 1,
  };

  const repoColumns: ColumnsType<ImportedRepository> = [
    {
      title: '',
      dataIndex: 'selected',
      key: 'selected',
      width: 50,
      render: (selected: boolean, record) => (
        <Checkbox
          checked={selected}
          onChange={() => handleToggleRepo(record.key)}
        />
      ),
    },
    {
      title: 'Repository',
      dataIndex: 'key',
      key: 'key',
    },
    {
      title: 'Type',
      dataIndex: 'repo_type',
      key: 'repo_type',
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Package Type',
      dataIndex: 'package_type',
      key: 'package_type',
      render: (type: string) => <Tag color="blue">{type}</Tag>,
    },
    {
      title: 'Artifacts',
      dataIndex: 'artifact_count',
      key: 'artifact_count',
      render: (count?: number) => count?.toLocaleString() ?? '-',
    },
  ];

  const renderStepContent = () => {
    switch (currentStep) {
      case 0:
        return (
          <Card title="Step 1: Select Export Source">
            <Space direction="vertical" style={{ width: '100%' }} size="large">
              <Alert
                message="Export Import is the Recommended Migration Method"
                description="Import from an Artifactory export directory provides the most reliable migration path. It handles all artifact metadata, properties, and checksums correctly."
                type="info"
                showIcon
              />

              <div>
                <Title level={5}>Upload Method</Title>
                <Space>
                  <Button
                    type={uploadMethod === 'path' ? 'primary' : 'default'}
                    onClick={() => setUploadMethod('path')}
                    icon={<FolderOpenOutlined />}
                  >
                    Server Path
                  </Button>
                  <Button
                    type={uploadMethod === 'upload' ? 'primary' : 'default'}
                    onClick={() => setUploadMethod('upload')}
                    icon={<UploadOutlined />}
                  >
                    Upload Archive
                  </Button>
                </Space>
              </div>

              {uploadMethod === 'path' ? (
                <Form layout="vertical">
                  <Form.Item
                    label="Export Directory Path"
                    extra="Enter the path to the Artifactory export directory on the server"
                  >
                    <Input
                      value={exportPath}
                      onChange={(e) => setExportPath(e.target.value)}
                      placeholder="/path/to/artifactory-export"
                      size="large"
                    />
                  </Form.Item>
                </Form>
              ) : (
                <Form layout="vertical">
                  <Form.Item
                    label="Export Archive"
                    extra="Upload a ZIP or TAR.GZ archive of the Artifactory export"
                  >
                    <Upload.Dragger {...uploadProps}>
                      <p className="ant-upload-drag-icon">
                        <UploadOutlined />
                      </p>
                      <p className="ant-upload-text">
                        Click or drag archive to this area
                      </p>
                      <p className="ant-upload-hint">
                        Supports .zip, .tar.gz archives
                      </p>
                    </Upload.Dragger>
                  </Form.Item>
                </Form>
              )}

              <Button
                type="primary"
                size="large"
                onClick={handleAnalyzeExport}
                loading={loading}
                disabled={
                  (uploadMethod === 'path' && !exportPath) ||
                  (uploadMethod === 'upload' && fileList.length === 0)
                }
              >
                Analyze Export
              </Button>
            </Space>
          </Card>
        );

      case 1:
        return (
          <Card title="Step 2: Review Export Contents">
            {metadata && (
              <Space direction="vertical" style={{ width: '100%' }} size="large">
                <Descriptions bordered column={2}>
                  <Descriptions.Item label="Artifactory Version">
                    {metadata.artifactory_version || 'Unknown'}
                  </Descriptions.Item>
                  <Descriptions.Item label="Export Time">
                    {metadata.export_time
                      ? new Date(metadata.export_time).toLocaleString()
                      : 'Unknown'}
                  </Descriptions.Item>
                  <Descriptions.Item label="Total Repositories">
                    {metadata.repositories.length}
                  </Descriptions.Item>
                  <Descriptions.Item label="Total Artifacts">
                    {metadata.total_artifacts.toLocaleString()}
                  </Descriptions.Item>
                  <Descriptions.Item label="Total Size">
                    {formatBytes(metadata.total_size_bytes)}
                  </Descriptions.Item>
                  <Descriptions.Item label="Security Data">
                    {metadata.has_security ? (
                      <Tag color="green">Available</Tag>
                    ) : (
                      <Tag>Not Available</Tag>
                    )}
                  </Descriptions.Item>
                </Descriptions>

                <Divider titlePlacement="left">Select Repositories</Divider>

                <Space>
                  <Button onClick={() => handleSelectAllRepos(true)}>
                    Select All
                  </Button>
                  <Button onClick={() => handleSelectAllRepos(false)}>
                    Deselect All
                  </Button>
                  <Text type="secondary">
                    {repositories.filter((r) => r.selected).length} of{' '}
                    {repositories.length} selected
                  </Text>
                </Space>

                <Table
                  columns={repoColumns}
                  dataSource={repositories}
                  rowKey="key"
                  pagination={false}
                  size="small"
                />

                <Space>
                  <Button onClick={() => setCurrentStep(0)}>Back</Button>
                  <Button
                    type="primary"
                    onClick={() => setCurrentStep(2)}
                    disabled={repositories.filter((r) => r.selected).length === 0}
                  >
                    Continue
                  </Button>
                </Space>
              </Space>
            )}
          </Card>
        );

      case 2:
        return (
          <Card title="Step 3: Configure Import Options">
            <Space direction="vertical" style={{ width: '100%' }} size="large">
              <Form layout="vertical">
                <Form.Item>
                  <Checkbox
                    checked={importOptions.includeUsers}
                    onChange={(e) =>
                      setImportOptions((opts) => ({
                        ...opts,
                        includeUsers: e.target.checked,
                      }))
                    }
                    disabled={!metadata?.has_security}
                  >
                    <Space direction="vertical" size={0}>
                      <Text strong>Import Users</Text>
                      <Text type="secondary">
                        Import user accounts from the export
                      </Text>
                    </Space>
                  </Checkbox>
                </Form.Item>

                <Form.Item>
                  <Checkbox
                    checked={importOptions.includeGroups}
                    onChange={(e) =>
                      setImportOptions((opts) => ({
                        ...opts,
                        includeGroups: e.target.checked,
                      }))
                    }
                    disabled={!metadata?.has_security}
                  >
                    <Space direction="vertical" size={0}>
                      <Text strong>Import Groups</Text>
                      <Text type="secondary">
                        Import group definitions from the export
                      </Text>
                    </Space>
                  </Checkbox>
                </Form.Item>

                <Form.Item>
                  <Checkbox
                    checked={importOptions.includePermissions}
                    onChange={(e) =>
                      setImportOptions((opts) => ({
                        ...opts,
                        includePermissions: e.target.checked,
                      }))
                    }
                    disabled={!metadata?.has_security}
                  >
                    <Space direction="vertical" size={0}>
                      <Text strong>Import Permissions</Text>
                      <Text type="secondary">
                        Import permission targets and assignments
                      </Text>
                    </Space>
                  </Checkbox>
                </Form.Item>

                <Divider />

                <Form.Item>
                  <Checkbox
                    checked={importOptions.dryRun}
                    onChange={(e) =>
                      setImportOptions((opts) => ({
                        ...opts,
                        dryRun: e.target.checked,
                      }))
                    }
                  >
                    <Space direction="vertical" size={0}>
                      <Text strong>Dry Run</Text>
                      <Text type="secondary">
                        Preview what would be imported without making changes
                      </Text>
                    </Space>
                  </Checkbox>
                </Form.Item>
              </Form>

              <Alert
                message="Import Summary"
                description={
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    <li>
                      {repositories.filter((r) => r.selected).length} repositories
                    </li>
                    <li>
                      ~{metadata?.total_artifacts.toLocaleString()} artifacts
                    </li>
                    {importOptions.includeUsers && (
                      <li>Users will be imported</li>
                    )}
                    {importOptions.includeGroups && (
                      <li>Groups will be imported</li>
                    )}
                    {importOptions.includePermissions && (
                      <li>Permissions will be imported</li>
                    )}
                    {importOptions.dryRun && (
                      <li>
                        <strong>Dry run mode - no changes will be made</strong>
                      </li>
                    )}
                  </ul>
                }
                type="info"
                showIcon
              />

              <Space>
                <Button onClick={() => setCurrentStep(1)}>Back</Button>
                <Button type="primary" onClick={handleStartImport}>
                  {importOptions.dryRun ? 'Start Dry Run' : 'Start Import'}
                </Button>
              </Space>
            </Space>
          </Card>
        );

      case 3:
        return (
          <Card title="Step 4: Import Progress">
            <Space direction="vertical" style={{ width: '100%' }} size="large">
              {progress && (
                <>
                  <Progress
                    percent={Math.round((progress.current / progress.total) * 100)}
                    status="active"
                  />
                  <Space>
                    <LoadingOutlined />
                    <Text>{progress.message}</Text>
                  </Space>
                  <Text type="secondary">
                    {progress.current} of {progress.total} repositories processed
                  </Text>
                </>
              )}
            </Space>
          </Card>
        );

      case 4:
        return (
          <Card title="Step 5: Import Complete">
            {result && (
              <Space direction="vertical" style={{ width: '100%' }} size="large">
                <Alert
                  message="Import Completed Successfully"
                  description={
                    <Descriptions column={1} size="small">
                      <Descriptions.Item label="Imported">
                        <Text strong style={{ color: 'green' }}>
                          {result.imported}
                        </Text>
                      </Descriptions.Item>
                      <Descriptions.Item label="Failed">
                        <Text strong style={{ color: result.failed > 0 ? 'red' : undefined }}>
                          {result.failed}
                        </Text>
                      </Descriptions.Item>
                      <Descriptions.Item label="Skipped">
                        <Text strong>{result.skipped}</Text>
                      </Descriptions.Item>
                    </Descriptions>
                  }
                  type={result.failed > 0 ? 'warning' : 'success'}
                  showIcon
                  icon={
                    result.failed > 0 ? (
                      <ExclamationCircleOutlined />
                    ) : (
                      <CheckCircleOutlined />
                    )
                  }
                />

                {result.errors.length > 0 && (
                  <Alert
                    message="Errors"
                    description={
                      <ul style={{ margin: 0, paddingLeft: 20 }}>
                        {result.errors.map((error, i) => (
                          <li key={i}>{error}</li>
                        ))}
                      </ul>
                    }
                    type="error"
                    showIcon
                  />
                )}

                <Space>
                  <Button type="primary" onClick={onCancel}>
                    Done
                  </Button>
                  <Button
                    onClick={() => {
                      setCurrentStep(0);
                      setMetadata(null);
                      setRepositories([]);
                      setResult(null);
                      setProgress(null);
                    }}
                  >
                    Import Another
                  </Button>
                </Space>
              </Space>
            )}
          </Card>
        );

      default:
        return null;
    }
  };

  return (
    <Space direction="vertical" style={{ width: '100%' }} size="large">
      <Steps current={currentStep} items={[
        { title: 'Select Source' },
        { title: 'Review Contents' },
        { title: 'Configure' },
        { title: 'Import' },
        { title: 'Complete' },
      ]} />

      {renderStepContent()}

      {currentStep < 3 && (
        <Space>
          {onCancel && <Button onClick={onCancel}>Cancel</Button>}
        </Space>
      )}
    </Space>
  );
};

export default ImportFromExport;
