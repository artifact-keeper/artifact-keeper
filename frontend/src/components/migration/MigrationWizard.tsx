import React, { useState, useCallback } from 'react';
import { Steps, Button, Card, Space, Typography, Result, message } from 'antd';
import {
  ApiOutlined,
  DatabaseOutlined,
  SettingOutlined,
  PlayCircleOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import { SourceConnectionForm } from './SourceConnectionForm';
import { RepositorySelector } from './RepositorySelector';
import type {
  SourceConnection,
  MigrationJob,
  MigrationConfig,
} from '../../types/migration';
import { migrationApi } from '../../api/migration';

/** Extended config for wizard UI state (includes fields not in API MigrationConfig) */
type WizardConfig = Partial<MigrationConfig> & {
  include_repositories?: string[];
  include_artifacts?: boolean;
  include_metadata?: boolean;
  verify_checksums?: boolean;
};

const { Title, Text, Paragraph } = Typography;

interface MigrationWizardProps {
  onComplete?: (job: MigrationJob) => void;
  onCancel?: () => void;
}

type WizardStep = 'connection' | 'repositories' | 'configure' | 'review' | 'complete';

const STEPS: { key: WizardStep; title: string; icon: React.ReactNode }[] = [
  { key: 'connection', title: 'Connect', icon: <ApiOutlined /> },
  { key: 'repositories', title: 'Select Repos', icon: <DatabaseOutlined /> },
  { key: 'configure', title: 'Configure', icon: <SettingOutlined /> },
  { key: 'review', title: 'Review', icon: <PlayCircleOutlined /> },
  { key: 'complete', title: 'Complete', icon: <CheckCircleOutlined /> },
];

export const MigrationWizard: React.FC<MigrationWizardProps> = ({
  onComplete,
  onCancel,
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [connection, setConnection] = useState<SourceConnection | null>(null);
  const [selectedRepos, setSelectedRepos] = useState<string[]>([]);
  const [config, setConfig] = useState<WizardConfig>({
    include_repositories: [],
    include_artifacts: true,
    include_metadata: true,
    include_users: false,
    include_groups: false,
    include_permissions: false,
    conflict_resolution: 'skip',
    verify_checksums: true,
  });
  const [createdJob, setCreatedJob] = useState<MigrationJob | null>(null);
  const [loading, setLoading] = useState(false);

  const handleConnectionCreated = useCallback((conn: SourceConnection) => {
    setConnection(conn);
    setCurrentStep(1);
  }, []);

  const handleRepoSelectionChange = useCallback((keys: string[]) => {
    setSelectedRepos(keys);
    setConfig((prev) => ({
      ...prev,
      include_repositories: keys,
    }));
  }, []);

  const handleConfigChange = useCallback((updates: WizardConfig) => {
    setConfig((prev) => ({ ...prev, ...updates }));
  }, []);

  const handleStartMigration = async () => {
    if (!connection) return;

    setLoading(true);
    try {
      const job = await migrationApi.createMigration({
        source_connection_id: connection.id,
        job_type: 'full',
        config: {
          ...config,
          include_repositories: selectedRepos,
        } as MigrationConfig,
      });

      // Start the migration
      await migrationApi.startMigration(job.id);

      setCreatedJob(job);
      setCurrentStep(4);
      onComplete?.(job);
    } catch (error) {
      message.error('Failed to start migration');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const goNext = () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const goBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const renderStepContent = () => {
    switch (STEPS[currentStep].key) {
      case 'connection':
        return (
          <Card title="Connect to Artifactory">
            <Paragraph>
              Enter your Artifactory server details and credentials to begin the migration process.
            </Paragraph>
            <SourceConnectionForm
              onSuccess={handleConnectionCreated}
              onCancel={onCancel}
            />
          </Card>
        );

      case 'repositories':
        return (
          <Card title="Select Repositories">
            <Paragraph>
              Select the repositories you want to migrate. Local repositories contain hosted artifacts,
              remote repositories are proxies, and virtual repositories are groups of other repositories.
            </Paragraph>
            {connection && (
              <RepositorySelector
                connectionId={connection.id}
                selectedKeys={selectedRepos}
                onSelectionChange={handleRepoSelectionChange}
              />
            )}
          </Card>
        );

      case 'configure':
        return (
          <Card title="Migration Configuration">
            <ConfigurationForm
              config={config}
              onChange={handleConfigChange}
            />
          </Card>
        );

      case 'review':
        return (
          <Card title="Review Migration">
            <ReviewSummary
              connection={connection}
              selectedRepos={selectedRepos}
              config={config}
            />
          </Card>
        );

      case 'complete':
        return (
          <Result
            status="success"
            title="Migration Started"
            subTitle={`Migration job ${createdJob?.id} has been started. You can monitor progress in the Jobs tab.`}
            extra={[
              <Button key="view" type="primary" onClick={() => window.location.reload()}>
                View Progress
              </Button>,
              <Button key="new" onClick={() => window.location.reload()}>
                Start New Migration
              </Button>,
            ]}
          />
        );
    }
  };

  const canProceed = () => {
    switch (STEPS[currentStep].key) {
      case 'connection':
        return !!connection;
      case 'repositories':
        return selectedRepos.length > 0;
      case 'configure':
        return true;
      case 'review':
        return true;
      default:
        return false;
    }
  };

  return (
    <div>
      <Steps
        current={currentStep}
        items={STEPS.map((step) => ({
          title: step.title,
          icon: step.icon,
        }))}
        style={{ marginBottom: 24 }}
      />

      <div style={{ minHeight: 400 }}>
        {renderStepContent()}
      </div>

      {currentStep < 4 && (
        <div style={{ marginTop: 24, display: 'flex', justifyContent: 'space-between' }}>
          <Space>
            {currentStep > 0 && currentStep < 4 && (
              <Button onClick={goBack}>Back</Button>
            )}
            {onCancel && currentStep === 0 && (
              <Button onClick={onCancel}>Cancel</Button>
            )}
          </Space>
          <Space>
            {currentStep > 0 && currentStep < 3 && (
              <Button
                type="primary"
                onClick={goNext}
                disabled={!canProceed()}
              >
                Next
              </Button>
            )}
            {currentStep === 3 && (
              <Button
                type="primary"
                onClick={handleStartMigration}
                loading={loading}
                disabled={!canProceed()}
              >
                Start Migration
              </Button>
            )}
          </Space>
        </div>
      )}
    </div>
  );
};

interface ConfigurationFormProps {
  config: WizardConfig;
  onChange: (updates: WizardConfig) => void;
}

const ConfigurationForm: React.FC<ConfigurationFormProps> = ({ config, onChange }) => {
  return (
    <Space direction="vertical" style={{ width: '100%' }} size="large">
      <div>
        <Title level={5}>Content Options</Title>
        <Space direction="vertical">
          <label>
            <input
              type="checkbox"
              checked={config.include_artifacts ?? true}
              onChange={(e) => onChange({ include_artifacts: e.target.checked })}
            />{' '}
            Include artifacts (binary files)
          </label>
          <label>
            <input
              type="checkbox"
              checked={config.include_metadata ?? true}
              onChange={(e) => onChange({ include_metadata: e.target.checked })}
            />{' '}
            Include artifact metadata and properties
          </label>
        </Space>
      </div>

      <div>
        <Title level={5}>Access Control</Title>
        <Space direction="vertical">
          <label>
            <input
              type="checkbox"
              checked={config.include_users ?? false}
              onChange={(e) => onChange({ include_users: e.target.checked })}
            />{' '}
            Migrate users
          </label>
          <label>
            <input
              type="checkbox"
              checked={config.include_groups ?? false}
              onChange={(e) => onChange({ include_groups: e.target.checked })}
            />{' '}
            Migrate groups
          </label>
          <label>
            <input
              type="checkbox"
              checked={config.include_permissions ?? false}
              onChange={(e) => onChange({ include_permissions: e.target.checked })}
            />{' '}
            Migrate permissions
          </label>
        </Space>
      </div>

      <div>
        <Title level={5}>Conflict Resolution</Title>
        <select
          value={config.conflict_resolution ?? 'skip'}
          onChange={(e) => onChange({ conflict_resolution: e.target.value as 'skip' | 'overwrite' | 'rename' })}
          style={{ padding: '4px 8px' }}
        >
          <option value="skip">Skip existing artifacts</option>
          <option value="overwrite">Overwrite existing artifacts</option>
          <option value="rename">Rename with suffix</option>
        </select>
      </div>

      <div>
        <Title level={5}>Verification</Title>
        <label>
          <input
            type="checkbox"
            checked={config.verify_checksums ?? true}
            onChange={(e) => onChange({ verify_checksums: e.target.checked })}
          />{' '}
          Verify checksums after transfer
        </label>
      </div>
    </Space>
  );
};

interface ReviewSummaryProps {
  connection: SourceConnection | null;
  selectedRepos: string[];
  config: WizardConfig;
}

const ReviewSummary: React.FC<ReviewSummaryProps> = ({
  connection,
  selectedRepos,
  config,
}) => {
  return (
    <Space direction="vertical" style={{ width: '100%' }} size="large">
      <div>
        <Title level={5}>Source Connection</Title>
        <Text>{connection?.name}</Text>
        <br />
        <Text type="secondary">{connection?.url}</Text>
      </div>

      <div>
        <Title level={5}>Repositories ({selectedRepos.length})</Title>
        <div style={{ maxHeight: 150, overflow: 'auto' }}>
          {selectedRepos.map((repo) => (
            <div key={repo}>
              <Text code>{repo}</Text>
            </div>
          ))}
        </div>
      </div>

      <div>
        <Title level={5}>Configuration</Title>
        <Space direction="vertical">
          <Text>Artifacts: {config.include_artifacts ? 'Yes' : 'No'}</Text>
          <Text>Metadata: {config.include_metadata ? 'Yes' : 'No'}</Text>
          <Text>Users: {config.include_users ? 'Yes' : 'No'}</Text>
          <Text>Groups: {config.include_groups ? 'Yes' : 'No'}</Text>
          <Text>Permissions: {config.include_permissions ? 'Yes' : 'No'}</Text>
          <Text>Conflict Resolution: {config.conflict_resolution}</Text>
          <Text>Verify Checksums: {config.verify_checksums ? 'Yes' : 'No'}</Text>
        </Space>
      </div>
    </Space>
  );
};

export default MigrationWizard;
