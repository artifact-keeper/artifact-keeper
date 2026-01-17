import React, { useState } from 'react';
import { Modal, Tabs, Typography, Space, Button, message } from 'antd';
import {
  GithubOutlined,
  GitlabOutlined,
  CloseOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { Repository } from '../../../types';
import JenkinsSetup from './JenkinsSetup';
import GitHubActionsSetup from './GitHubActionsSetup';
import GitLabCISetup from './GitLabCISetup';
import AzureDevOpsSetup from './AzureDevOpsSetup';

const { Title, Text } = Typography;

export interface CICDPlatformWizardProps {
  repository?: Repository;
  onClose: () => void;
  visible?: boolean;
}

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, language = 'yaml', filename }) => {
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      message.success('Copied to clipboard');
    } catch {
      message.error('Failed to copy to clipboard');
    }
  };

  return (
    <div
      style={{
        backgroundColor: '#1e1e1e',
        borderRadius: borderRadius.md,
        overflow: 'hidden',
        marginBottom: spacing.md,
      }}
    >
      {filename && (
        <div
          style={{
            backgroundColor: '#2d2d2d',
            padding: `${spacing.xs}px ${spacing.md}px`,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: '1px solid #404040',
          }}
        >
          <Text style={{ color: '#e0e0e0', fontSize: 12, fontFamily: 'monospace' }}>
            {filename}
          </Text>
          <Button
            type="text"
            size="small"
            onClick={handleCopy}
            style={{ color: '#e0e0e0' }}
          >
            Copy
          </Button>
        </div>
      )}
      <div style={{ position: 'relative' }}>
        {!filename && (
          <Button
            type="text"
            size="small"
            onClick={handleCopy}
            style={{
              position: 'absolute',
              top: spacing.xs,
              right: spacing.xs,
              color: '#e0e0e0',
              zIndex: 1,
            }}
          >
            Copy
          </Button>
        )}
        <pre
          style={{
            margin: 0,
            padding: spacing.md,
            color: '#d4d4d4',
            fontSize: 13,
            fontFamily: "'Fira Code', 'Monaco', 'Menlo', monospace",
            lineHeight: 1.5,
            overflow: 'auto',
            maxHeight: 400,
          }}
        >
          <code className={`language-${language}`}>{code}</code>
        </pre>
      </div>
    </div>
  );
};

const JenkinsIcon: React.FC = () => (
  <svg viewBox="0 0 24 24" width="1em" height="1em" fill="currentColor">
    <path d="M4.5,5.5C4.5,5.5 3.5,7.5 4.5,9C5.5,10.5 5.5,11.5 5,12.5C4.5,13.5 3.5,14 3.5,15.5C3.5,17 4,18.5 5,19.5C6,20.5 7.5,21 9,21C10.5,21 12,20.5 13.5,19C15,17.5 16,15.5 17,14.5C18,13.5 19.5,13 20,11.5C20.5,10 20,8.5 18.5,7.5C17,6.5 15.5,6.5 14.5,6C13.5,5.5 12.5,4.5 11,4C9.5,3.5 7,3.5 5.5,4.5C4,5.5 4.5,5.5 4.5,5.5Z" />
  </svg>
);

const AzureIcon: React.FC = () => (
  <svg viewBox="0 0 24 24" width="1em" height="1em" fill="currentColor">
    <path d="M5.483 21.3H24L14.025 4.013l-3.038 8.347 5.836 6.938L5.483 21.3zM13.049 4.594l-6.394 5.406L0 19.292h5.483l7.566-14.698z" />
  </svg>
);

type CICDPlatform = 'github' | 'gitlab' | 'jenkins' | 'azure';

export const CICDPlatformWizard: React.FC<CICDPlatformWizardProps> = ({
  repository,
  onClose,
  visible = true,
}) => {
  const [activeTab, setActiveTab] = useState<CICDPlatform>('github');

  const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'https://artifact-keeper.example.com';

  const tabItems = [
    {
      key: 'github' as CICDPlatform,
      label: (
        <Space>
          <GithubOutlined />
          GitHub Actions
        </Space>
      ),
      children: <GitHubActionsSetup repository={repository} baseUrl={baseUrl} />,
    },
    {
      key: 'gitlab' as CICDPlatform,
      label: (
        <Space>
          <GitlabOutlined />
          GitLab CI
        </Space>
      ),
      children: <GitLabCISetup repository={repository} baseUrl={baseUrl} />,
    },
    {
      key: 'jenkins' as CICDPlatform,
      label: (
        <Space>
          <span style={{ display: 'flex', alignItems: 'center' }}>
            <JenkinsIcon />
          </span>
          Jenkins
        </Space>
      ),
      children: <JenkinsSetup repository={repository} baseUrl={baseUrl} />,
    },
    {
      key: 'azure' as CICDPlatform,
      label: (
        <Space>
          <span style={{ display: 'flex', alignItems: 'center' }}>
            <AzureIcon />
          </span>
          Azure DevOps
        </Space>
      ),
      children: <AzureDevOpsSetup repository={repository} baseUrl={baseUrl} />,
    },
  ];

  return (
    <Modal
      open={visible}
      title={
        <Space>
          <Title level={4} style={{ margin: 0 }}>
            CI/CD Integration Setup
          </Title>
        </Space>
      }
      onCancel={onClose}
      width={900}
      centered
      footer={
        <Button onClick={onClose}>
          Close
        </Button>
      }
      closeIcon={<CloseOutlined />}
      styles={{
        body: {
          padding: spacing.lg,
          maxHeight: 'calc(100vh - 200px)',
          overflow: 'auto',
        },
      }}
    >
      <Text type="secondary" style={{ display: 'block', marginBottom: spacing.lg }}>
        Configure your CI/CD platform to integrate with Artifact Keeper
        {repository && (
          <>
            {' '}for repository <Text strong>{repository.name}</Text>
          </>
        )}
        . Select your platform below and follow the setup instructions.
      </Text>

      <Tabs
        activeKey={activeTab}
        onChange={(key) => setActiveTab(key as CICDPlatform)}
        items={tabItems}
        type="card"
        style={{
          marginTop: spacing.md,
        }}
      />
    </Modal>
  );
};

export default CICDPlatformWizard;
