import React, { useState, useMemo, useCallback } from 'react';
import { Modal, Steps, Card, Button, Space, Typography, Empty } from 'antd';
import {
  ArrowLeftOutlined,
  ArrowRightOutlined,
  CloseOutlined,
  BuildOutlined,
  BoxPlotOutlined,
  ContainerOutlined,
  CodeOutlined,
  AppstoreOutlined,
} from '@ant-design/icons';
import type { Repository, RepositoryFormat } from '../../../types';
import { MavenSetup } from './MavenSetup';
import { NpmSetup } from './NpmSetup';
import { DockerSetup } from './DockerSetup';
import { PyPISetup } from './PyPISetup';
import { colors, spacing, borderRadius } from '../../../styles/tokens';

const { Title, Text, Paragraph } = Typography;

export interface PackageManagerWizardProps {
  repository?: Repository;
  onClose: () => void;
}

interface PackageManagerOption {
  key: RepositoryFormat;
  label: string;
  description: string;
  icon: React.ReactNode;
}

const supportedPackageManagers: PackageManagerOption[] = [
  {
    key: 'maven',
    label: 'Maven',
    description: 'Java/JVM dependency management',
    icon: <BuildOutlined style={{ fontSize: 32 }} />,
  },
  {
    key: 'npm',
    label: 'npm',
    description: 'Node.js package management',
    icon: <BoxPlotOutlined style={{ fontSize: 32 }} />,
  },
  {
    key: 'docker',
    label: 'Docker',
    description: 'Container image registry',
    icon: <ContainerOutlined style={{ fontSize: 32 }} />,
  },
  {
    key: 'pypi',
    label: 'PyPI',
    description: 'Python package management',
    icon: <CodeOutlined style={{ fontSize: 32 }} />,
  },
];

export const PackageManagerWizard: React.FC<PackageManagerWizardProps> = ({
  repository,
  onClose,
}) => {
  const [currentStep, setCurrentStep] = useState(repository ? 1 : 0);
  const [selectedPackageManager, setSelectedPackageManager] = useState<RepositoryFormat | undefined>(
    repository?.format
  );

  const baseUrl = useMemo(() => {
    if (typeof window !== 'undefined') {
      return `${window.location.protocol}//${window.location.host}/api/v1`;
    }
    return '/api/v1';
  }, []);

  const handlePackageManagerSelect = useCallback((format: RepositoryFormat) => {
    setSelectedPackageManager(format);
  }, []);

  const handleNext = useCallback(() => {
    if (currentStep === 0 && selectedPackageManager) {
      setCurrentStep(1);
    }
  }, [currentStep, selectedPackageManager]);

  const handlePrevious = useCallback(() => {
    if (currentStep > 0 && !repository) {
      setCurrentStep(0);
    }
  }, [currentStep, repository]);

  const canGoNext = currentStep === 0 && selectedPackageManager;
  const canGoPrevious = currentStep > 0 && !repository;
  const isLastStep = currentStep === 1;

  const steps = useMemo(() => {
    const stepsList = [];
    if (!repository) {
      stepsList.push({
        key: 'select',
        title: 'Select Package Manager',
        icon: <AppstoreOutlined />,
      });
    }
    stepsList.push({
      key: 'configure',
      title: 'Configuration',
      icon: selectedPackageManager
        ? supportedPackageManagers.find((pm) => pm.key === selectedPackageManager)?.icon
        : <AppstoreOutlined />,
    });
    return stepsList;
  }, [repository, selectedPackageManager]);

  const renderPackageManagerSelection = () => (
    <div>
      <div style={{ textAlign: 'center', marginBottom: spacing.xl }}>
        <Title level={4}>Select Package Manager Type</Title>
        <Paragraph type="secondary">
          Choose the package manager you want to configure. Each option provides specific setup instructions.
        </Paragraph>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: spacing.md,
          maxWidth: 700,
          margin: '0 auto',
        }}
      >
        {supportedPackageManagers.map((pm) => {
          const isSelected = selectedPackageManager === pm.key;
          return (
            <Card
              key={pm.key}
              hoverable
              onClick={() => handlePackageManagerSelect(pm.key)}
              style={{
                textAlign: 'center',
                cursor: 'pointer',
                borderColor: isSelected ? colors.primary : colors.border,
                borderWidth: isSelected ? 2 : 1,
                backgroundColor: isSelected ? colors.bgContainerLight : colors.bgContainer,
                transition: 'all 0.2s ease',
              }}
              styles={{
                body: {
                  padding: spacing.lg,
                },
              }}
            >
              <div
                style={{
                  color: isSelected ? colors.primary : colors.textSecondary,
                  marginBottom: spacing.md,
                }}
              >
                {pm.icon}
              </div>
              <Title
                level={5}
                style={{
                  marginBottom: spacing.xxs,
                  color: isSelected ? colors.primary : colors.textPrimary,
                }}
              >
                {pm.label}
              </Title>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {pm.description}
              </Text>
            </Card>
          );
        })}
      </div>
    </div>
  );

  const renderConfiguration = () => {
    const format = selectedPackageManager || repository?.format;
    const configRepository = repository || {
      id: 'example-id',
      key: 'my-repo',
      name: 'My Repository',
      format: format!,
      repo_type: 'local' as const,
      is_public: false,
      storage_used_bytes: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    switch (format) {
      case 'maven':
        return <MavenSetup repository={configRepository} baseUrl={baseUrl} />;
      case 'npm':
        return <NpmSetup repository={configRepository} baseUrl={baseUrl} />;
      case 'docker':
        return <DockerSetup repository={configRepository} baseUrl={baseUrl} />;
      case 'pypi':
        return <PyPISetup repository={configRepository} baseUrl={baseUrl} />;
      default:
        return (
          <Empty
            description={
              <Space orientation="vertical">
                <Text>Configuration not available for this package type.</Text>
                <Text type="secondary">
                  Supported types: Maven, npm, Docker, PyPI
                </Text>
              </Space>
            }
          />
        );
    }
  };

  const renderStepContent = () => {
    if (repository) {
      return renderConfiguration();
    }

    switch (currentStep) {
      case 0:
        return renderPackageManagerSelection();
      case 1:
        return renderConfiguration();
      default:
        return null;
    }
  };

  return (
    <Modal
      open
      title={
        <Space>
          <AppstoreOutlined />
          <span>
            {repository
              ? `Setup ${repository.name} Repository`
              : 'Package Manager Setup'}
          </span>
        </Space>
      }
      onCancel={onClose}
      width={900}
      centered
      destroyOnClose
      footer={null}
      styles={{
        body: {
          padding: spacing.lg,
          minHeight: 500,
        },
      }}
    >
      {!repository && steps.length > 1 && (
        <Steps
          current={currentStep}
          items={steps.map((step) => ({
            key: step.key,
            title: step.title,
          }))}
          size="small"
          style={{ marginBottom: spacing.xl }}
        />
      )}

      <div
        style={{
          minHeight: 400,
          maxHeight: 'calc(80vh - 200px)',
          overflow: 'auto',
          padding: `${spacing.md}px 0`,
        }}
      >
        {renderStepContent()}
      </div>

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          paddingTop: spacing.lg,
          borderTop: `1px solid ${colors.borderLight}`,
          marginTop: spacing.lg,
        }}
      >
        <div>
          {canGoPrevious && (
            <Button icon={<ArrowLeftOutlined />} onClick={handlePrevious}>
              Previous
            </Button>
          )}
        </div>

        <Space>
          <Button icon={<CloseOutlined />} onClick={onClose}>
            Close
          </Button>
          {!isLastStep && canGoNext && (
            <Button
              type="primary"
              icon={<ArrowRightOutlined />}
              iconPlacement="end"
              onClick={handleNext}
            >
              Next
            </Button>
          )}
        </Space>
      </div>
    </Modal>
  );
};

export default PackageManagerWizard;
