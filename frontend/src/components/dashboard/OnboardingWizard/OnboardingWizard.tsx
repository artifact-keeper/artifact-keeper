import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Steps, Card, Button, Typography, Space, Result } from 'antd';
import {
  RocketOutlined,
  DatabaseOutlined,
  UploadOutlined,
  CompassOutlined,
  CheckCircleOutlined,
  ArrowLeftOutlined,
  ArrowRightOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';

const { Title, Text, Paragraph } = Typography;

export interface OnboardingWizardProps {
  onComplete: () => void;
  onSkip: () => void;
}

interface StepContent {
  title: string;
  description: string;
  icon: React.ReactNode;
}

const steps: StepContent[] = [
  {
    title: 'Welcome',
    description: 'Get started',
    icon: <RocketOutlined />,
  },
  {
    title: 'Create Repository',
    description: 'Set up storage',
    icon: <DatabaseOutlined />,
  },
  {
    title: 'Upload Artifact',
    description: 'Add your first file',
    icon: <UploadOutlined />,
  },
  {
    title: 'Explore Features',
    description: 'Discover more',
    icon: <CompassOutlined />,
  },
];

export const OnboardingWizard: React.FC<OnboardingWizardProps> = ({
  onComplete,
  onSkip,
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const navigate = useNavigate();

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      onComplete();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSkipStep = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      onComplete();
    }
  };

  const renderWelcomeStep = () => (
    <Result
      icon={
        <RocketOutlined
          style={{ fontSize: 72, color: colors.primary }}
        />
      }
      title={
        <Title level={3} style={{ marginBottom: spacing.xs }}>
          Welcome to Artifact Keeper
        </Title>
      }
      subTitle={
        <Space orientation="vertical" size="small">
          <Text type="secondary" style={{ fontSize: 16 }}>
            Your centralized platform for managing artifacts, packages, and dependencies.
          </Text>
          <Paragraph type="secondary" style={{ marginTop: spacing.md, marginBottom: 0 }}>
            This quick setup will help you get started with the key features.
            You can skip any step and complete the setup later.
          </Paragraph>
        </Space>
      }
    />
  );

  const renderCreateRepositoryStep = () => (
    <Result
      icon={
        <DatabaseOutlined
          style={{ fontSize: 72, color: colors.primary }}
        />
      }
      title={
        <Title level={3} style={{ marginBottom: spacing.xs }}>
          Create Your First Repository
        </Title>
      }
      subTitle={
        <Space orientation="vertical" size="small">
          <Text type="secondary" style={{ fontSize: 16 }}>
            Repositories are containers for your artifacts and packages.
          </Text>
          <Paragraph type="secondary" style={{ marginTop: spacing.md, marginBottom: 0 }}>
            You can create different repository types for various package formats
            like Docker, npm, Maven, and more.
          </Paragraph>
        </Space>
      }
      extra={
        <Button
          type="primary"
          size="large"
          icon={<DatabaseOutlined />}
          onClick={() => navigate('/repositories/new')}
        >
          Create Repository
        </Button>
      }
    />
  );

  const renderUploadArtifactStep = () => (
    <Result
      icon={
        <UploadOutlined
          style={{ fontSize: 72, color: colors.primary }}
        />
      }
      title={
        <Title level={3} style={{ marginBottom: spacing.xs }}>
          Upload Your First Artifact
        </Title>
      }
      subTitle={
        <Space orientation="vertical" size="small">
          <Text type="secondary" style={{ fontSize: 16 }}>
            Add artifacts to your repositories for versioning and distribution.
          </Text>
          <Paragraph type="secondary" style={{ marginTop: spacing.md, marginBottom: 0 }}>
            Upload files directly through the web interface or use CLI tools
            and package managers for automated workflows.
          </Paragraph>
        </Space>
      }
      extra={
        <Button
          type="primary"
          size="large"
          icon={<UploadOutlined />}
          onClick={() => navigate('/repositories')}
        >
          Go to Repositories
        </Button>
      }
    />
  );

  const renderExploreFeaturesStep = () => {
    const features = [
      {
        title: 'Repository Management',
        description: 'Organize and manage multiple repository types',
        path: '/repositories',
      },
      {
        title: 'Artifact Browser',
        description: 'Browse, search, and download artifacts',
        path: '/artifacts',
      },
      {
        title: 'Access Control',
        description: 'Manage permissions and API keys',
        path: '/profile',
      },
      {
        title: 'System Administration',
        description: 'Configure system settings and users',
        path: '/admin',
      },
    ];

    return (
      <div style={{ textAlign: 'center', padding: `${spacing.lg}px 0` }}>
        <CompassOutlined
          style={{ fontSize: 72, color: colors.primary, marginBottom: spacing.lg }}
        />
        <Title level={3} style={{ marginBottom: spacing.xs }}>
          Explore Key Features
        </Title>
        <Text type="secondary" style={{ fontSize: 16, display: 'block', marginBottom: spacing.xl }}>
          Discover the powerful capabilities available to you.
        </Text>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: spacing.md,
            maxWidth: 600,
            margin: '0 auto',
          }}
        >
          {features.map((feature) => (
            <Card
              key={feature.path}
              size="small"
              hoverable
              onClick={() => navigate(feature.path)}
              style={{
                textAlign: 'left',
                borderRadius: borderRadius.md,
                cursor: 'pointer',
              }}
            >
              <Text strong style={{ display: 'block', marginBottom: spacing.xxs }}>
                {feature.title}
              </Text>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {feature.description}
              </Text>
            </Card>
          ))}
        </div>
      </div>
    );
  };

  const renderStepContent = () => {
    switch (currentStep) {
      case 0:
        return renderWelcomeStep();
      case 1:
        return renderCreateRepositoryStep();
      case 2:
        return renderUploadArtifactStep();
      case 3:
        return renderExploreFeaturesStep();
      default:
        return null;
    }
  };

  const isLastStep = currentStep === steps.length - 1;
  const isFirstStep = currentStep === 0;

  return (
    <Card
      style={{
        maxWidth: 800,
        margin: '0 auto',
        borderRadius: borderRadius.lg,
      }}
      styles={{
        body: {
          padding: spacing.xl,
        },
      }}
    >
      <Steps
        current={currentStep}
        items={steps.map((step) => ({
          title: step.title,
          description: step.description,
          icon: step.icon,
        }))}
        style={{ marginBottom: spacing.xl }}
        responsive
      />

      <div
        style={{
          minHeight: 300,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
        }}
      >
        {renderStepContent()}
      </div>

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: spacing.xl,
          paddingTop: spacing.lg,
          borderTop: `1px solid ${colors.borderLight}`,
        }}
      >
        <div>
          {!isFirstStep && (
            <Button
              icon={<ArrowLeftOutlined />}
              onClick={handlePrevious}
            >
              Previous
            </Button>
          )}
        </div>

        <Space>
          <Button onClick={onSkip}>
            Skip Setup
          </Button>
          {!isLastStep && currentStep > 0 && (
            <Button onClick={handleSkipStep}>
              Skip Step
            </Button>
          )}
          <Button
            type="primary"
            icon={isLastStep ? <CheckCircleOutlined /> : <ArrowRightOutlined />}
            iconPlacement="end"
            onClick={handleNext}
          >
            {isLastStep ? 'Complete' : 'Next'}
          </Button>
        </Space>
      </div>
    </Card>
  );
};

export default OnboardingWizard;
