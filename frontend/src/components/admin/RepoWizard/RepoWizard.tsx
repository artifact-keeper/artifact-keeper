import React, { useState, useEffect, useCallback } from 'react';
import { Modal, Steps, Button, Space, Form, message } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeftOutlined,
  ArrowRightOutlined,
  CheckOutlined,
  DatabaseOutlined,
  AppstoreOutlined,
  SettingOutlined,
  ControlOutlined,
  LinkOutlined,
  ClusterOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import { repositoriesApi } from '../../../api';
import type { Repository, RepositoryType, RepositoryFormat, CreateRepositoryRequest } from '../../../types';
import RepoTypeSelector from './RepoTypeSelector';
import PackageTypeSelector from './PackageTypeSelector';
import BasicConfigStep, { type BasicConfigFormValues } from './BasicConfigStep';
import AdvancedConfigStep, { type AdvancedConfigFormValues } from './AdvancedConfigStep';
import RemoteRepoConfig, { type RemoteRepoConfigFormValues } from './RemoteRepoConfig';
import VirtualRepoConfig, { type VirtualRepoConfigFormValues } from './VirtualRepoConfig';

export interface RepoWizardProps {
  visible: boolean;
  onClose: () => void;
  onSuccess?: (repository: Repository) => void;
  editMode?: boolean;
  initialValues?: Partial<Repository>;
}

interface StepConfig {
  key: string;
  title: string;
  icon: React.ReactNode;
  component: React.ReactNode;
}

export const RepoWizard: React.FC<RepoWizardProps> = ({
  visible,
  onClose,
  onSuccess,
  editMode = false,
  initialValues,
}) => {
  const queryClient = useQueryClient();
  const [currentStep, setCurrentStep] = useState(0);
  const [repoType, setRepoType] = useState<RepositoryType | undefined>(initialValues?.repo_type);
  const [packageType, setPackageType] = useState<RepositoryFormat | undefined>(initialValues?.format);

  const [basicForm] = Form.useForm<BasicConfigFormValues>();
  const [advancedForm] = Form.useForm<AdvancedConfigFormValues>();
  const [remoteForm] = Form.useForm<RemoteRepoConfigFormValues>();
  const [virtualForm] = Form.useForm<VirtualRepoConfigFormValues>();

  const { data: repositoriesData } = useQuery({
    queryKey: ['repositories', 'all'],
    queryFn: () => repositoriesApi.list({ per_page: 1000 }),
    enabled: visible && repoType === 'virtual',
  });

  const availableRepos = repositoriesData?.items || [];

  const createMutation = useMutation({
    mutationFn: (data: CreateRepositoryRequest) => repositoriesApi.create(data),
    onSuccess: (repository) => {
      message.success(`Repository "${repository.name}" created successfully`);
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      onSuccess?.(repository);
      handleClose();
    },
    onError: (error: Error) => {
      message.error(`Failed to create repository: ${error.message}`);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ key, data }: { key: string; data: Partial<CreateRepositoryRequest> }) =>
      repositoriesApi.update(key, data),
    onSuccess: (repository) => {
      message.success(`Repository "${repository.name}" updated successfully`);
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      onSuccess?.(repository);
      handleClose();
    },
    onError: (error: Error) => {
      message.error(`Failed to update repository: ${error.message}`);
    },
  });

  const isLoading = createMutation.isPending || updateMutation.isPending;

  useEffect(() => {
    if (visible && initialValues) {
      setRepoType(initialValues.repo_type);
      setPackageType(initialValues.format);
      basicForm.setFieldsValue({
        key: initialValues.key,
        name: initialValues.name,
        description: initialValues.description,
        is_public: initialValues.is_public,
      });
    }
  }, [visible, initialValues, basicForm]);

  const handleClose = useCallback(() => {
    setCurrentStep(0);
    setRepoType(undefined);
    setPackageType(undefined);
    basicForm.resetFields();
    advancedForm.resetFields();
    remoteForm.resetFields();
    virtualForm.resetFields();
    onClose();
  }, [basicForm, advancedForm, remoteForm, virtualForm, onClose]);

  const getSteps = useCallback((): StepConfig[] => {
    const steps: StepConfig[] = [
      {
        key: 'repo-type',
        title: 'Repository Type',
        icon: <DatabaseOutlined />,
        component: <RepoTypeSelector value={repoType} onChange={setRepoType} />,
      },
      {
        key: 'package-type',
        title: 'Package Format',
        icon: <AppstoreOutlined />,
        component: (
          <PackageTypeSelector
            value={packageType}
            onChange={setPackageType}
            repoType={repoType}
          />
        ),
      },
      {
        key: 'basic-config',
        title: 'Basic Settings',
        icon: <SettingOutlined />,
        component: (
          <BasicConfigStep form={basicForm} repoType={repoType} packageType={packageType} />
        ),
      },
    ];

    if (repoType === 'remote') {
      steps.push({
        key: 'remote-config',
        title: 'Remote Settings',
        icon: <LinkOutlined />,
        component: <RemoteRepoConfig form={remoteForm} />,
      });
    }

    if (repoType === 'virtual') {
      steps.push({
        key: 'virtual-config',
        title: 'Virtual Settings',
        icon: <ClusterOutlined />,
        component: <VirtualRepoConfig form={virtualForm} availableRepos={availableRepos} />,
      });
    }

    steps.push({
      key: 'advanced-config',
      title: 'Advanced',
      icon: <ControlOutlined />,
      component: <AdvancedConfigStep form={advancedForm} repoType={repoType} />,
    });

    return steps;
  }, [repoType, packageType, basicForm, advancedForm, remoteForm, virtualForm, availableRepos]);

  const steps = getSteps();
  const isFirstStep = currentStep === 0;
  const isLastStep = currentStep === steps.length - 1;

  const validateCurrentStep = async (): Promise<boolean> => {
    const currentStepKey = steps[currentStep]?.key;

    switch (currentStepKey) {
      case 'repo-type':
        if (!repoType) {
          message.warning('Please select a repository type');
          return false;
        }
        return true;

      case 'package-type':
        if (!packageType) {
          message.warning('Please select a package format');
          return false;
        }
        return true;

      case 'basic-config':
        try {
          await basicForm.validateFields();
          return true;
        } catch {
          return false;
        }

      case 'remote-config':
        try {
          await remoteForm.validateFields();
          return true;
        } catch {
          return false;
        }

      case 'virtual-config':
        try {
          await virtualForm.validateFields();
          return true;
        } catch {
          return false;
        }

      case 'advanced-config':
        return true;

      default:
        return true;
    }
  };

  const handleNext = async () => {
    const isValid = await validateCurrentStep();
    if (isValid && currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSubmit = async () => {
    const isValid = await validateCurrentStep();
    if (!isValid) return;

    const basicValues = basicForm.getFieldsValue();
    const advancedValues = advancedForm.getFieldsValue();

    if (!repoType || !packageType) {
      message.error('Repository type and package format are required');
      return;
    }

    const repositoryData: CreateRepositoryRequest = {
      key: basicValues.key,
      name: basicValues.name,
      description: basicValues.description,
      format: packageType,
      repo_type: repoType,
      is_public: basicValues.is_public,
      quota_bytes: advancedValues.quota_bytes,
    };

    if (editMode && initialValues?.key) {
      updateMutation.mutate({
        key: initialValues.key,
        data: repositoryData,
      });
    } else {
      createMutation.mutate(repositoryData);
    }
  };

  const modalTitle = editMode ? 'Edit Repository' : 'Create New Repository';

  return (
    <Modal
      open={visible}
      title={modalTitle}
      onCancel={handleClose}
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
      <Steps
        current={currentStep}
        items={steps.map((step) => ({
          key: step.key,
          title: step.title,
          icon: step.icon,
        }))}
        size="small"
        style={{ marginBottom: spacing.xl }}
      />

      <div
        style={{
          minHeight: 350,
          padding: `${spacing.md}px 0`,
          overflow: 'auto',
        }}
      >
        {steps[currentStep]?.component}
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
          {!isFirstStep && (
            <Button icon={<ArrowLeftOutlined />} onClick={handlePrevious} disabled={isLoading}>
              Previous
            </Button>
          )}
        </div>

        <Space>
          <Button onClick={handleClose} disabled={isLoading}>
            Cancel
          </Button>
          {isLastStep ? (
            <Button
              type="primary"
              icon={<CheckOutlined />}
              onClick={handleSubmit}
              loading={isLoading}
            >
              {editMode ? 'Save Changes' : 'Create Repository'}
            </Button>
          ) : (
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

export default RepoWizard;
