import React, { useState, useEffect, useCallback } from 'react';
import { Modal, Steps, Button, Space, Form, Input, message } from 'antd';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeftOutlined,
  ArrowRightOutlined,
  CheckOutlined,
  InfoCircleOutlined,
  DatabaseOutlined,
  LockOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import { colors, spacing } from '../../../styles/tokens';
import { repositoriesApi, groupsApi, adminApi } from '../../../api';
import type { Repository, User } from '../../../types';
import type { Group, PermissionAction } from '../../../api';
import RepositoryPatternSelector, { type PatternValue } from './RepositoryPatternSelector';
import PermissionAssigner, { type PermissionAssignerValue } from './PermissionAssigner';
import type { PermissionTargetData } from './PermissionTargetTable';

const { TextArea } = Input;

export interface PermissionTargetWizardProps {
  visible: boolean;
  onClose: () => void;
  onSuccess?: (target: PermissionTargetData) => void;
  initialValues?: Partial<PermissionTargetData>;
}

interface BasicInfoFormValues {
  name: string;
  description?: string;
}

interface StepConfig {
  key: string;
  title: string;
  icon: React.ReactNode;
}

export const PermissionTargetWizard: React.FC<PermissionTargetWizardProps> = ({
  visible,
  onClose,
  onSuccess,
  initialValues,
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [basicForm] = Form.useForm<BasicInfoFormValues>();
  const [patternValue, setPatternValue] = useState<PatternValue>({
    includePatterns: [],
    excludePatterns: [],
    selectedRepositories: [],
  });
  const [permissionValue, setPermissionValue] = useState<PermissionAssignerValue>({
    actions: [],
    assignments: [],
  });

  const isEditMode = !!initialValues?.id;

  const { data: repositoriesData, isLoading: repositoriesLoading } = useQuery({
    queryKey: ['repositories', 'all'],
    queryFn: () => repositoriesApi.list({ per_page: 1000 }),
    enabled: visible,
  });

  const { data: groupsData, isLoading: groupsLoading } = useQuery({
    queryKey: ['groups', 'all'],
    queryFn: () => groupsApi.list({ per_page: 1000 }),
    enabled: visible,
  });

  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ['users', 'all'],
    queryFn: () => adminApi.listUsers(),
    enabled: visible,
  });

  const repositories: Repository[] = repositoriesData?.items || [];
  const groups: Group[] = groupsData?.items || [];
  const users: User[] = usersData || [];

  useEffect(() => {
    if (visible && initialValues) {
      basicForm.setFieldsValue({
        name: initialValues.name,
        description: initialValues.description,
      });

      if (initialValues.repository_pattern) {
        setPatternValue({
          includePatterns: [initialValues.repository_pattern],
          excludePatterns: [],
          selectedRepositories: [],
        });
      }

      if (initialValues.actions) {
        const assignments = [
          ...(initialValues.assigned_users || []).map((u) => ({
            principalType: 'user' as const,
            principalId: u.id,
            principalName: u.name,
            actions: initialValues.actions || [],
          })),
          ...(initialValues.assigned_groups || []).map((g) => ({
            principalType: 'group' as const,
            principalId: g.id,
            principalName: g.name,
            actions: initialValues.actions || [],
          })),
        ];

        setPermissionValue({
          actions: initialValues.actions,
          assignments,
        });
      }
    }
  }, [visible, initialValues, basicForm]);

  const handleClose = useCallback(() => {
    setCurrentStep(0);
    basicForm.resetFields();
    setPatternValue({
      includePatterns: [],
      excludePatterns: [],
      selectedRepositories: [],
    });
    setPermissionValue({
      actions: [],
      assignments: [],
    });
    onClose();
  }, [basicForm, onClose]);

  const steps: StepConfig[] = [
    {
      key: 'basic',
      title: 'Basic Info',
      icon: <InfoCircleOutlined />,
    },
    {
      key: 'repositories',
      title: 'Repository Pattern',
      icon: <DatabaseOutlined />,
    },
    {
      key: 'permissions',
      title: 'Permissions',
      icon: <LockOutlined />,
    },
    {
      key: 'assignment',
      title: 'Assignment',
      icon: <TeamOutlined />,
    },
  ];

  const isFirstStep = currentStep === 0;
  const isLastStep = currentStep === steps.length - 1;

  const validateCurrentStep = async (): Promise<boolean> => {
    const currentStepKey = steps[currentStep]?.key;

    switch (currentStepKey) {
      case 'basic':
        try {
          await basicForm.validateFields();
          return true;
        } catch {
          return false;
        }

      case 'repositories':
        if (
          patternValue.includePatterns.length === 0 &&
          patternValue.selectedRepositories.length === 0
        ) {
          message.warning('Please select at least one repository or add an include pattern');
          return false;
        }
        return true;

      case 'permissions':
        if (permissionValue.actions.length === 0) {
          message.warning('Please select at least one permission action');
          return false;
        }
        return true;

      case 'assignment':
        if (permissionValue.assignments.length === 0) {
          message.warning('Please assign permissions to at least one user or group');
          return false;
        }
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

    setIsSubmitting(true);

    try {
      const basicValues = basicForm.getFieldsValue();

      const repositoryPattern =
        patternValue.includePatterns.length > 0
          ? patternValue.includePatterns.join(',')
          : patternValue.selectedRepositories.join(',');

      const targetData: PermissionTargetData = {
        id: initialValues?.id || `target-${Date.now()}`,
        name: basicValues.name,
        description: basicValues.description,
        repository_pattern: repositoryPattern,
        actions: permissionValue.actions,
        assigned_users: permissionValue.assignments
          .filter((a) => a.principalType === 'user')
          .map((a) => ({ id: a.principalId, name: a.principalName })),
        assigned_groups: permissionValue.assignments
          .filter((a) => a.principalType === 'group')
          .map((a) => ({ id: a.principalId, name: a.principalName })),
        created_at: initialValues?.created_at || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      message.success(
        isEditMode
          ? `Permission target "${targetData.name}" updated successfully`
          : `Permission target "${targetData.name}" created successfully`
      );

      onSuccess?.(targetData);
      handleClose();
    } catch (error) {
      message.error(
        isEditMode
          ? 'Failed to update permission target'
          : 'Failed to create permission target'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderStepContent = () => {
    switch (steps[currentStep]?.key) {
      case 'basic':
        return (
          <Form
            form={basicForm}
            layout="vertical"
            requiredMark="optional"
          >
            <Form.Item
              name="name"
              label="Name"
              rules={[
                { required: true, message: 'Please enter a name' },
                { min: 2, message: 'Name must be at least 2 characters' },
                { max: 100, message: 'Name cannot exceed 100 characters' },
              ]}
            >
              <Input placeholder="Enter permission target name" />
            </Form.Item>

            <Form.Item
              name="description"
              label="Description"
              rules={[{ max: 500, message: 'Description cannot exceed 500 characters' }]}
            >
              <TextArea
                placeholder="Describe the purpose of this permission target"
                rows={4}
              />
            </Form.Item>
          </Form>
        );

      case 'repositories':
        return (
          <RepositoryPatternSelector
            value={patternValue}
            onChange={setPatternValue}
            repositories={repositories}
          />
        );

      case 'permissions':
        return (
          <div>
            <PermissionAssigner
              value={{ ...permissionValue, assignments: [] }}
              onChange={(val) =>
                setPermissionValue({
                  ...permissionValue,
                  actions: val.actions,
                })
              }
              users={[]}
              groups={[]}
            />
          </div>
        );

      case 'assignment':
        return (
          <PermissionAssigner
            value={permissionValue}
            onChange={setPermissionValue}
            users={users}
            groups={groups}
          />
        );

      default:
        return null;
    }
  };

  const modalTitle = isEditMode ? 'Edit Permission Target' : 'Create Permission Target';

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
          {!isFirstStep && (
            <Button
              icon={<ArrowLeftOutlined />}
              onClick={handlePrevious}
              disabled={isSubmitting}
            >
              Previous
            </Button>
          )}
        </div>

        <Space>
          <Button onClick={handleClose} disabled={isSubmitting}>
            Cancel
          </Button>
          {isLastStep ? (
            <Button
              type="primary"
              icon={<CheckOutlined />}
              onClick={handleSubmit}
              loading={isSubmitting}
            >
              {isEditMode ? 'Save Changes' : 'Create Permission Target'}
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

export default PermissionTargetWizard;
