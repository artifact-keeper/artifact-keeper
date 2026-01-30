import { useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Typography,
  Space,
  Modal,
  Form,
  Input,
  Select,
  Switch,
  Popconfirm,
  message,
} from 'antd';
import { PlusOutlined, NodeIndexOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { securityApi } from '../api';
import type { ScanPolicy, CreatePolicyRequest, UpdatePolicyRequest } from '../types/security';

const { Title } = Typography;

export default function SecurityPolicies() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editPolicy, setEditPolicy] = useState<ScanPolicy | null>(null);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();

  const { data: policies, isLoading } = useQuery({
    queryKey: ['security', 'policies'],
    queryFn: securityApi.listPolicies,
  });

  const createMutation = useMutation({
    mutationFn: (req: CreatePolicyRequest) => securityApi.createPolicy(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security', 'policies'] });
      setCreateOpen(false);
      createForm.resetFields();
      message.success('Policy created');
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, req }: { id: string; req: UpdatePolicyRequest }) =>
      securityApi.updatePolicy(id, req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security', 'policies'] });
      setEditPolicy(null);
      message.success('Policy updated');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: securityApi.deletePolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security', 'policies'] });
      message.success('Policy deleted');
    },
  });

  if (!user?.is_admin) {
    return (
      <Card>
        <p>You must be an administrator to manage security policies.</p>
      </Card>
    );
  }

  const columns = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'Scope',
      dataIndex: 'repository_id',
      key: 'scope',
      render: (repoId: string | null) =>
        repoId ? (
          <Tag>Repo: {repoId.slice(0, 8)}...</Tag>
        ) : (
          <Tag color="blue">Global</Tag>
        ),
    },
    {
      title: 'Max Severity',
      dataIndex: 'max_severity',
      key: 'max_severity',
      render: (sev: string) => {
        const colors: Record<string, string> = {
          critical: 'red',
          high: 'orange',
          medium: 'gold',
          low: 'blue',
        };
        return <Tag color={colors[sev] || 'default'}>{sev}</Tag>;
      },
    },
    {
      title: 'Block Unscanned',
      dataIndex: 'block_unscanned',
      key: 'block_unscanned',
      render: (val: boolean) =>
        val ? <Tag color="red">Yes</Tag> : <Tag>No</Tag>,
    },
    {
      title: 'Block on Fail',
      dataIndex: 'block_on_fail',
      key: 'block_on_fail',
      render: (val: boolean) =>
        val ? <Tag color="red">Yes</Tag> : <Tag>No</Tag>,
    },
    {
      title: 'Enabled',
      dataIndex: 'is_enabled',
      key: 'is_enabled',
      render: (val: boolean) =>
        val ? <Tag color="green">Yes</Tag> : <Tag color="default">No</Tag>,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: unknown, record: ScanPolicy) => (
        <Space>
          <Button
            size="small"
            onClick={() => {
              setEditPolicy(record);
              editForm.setFieldsValue({
                name: record.name,
                max_severity: record.max_severity,
                block_unscanned: record.block_unscanned,
                block_on_fail: record.block_on_fail,
                is_enabled: record.is_enabled,
              });
            }}
          >
            Edit
          </Button>
          <Popconfirm
            title="Delete this policy?"
            onConfirm={() => deleteMutation.mutate(record.id)}
          >
            <Button size="small" danger loading={deleteMutation.isPending}>
              Delete
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const policyForm = (
    <>
      <Form.Item name="name" label="Policy Name" rules={[{ required: true }]}>
        <Input placeholder="e.g., Block Critical CVEs" />
      </Form.Item>
      <Form.Item
        name="max_severity"
        label="Max Severity"
        rules={[{ required: true }]}
        extra="Block artifacts with findings at or above this severity"
      >
        <Select
          options={[
            { label: 'Critical', value: 'critical' },
            { label: 'High', value: 'high' },
            { label: 'Medium', value: 'medium' },
            { label: 'Low', value: 'low' },
          ]}
        />
      </Form.Item>
      <Form.Item
        name="block_unscanned"
        label="Block Unscanned"
        valuePropName="checked"
        extra="Block downloads for artifacts that have not been scanned"
      >
        <Switch />
      </Form.Item>
      <Form.Item
        name="block_on_fail"
        label="Block on Scan Failure"
        valuePropName="checked"
        extra="Block downloads if the latest scan failed"
      >
        <Switch />
      </Form.Item>
    </>
  );

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={3} style={{ margin: 0 }}>
          <NodeIndexOutlined /> Security Policies
        </Title>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => setCreateOpen(true)}
        >
          Create Policy
        </Button>
      </div>

      <Card>
        <Table
          dataSource={policies || []}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={false}
        />
      </Card>

      {/* Create Modal */}
      <Modal
        title="Create Security Policy"
        open={createOpen}
        onCancel={() => {
          setCreateOpen(false);
          createForm.resetFields();
        }}
        onOk={() => createForm.submit()}
        confirmLoading={createMutation.isPending}
      >
        <Form
          form={createForm}
          layout="vertical"
          initialValues={{
            block_unscanned: false,
            block_on_fail: false,
            max_severity: 'high',
          }}
          onFinish={(values) => {
            createMutation.mutate({
              name: values.name,
              max_severity: values.max_severity,
              block_unscanned: values.block_unscanned || false,
              block_on_fail: values.block_on_fail || false,
              repository_id: values.repository_id || null,
            });
          }}
        >
          {policyForm}
          <Form.Item
            name="repository_id"
            label="Repository ID (optional)"
            extra="Leave blank for a global policy"
          >
            <Input placeholder="UUID of specific repository" />
          </Form.Item>
        </Form>
      </Modal>

      {/* Edit Modal */}
      <Modal
        title="Edit Security Policy"
        open={!!editPolicy}
        onCancel={() => setEditPolicy(null)}
        onOk={() => editForm.submit()}
        confirmLoading={updateMutation.isPending}
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={(values) => {
            if (editPolicy) {
              updateMutation.mutate({
                id: editPolicy.id,
                req: {
                  name: values.name,
                  max_severity: values.max_severity,
                  block_unscanned: values.block_unscanned || false,
                  block_on_fail: values.block_on_fail || false,
                  is_enabled: values.is_enabled ?? true,
                },
              });
            }
          }}
        >
          {policyForm}
          <Form.Item
            name="is_enabled"
            label="Enabled"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
