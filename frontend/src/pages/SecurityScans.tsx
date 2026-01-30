import { useState } from 'react';
import { Card, Table, Tag, Select, Button, Typography, Space, Modal, Form, Input } from 'antd';
import { ScanOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { securityApi } from '../api';
import type { ScanResult } from '../types/security';

const { Title } = Typography;

const statusColors: Record<string, string> = {
  completed: 'green',
  running: 'blue',
  pending: 'default',
  failed: 'red',
};

const severityColors: Record<string, string> = {
  critical: '#f5222d',
  high: '#fa8c16',
  medium: '#faad14',
  low: '#1890ff',
  info: '#d9d9d9',
};

export default function SecurityScans() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<string | undefined>(undefined);
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [form] = Form.useForm();
  const perPage = 20;

  const { data, isLoading } = useQuery({
    queryKey: ['security', 'scans', page, statusFilter],
    queryFn: () =>
      securityApi.listScans({
        page,
        per_page: perPage,
        status: statusFilter,
      }),
  });

  const triggerScanMutation = useMutation({
    mutationFn: securityApi.triggerScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security', 'scans'] });
      setScanModalOpen(false);
      form.resetFields();
    },
  });

  if (!user?.is_admin) {
    return (
      <Card>
        <p>You must be an administrator to view scan results.</p>
      </Card>
    );
  }

  const columns = [
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={statusColors[status] || 'default'}>{status.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'scan_type',
      key: 'scan_type',
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Findings',
      dataIndex: 'findings_count',
      key: 'findings_count',
      render: (_: number, record: ScanResult) => (
        <Space size={4}>
          {record.critical_count > 0 && (
            <Tag color={severityColors.critical}>{record.critical_count}C</Tag>
          )}
          {record.high_count > 0 && (
            <Tag color={severityColors.high}>{record.high_count}H</Tag>
          )}
          {record.medium_count > 0 && (
            <Tag color={severityColors.medium}>{record.medium_count}M</Tag>
          )}
          {record.low_count > 0 && (
            <Tag color={severityColors.low}>{record.low_count}L</Tag>
          )}
          {record.findings_count === 0 && <Tag color="green">Clean</Tag>}
        </Space>
      ),
    },
    {
      title: 'Artifact',
      dataIndex: 'artifact_id',
      key: 'artifact_id',
      render: (id: string) => <code>{id.slice(0, 8)}...</code>,
    },
    {
      title: 'Started',
      dataIndex: 'started_at',
      key: 'started_at',
      render: (val: string | null) =>
        val ? new Date(val).toLocaleString() : '-',
    },
    {
      title: 'Completed',
      dataIndex: 'completed_at',
      key: 'completed_at',
      render: (val: string | null) =>
        val ? new Date(val).toLocaleString() : '-',
    },
    {
      title: 'Error',
      dataIndex: 'error_message',
      key: 'error_message',
      render: (msg: string | null) =>
        msg ? <Tag color="red">{msg.slice(0, 40)}...</Tag> : null,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: unknown, record: ScanResult) => (
        <Link to={`/security/scans/${record.id}`}>View Findings</Link>
      ),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={3} style={{ margin: 0 }}>
          <ScanOutlined /> Security Scans
        </Title>
        <Space>
          <Select
            allowClear
            placeholder="Filter by status"
            style={{ width: 160 }}
            value={statusFilter}
            onChange={(val) => {
              setStatusFilter(val);
              setPage(1);
            }}
            options={[
              { label: 'Completed', value: 'completed' },
              { label: 'Running', value: 'running' },
              { label: 'Pending', value: 'pending' },
              { label: 'Failed', value: 'failed' },
            ]}
          />
          <Button
            icon={<ReloadOutlined />}
            onClick={() =>
              queryClient.invalidateQueries({ queryKey: ['security', 'scans'] })
            }
          >
            Refresh
          </Button>
          <Button
            type="primary"
            icon={<ScanOutlined />}
            onClick={() => setScanModalOpen(true)}
          >
            Trigger Scan
          </Button>
        </Space>
      </div>

      <Card>
        <Table
          dataSource={data?.items || []}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            current: page,
            pageSize: perPage,
            total: data?.total || 0,
            onChange: (p) => setPage(p),
          }}
        />
      </Card>

      <Modal
        title="Trigger Security Scan"
        open={scanModalOpen}
        onCancel={() => setScanModalOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={triggerScanMutation.isPending}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) => {
            triggerScanMutation.mutate({
              artifact_id: values.artifact_id || undefined,
              repository_id: values.repository_id || undefined,
            });
          }}
        >
          <Form.Item
            name="repository_id"
            label="Repository ID"
            extra="Scan all artifacts in a repository"
          >
            <Input placeholder="Enter repository UUID" />
          </Form.Item>
          <Form.Item
            name="artifact_id"
            label="Artifact ID"
            extra="Or scan a single artifact"
          >
            <Input placeholder="Enter artifact UUID" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
