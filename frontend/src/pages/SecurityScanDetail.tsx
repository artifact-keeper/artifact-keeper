import { useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Typography,
  Space,
  Descriptions,
  Modal,
  Input,
  Popconfirm,
  message,
  Spin,
} from 'antd';
import { ArrowLeftOutlined, CheckCircleOutlined, UndoOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { securityApi } from '../api';
import type { ScanFinding } from '../types/security';

const { Title, Text } = Typography;

const severityColors: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
  info: 'default',
};

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export default function SecurityScanDetail() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [ackModalOpen, setAckModalOpen] = useState(false);
  const [ackFindingId, setAckFindingId] = useState<string | null>(null);
  const [ackReason, setAckReason] = useState('');
  const perPage = 50;

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['security', 'scan', id],
    queryFn: () => securityApi.getScan(id!),
    enabled: !!id,
  });

  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['security', 'findings', id, page],
    queryFn: () => securityApi.listFindings(id!, { page, per_page: perPage }),
    enabled: !!id,
  });

  const acknowledgeMutation = useMutation({
    mutationFn: ({ findingId, reason }: { findingId: string; reason: string }) =>
      securityApi.acknowledgeFinding(findingId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security', 'findings', id] });
      setAckModalOpen(false);
      setAckReason('');
      setAckFindingId(null);
      message.success('Finding acknowledged');
    },
  });

  const revokeMutation = useMutation({
    mutationFn: securityApi.revokeAcknowledgment,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security', 'findings', id] });
      message.success('Acknowledgment revoked');
    },
  });

  if (!user?.is_admin) {
    return (
      <Card>
        <p>You must be an administrator to view scan details.</p>
      </Card>
    );
  }

  if (scanLoading) {
    return <Spin size="large" />;
  }

  const columns = [
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity: string) => (
        <Tag color={severityColors[severity] || 'default'}>
          {severity.toUpperCase()}
        </Tag>
      ),
      sorter: (a: ScanFinding, b: ScanFinding) =>
        (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5),
    },
    {
      title: 'Title',
      dataIndex: 'title',
      key: 'title',
      width: '30%',
    },
    {
      title: 'CVE',
      dataIndex: 'cve_id',
      key: 'cve_id',
      render: (cve: string | null) =>
        cve ? (
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            {cve}
          </a>
        ) : (
          '-'
        ),
    },
    {
      title: 'Component',
      dataIndex: 'affected_component',
      key: 'affected_component',
      render: (comp: string | null) => comp || '-',
    },
    {
      title: 'Version',
      key: 'versions',
      render: (_: unknown, record: ScanFinding) => (
        <Space direction="vertical" size={0}>
          {record.affected_version && (
            <Text type="danger">{record.affected_version}</Text>
          )}
          {record.fixed_version && (
            <Text type="success">Fix: {record.fixed_version}</Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Source',
      dataIndex: 'source',
      key: 'source',
      render: (source: string | null, record: ScanFinding) =>
        source && record.source_url ? (
          <a href={record.source_url} target="_blank" rel="noopener noreferrer">
            {source}
          </a>
        ) : (
          source || '-'
        ),
    },
    {
      title: 'Status',
      key: 'status',
      render: (_: unknown, record: ScanFinding) =>
        record.is_acknowledged ? (
          <Tag color="cyan" icon={<CheckCircleOutlined />}>
            Acknowledged
          </Tag>
        ) : (
          <Tag color="warning">Open</Tag>
        ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: unknown, record: ScanFinding) =>
        record.is_acknowledged ? (
          <Popconfirm
            title="Revoke acknowledgment?"
            description="This finding will count against the security score again."
            onConfirm={() => revokeMutation.mutate(record.id)}
          >
            <Button
              size="small"
              icon={<UndoOutlined />}
              loading={revokeMutation.isPending}
            >
              Revoke
            </Button>
          </Popconfirm>
        ) : (
          <Button
            size="small"
            type="primary"
            icon={<CheckCircleOutlined />}
            onClick={() => {
              setAckFindingId(record.id);
              setAckModalOpen(true);
            }}
          >
            Acknowledge
          </Button>
        ),
    },
  ];

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Link to="/security/scans">
          <Button icon={<ArrowLeftOutlined />}>Back to Scans</Button>
        </Link>
      </Space>

      <Title level={3}>Scan Detail</Title>

      {scan && (
        <Card style={{ marginBottom: 24 }}>
          <Descriptions column={{ xs: 1, sm: 2, md: 3 }}>
            <Descriptions.Item label="Scan ID">
              <code>{scan.id}</code>
            </Descriptions.Item>
            <Descriptions.Item label="Status">
              <Tag color={scan.status === 'completed' ? 'green' : scan.status === 'failed' ? 'red' : 'blue'}>
                {scan.status.toUpperCase()}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Type">
              <Tag>{scan.scan_type}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Findings">
              {scan.findings_count}
            </Descriptions.Item>
            <Descriptions.Item label="Critical">
              <Tag color={scan.critical_count > 0 ? 'red' : 'green'}>
                {scan.critical_count}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="High">
              <Tag color={scan.high_count > 0 ? 'orange' : 'green'}>
                {scan.high_count}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Started">
              {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="Completed">
              {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '-'}
            </Descriptions.Item>
            {scan.error_message && (
              <Descriptions.Item label="Error" span={3}>
                <Text type="danger">{scan.error_message}</Text>
              </Descriptions.Item>
            )}
          </Descriptions>
        </Card>
      )}

      <Card title="Findings">
        <Table
          dataSource={findingsData?.items || []}
          columns={columns}
          rowKey="id"
          loading={findingsLoading}
          pagination={{
            current: page,
            pageSize: perPage,
            total: findingsData?.total || 0,
            onChange: (p) => setPage(p),
          }}
          expandable={{
            expandedRowRender: (record: ScanFinding) => (
              <div style={{ padding: 8 }}>
                {record.description && (
                  <p>
                    <strong>Description:</strong> {record.description}
                  </p>
                )}
                {record.is_acknowledged && record.acknowledged_reason && (
                  <p>
                    <strong>Acknowledgment Reason:</strong>{' '}
                    {record.acknowledged_reason}
                  </p>
                )}
              </div>
            ),
            rowExpandable: (record: ScanFinding) =>
              !!(record.description || record.acknowledged_reason),
          }}
        />
      </Card>

      <Modal
        title="Acknowledge Finding"
        open={ackModalOpen}
        onCancel={() => {
          setAckModalOpen(false);
          setAckReason('');
          setAckFindingId(null);
        }}
        onOk={() => {
          if (ackFindingId && ackReason.trim()) {
            acknowledgeMutation.mutate({
              findingId: ackFindingId,
              reason: ackReason.trim(),
            });
          }
        }}
        okButtonProps={{
          disabled: !ackReason.trim(),
          loading: acknowledgeMutation.isPending,
        }}
      >
        <p>
          Acknowledging a finding marks it as an accepted risk. It will no longer
          count against the repository security score.
        </p>
        <Input.TextArea
          rows={3}
          placeholder="Reason for acknowledging (e.g., 'Required for CentOS 7 compatibility')"
          value={ackReason}
          onChange={(e) => setAckReason(e.target.value)}
        />
      </Modal>
    </div>
  );
}
