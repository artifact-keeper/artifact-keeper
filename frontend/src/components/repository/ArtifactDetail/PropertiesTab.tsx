import React, { useState } from 'react';
import {
  Table,
  Button,
  Space,
  Input,
  Form,
  Popconfirm,
  Typography,
  Empty,
} from 'antd';
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  SaveOutlined,
  CloseOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { colors } from '../../../styles/tokens';

const { Text } = Typography;

export interface ArtifactProperty {
  key: string;
  value: string;
}

export interface PropertiesTabProps {
  properties: ArtifactProperty[];
  onAdd?: (key: string, value: string) => void;
  onEdit?: (key: string, value: string) => void;
  onDelete?: (key: string) => void;
  canEdit?: boolean;
}

interface EditableCellProps {
  editing: boolean;
  dataIndex: string;
  title: string;
  record: ArtifactProperty;
  children: React.ReactNode;
}

const EditableCell: React.FC<EditableCellProps> = ({
  editing,
  dataIndex,
  title,
  children,
  ...restProps
}) => {
  return (
    <td {...restProps}>
      {editing ? (
        <Form.Item
          name={dataIndex}
          style={{ margin: 0 }}
          rules={[{ required: true, message: `${title} is required` }]}
        >
          <Input size="small" />
        </Form.Item>
      ) : (
        children
      )}
    </td>
  );
};

export const PropertiesTab: React.FC<PropertiesTabProps> = ({
  properties,
  onAdd,
  onEdit,
  onDelete,
  canEdit = false,
}) => {
  const [form] = Form.useForm();
  const [editingKey, setEditingKey] = useState<string>('');
  const [isAdding, setIsAdding] = useState(false);
  const [newProperty, setNewProperty] = useState<ArtifactProperty>({
    key: '',
    value: '',
  });

  const isEditing = (record: ArtifactProperty) => record.key === editingKey;

  const edit = (record: ArtifactProperty) => {
    form.setFieldsValue({ key: record.key, value: record.value });
    setEditingKey(record.key);
  };

  const cancel = () => {
    setEditingKey('');
  };

  const save = async (key: string) => {
    try {
      const row = await form.validateFields();
      if (onEdit) {
        onEdit(key, row.value);
      }
      setEditingKey('');
    } catch (errInfo) {
      console.error('Validate Failed:', errInfo);
    }
  };

  const handleAdd = () => {
    if (newProperty.key && newProperty.value && onAdd) {
      onAdd(newProperty.key, newProperty.value);
      setNewProperty({ key: '', value: '' });
      setIsAdding(false);
    }
  };

  const handleDelete = (key: string) => {
    if (onDelete) {
      onDelete(key);
    }
  };

  const columns: ColumnsType<ArtifactProperty> = [
    {
      title: 'Key',
      dataIndex: 'key',
      key: 'key',
      width: '35%',
      render: (text: string) => (
        <Text style={{ fontFamily: 'monospace' }}>{text}</Text>
      ),
    },
    {
      title: 'Value',
      dataIndex: 'value',
      key: 'value',
      width: canEdit ? '45%' : '65%',
      onCell: (record) => ({
        record,
        dataIndex: 'value',
        title: 'Value',
        editing: isEditing(record),
      }),
      render: (text: string) => (
        <Text style={{ wordBreak: 'break-all' }}>{text}</Text>
      ),
    },
  ];

  if (canEdit) {
    columns.push({
      title: 'Actions',
      key: 'actions',
      width: '20%',
      render: (_: unknown, record: ArtifactProperty) => {
        const editable = isEditing(record);
        return editable ? (
          <Space size="small">
            <Button
              type="link"
              size="small"
              icon={<SaveOutlined />}
              onClick={() => save(record.key)}
            >
              Save
            </Button>
            <Button
              type="link"
              size="small"
              icon={<CloseOutlined />}
              onClick={cancel}
            >
              Cancel
            </Button>
          </Space>
        ) : (
          <Space size="small">
            <Button
              type="link"
              size="small"
              icon={<EditOutlined />}
              disabled={editingKey !== ''}
              onClick={() => edit(record)}
            >
              Edit
            </Button>
            <Popconfirm
              title="Delete this property?"
              description="This action cannot be undone."
              onConfirm={() => handleDelete(record.key)}
              okText="Delete"
              cancelText="Cancel"
              okButtonProps={{ danger: true }}
            >
              <Button
                type="link"
                size="small"
                danger
                icon={<DeleteOutlined />}
                disabled={editingKey !== ''}
              >
                Delete
              </Button>
            </Popconfirm>
          </Space>
        );
      },
    });
  }

  return (
    <div>
      {canEdit && (
        <div style={{ marginBottom: 16 }}>
          {isAdding ? (
            <Space style={{ width: '100%' }} orientation="vertical" size="small">
              <Space>
                <Input
                  placeholder="Key"
                  value={newProperty.key}
                  onChange={(e) =>
                    setNewProperty({ ...newProperty, key: e.target.value })
                  }
                  style={{ width: 200 }}
                />
                <Input
                  placeholder="Value"
                  value={newProperty.value}
                  onChange={(e) =>
                    setNewProperty({ ...newProperty, value: e.target.value })
                  }
                  style={{ width: 300 }}
                />
                <Button
                  type="primary"
                  icon={<SaveOutlined />}
                  onClick={handleAdd}
                  disabled={!newProperty.key || !newProperty.value}
                >
                  Add
                </Button>
                <Button
                  icon={<CloseOutlined />}
                  onClick={() => {
                    setIsAdding(false);
                    setNewProperty({ key: '', value: '' });
                  }}
                >
                  Cancel
                </Button>
              </Space>
            </Space>
          ) : (
            <Button
              type="dashed"
              icon={<PlusOutlined />}
              onClick={() => setIsAdding(true)}
            >
              Add Property
            </Button>
          )}
        </div>
      )}

      <Form form={form} component={false}>
        <Table
          components={{
            body: {
              cell: EditableCell,
            },
          }}
          dataSource={properties}
          columns={columns}
          rowKey="key"
          pagination={false}
          size="small"
          bordered
          locale={{
            emptyText: (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="No properties defined"
              />
            ),
          }}
        />
      </Form>
    </div>
  );
};

export default PropertiesTab;
