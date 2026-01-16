import { useState } from 'react'
import { Form, Input, Button, Card, message, Alert } from 'antd'
import { LockOutlined } from '@ant-design/icons'
import { useAuth } from '../contexts'
import { useDocumentTitle } from '../hooks'

interface ChangePasswordValues {
  current_password: string
  new_password: string
  confirm_password: string
}

const ChangePassword = () => {
  useDocumentTitle('Change Password')
  const { changePassword, logout } = useAuth()
  const [loading, setLoading] = useState(false)
  const [form] = Form.useForm<ChangePasswordValues>()

  const onFinish = async (values: ChangePasswordValues) => {
    if (values.new_password !== values.confirm_password) {
      message.error('Passwords do not match')
      return
    }
    setLoading(true)
    try {
      await changePassword(values.current_password, values.new_password)
      message.success('Password changed successfully!')
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to change password.'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = async () => {
    await logout()
  }

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '100vh',
      background: '#f0f2f5'
    }}>
      <Card style={{ width: 450 }}>
        <h1 style={{ textAlign: 'center', marginBottom: 16 }}>Change Password Required</h1>
        <Alert
          message="Password Change Required"
          description="Your password was auto-generated or has been reset by an administrator. Please set a new password to continue."
          type="warning"
          showIcon
          style={{ marginBottom: 24 }}
        />
        <Form
          form={form}
          layout="vertical"
          onFinish={onFinish}
        >
          <Form.Item
            name="current_password"
            label="Current Password"
            rules={[{ required: true, message: 'Please enter your current password' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Enter current password" size="large" disabled={loading} />
          </Form.Item>
          <Form.Item
            name="new_password"
            label="New Password"
            rules={[
              { required: true, message: 'Please enter a new password' },
              { min: 8, message: 'Password must be at least 8 characters' },
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Enter new password" size="large" disabled={loading} />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label="Confirm New Password"
            dependencies={['new_password']}
            rules={[
              { required: true, message: 'Please confirm your new password' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) {
                    return Promise.resolve()
                  }
                  return Promise.reject(new Error('Passwords do not match'))
                },
              }),
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Confirm new password" size="large" disabled={loading} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block size="large" loading={loading}>
              Change Password
            </Button>
          </Form.Item>
          <Form.Item style={{ marginBottom: 0 }}>
            <Button type="link" block onClick={handleLogout} disabled={loading}>
              Logout instead
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  )
}

export default ChangePassword
