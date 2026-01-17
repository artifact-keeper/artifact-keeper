import React, { useState, useEffect, useCallback } from 'react';
import { Button, Input, Typography, Space, Card, Alert } from 'antd';
import { SafetyOutlined, ReloadOutlined } from '@ant-design/icons';
import { colors } from '../../../styles/tokens';

const { Title, Text, Paragraph } = Typography;

export interface MFAVerifyProps {
  onSubmit: (code: string) => void | Promise<void>;
  onCancel: () => void;
  onResend?: () => void | Promise<void>;
  loading?: boolean;
  error?: string;
  expirySeconds?: number;
  codeLength?: number;
  title?: string;
  description?: string;
}

export const MFAVerify: React.FC<MFAVerifyProps> = ({
  onSubmit,
  onCancel,
  onResend,
  loading = false,
  error,
  expirySeconds = 300,
  codeLength = 6,
  title = 'Two-Factor Authentication',
  description = 'Enter the verification code from your authenticator app.',
}) => {
  const [code, setCode] = useState('');
  const [timeRemaining, setTimeRemaining] = useState(expirySeconds);
  const [isResending, setIsResending] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (timeRemaining <= 0) return;

    const timer = setInterval(() => {
      setTimeRemaining((prev) => Math.max(0, prev - 1));
    }, 1000);

    return () => clearInterval(timer);
  }, [timeRemaining]);

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const handleCodeChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const value = e.target.value.replace(/\D/g, '').slice(0, codeLength);
      setCode(value);
    },
    [codeLength]
  );

  const handleSubmit = useCallback(async () => {
    if (code.length !== codeLength || loading || isSubmitting) return;

    setIsSubmitting(true);
    try {
      await onSubmit(code);
    } finally {
      setIsSubmitting(false);
    }
  }, [code, codeLength, loading, isSubmitting, onSubmit]);

  const handleResend = useCallback(async () => {
    if (!onResend || isResending) return;

    setIsResending(true);
    try {
      await onResend();
      setTimeRemaining(expirySeconds);
      setCode('');
    } finally {
      setIsResending(false);
    }
  }, [onResend, isResending, expirySeconds]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        handleSubmit();
      }
    },
    [handleSubmit]
  );

  const isExpired = timeRemaining <= 0;
  const isValid = code.length === codeLength;
  const isLoading = loading || isSubmitting;

  return (
    <Card
      style={{
        maxWidth: 400,
        margin: '0 auto',
        textAlign: 'center',
      }}
    >
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <div>
          <SafetyOutlined
            style={{
              fontSize: 48,
              color: colors.primary,
              marginBottom: 16,
            }}
          />
          <Title level={4} style={{ margin: 0 }}>
            {title}
          </Title>
          <Paragraph type="secondary" style={{ marginTop: 8 }}>
            {description}
          </Paragraph>
        </div>

        {error && (
          <Alert
            type="error"
            message={error}
            showIcon
            style={{ textAlign: 'left' }}
          />
        )}

        {isExpired ? (
          <Alert
            type="warning"
            message="Code expired"
            description="Your verification code has expired. Please request a new code."
            showIcon
            style={{ textAlign: 'left' }}
          />
        ) : (
          <div>
            <Input
              value={code}
              onChange={handleCodeChange}
              onKeyDown={handleKeyDown}
              placeholder={'0'.repeat(codeLength)}
              maxLength={codeLength}
              disabled={isLoading || isExpired}
              status={error ? 'error' : undefined}
              autoFocus
              style={{
                textAlign: 'center',
                fontSize: 24,
                letterSpacing: 8,
                fontFamily: 'monospace',
                height: 56,
              }}
            />
            <Text
              type="secondary"
              style={{
                display: 'block',
                marginTop: 8,
                color: timeRemaining < 60 ? colors.warning : undefined,
              }}
            >
              Code expires in {formatTime(timeRemaining)}
            </Text>
          </div>
        )}

        <Space orientation="vertical" size="small" style={{ width: '100%' }}>
          <Button
            type="primary"
            onClick={handleSubmit}
            loading={isLoading}
            disabled={!isValid || isExpired}
            block
            size="large"
          >
            Verify
          </Button>

          {onResend && (
            <Button
              type="link"
              onClick={handleResend}
              loading={isResending}
              disabled={isLoading}
              icon={<ReloadOutlined />}
            >
              Resend code
            </Button>
          )}

          <Button type="text" onClick={onCancel} disabled={isLoading}>
            Cancel
          </Button>
        </Space>
      </Space>
    </Card>
  );
};

export default MFAVerify;
