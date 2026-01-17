import React, { useState, useCallback } from 'react';
import { Button, Input, Typography, Space, Card, Alert, QRCode } from 'antd';
import { SafetyOutlined, CopyOutlined, CheckOutlined } from '@ant-design/icons';
import { colors } from '../../../styles/tokens';

const { Title, Text, Paragraph } = Typography;

export interface MFAEnrollProps {
  secretKey: string;
  qrCodeUrl: string;
  onVerify: (code: string) => void | Promise<void>;
  onCancel: () => void;
  loading?: boolean;
  error?: string;
  codeLength?: number;
  issuer?: string;
  accountName?: string;
}

export const MFAEnroll: React.FC<MFAEnrollProps> = ({
  secretKey,
  qrCodeUrl,
  onVerify,
  onCancel,
  loading = false,
  error,
  codeLength = 6,
  issuer = 'Artifact Keeper',
  accountName,
}) => {
  const [code, setCode] = useState('');
  const [copied, setCopied] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showManualEntry, setShowManualEntry] = useState(false);

  const handleCodeChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const value = e.target.value.replace(/\D/g, '').slice(0, codeLength);
      setCode(value);
    },
    [codeLength]
  );

  const handleVerify = useCallback(async () => {
    if (code.length !== codeLength || loading || isSubmitting) return;

    setIsSubmitting(true);
    try {
      await onVerify(code);
    } finally {
      setIsSubmitting(false);
    }
  }, [code, codeLength, loading, isSubmitting, onVerify]);

  const handleCopySecret = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(secretKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      console.error('Failed to copy secret key');
    }
  }, [secretKey]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        handleVerify();
      }
    },
    [handleVerify]
  );

  const formatSecretKey = (key: string): string => {
    return key.replace(/(.{4})/g, '$1 ').trim();
  };

  const isValid = code.length === codeLength;
  const isLoading = loading || isSubmitting;

  return (
    <Card
      style={{
        maxWidth: 480,
        margin: '0 auto',
      }}
    >
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <div style={{ textAlign: 'center' }}>
          <SafetyOutlined
            style={{
              fontSize: 48,
              color: colors.primary,
              marginBottom: 16,
            }}
          />
          <Title level={4} style={{ margin: 0 }}>
            Set Up Two-Factor Authentication
          </Title>
          <Paragraph type="secondary" style={{ marginTop: 8 }}>
            Scan the QR code below with your authenticator app to enable two-factor authentication.
          </Paragraph>
        </div>

        {error && (
          <Alert
            type="error"
            message={error}
            showIcon
          />
        )}

        <div style={{ textAlign: 'center' }}>
          <div
            style={{
              display: 'inline-block',
              padding: 16,
              backgroundColor: '#ffffff',
              borderRadius: 8,
              border: `1px solid ${colors.border}`,
            }}
          >
            <QRCode
              value={qrCodeUrl}
              size={200}
              errorLevel="M"
              style={{ display: 'block' }}
            />
          </div>
        </div>

        <div>
          <Button
            type="link"
            onClick={() => setShowManualEntry(!showManualEntry)}
            style={{ padding: 0 }}
          >
            {showManualEntry ? 'Hide manual entry key' : "Can't scan? Enter key manually"}
          </Button>

          {showManualEntry && (
            <Card
              size="small"
              style={{
                marginTop: 12,
                backgroundColor: colors.bgLayout,
              }}
            >
              <Space orientation="vertical" size="small" style={{ width: '100%' }}>
                {accountName && (
                  <div>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      Account
                    </Text>
                    <Text
                      strong
                      style={{ display: 'block' }}
                    >
                      {issuer}: {accountName}
                    </Text>
                  </div>
                )}
                <div>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    Secret Key
                  </Text>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Text
                      code
                      style={{
                        fontSize: 14,
                        fontFamily: 'monospace',
                        letterSpacing: 2,
                        wordBreak: 'break-all',
                      }}
                    >
                      {formatSecretKey(secretKey)}
                    </Text>
                    <Button
                      type="text"
                      size="small"
                      icon={copied ? <CheckOutlined style={{ color: colors.success }} /> : <CopyOutlined />}
                      onClick={handleCopySecret}
                    />
                  </div>
                </div>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  Time based, 6 digit code
                </Text>
              </Space>
            </Card>
          )}
        </div>

        <div>
          <Text strong style={{ display: 'block', marginBottom: 8 }}>
            Enter the 6-digit code from your app
          </Text>
          <Input
            value={code}
            onChange={handleCodeChange}
            onKeyDown={handleKeyDown}
            placeholder={'0'.repeat(codeLength)}
            maxLength={codeLength}
            disabled={isLoading}
            status={error ? 'error' : undefined}
            style={{
              textAlign: 'center',
              fontSize: 24,
              letterSpacing: 8,
              fontFamily: 'monospace',
              height: 56,
            }}
          />
        </div>

        <Space orientation="vertical" size="small" style={{ width: '100%' }}>
          <Button
            type="primary"
            onClick={handleVerify}
            loading={isLoading}
            disabled={!isValid}
            block
            size="large"
          >
            Enable Two-Factor Authentication
          </Button>

          <Button type="text" onClick={onCancel} disabled={isLoading} block>
            Cancel
          </Button>
        </Space>

        <Alert
          type="info"
          message="Recommended authenticator apps"
          description={
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              <li>Google Authenticator</li>
              <li>Microsoft Authenticator</li>
              <li>Authy</li>
              <li>1Password</li>
            </ul>
          }
          showIcon
        />
      </Space>
    </Card>
  );
};

export default MFAEnroll;
