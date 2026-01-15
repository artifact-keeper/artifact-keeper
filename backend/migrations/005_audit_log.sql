-- Create audit_log table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB,
    ip_address INET,
    correlation_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_audit_log_user ON audit_log(user_id, created_at);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id, created_at);
CREATE INDEX idx_audit_log_correlation ON audit_log(correlation_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
