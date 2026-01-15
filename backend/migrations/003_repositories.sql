-- Create repository_format enum
CREATE TYPE repository_format AS ENUM (
    'maven', 'gradle', 'npm', 'pypi', 'nuget', 'go', 'rubygems',
    'docker', 'helm', 'rpm', 'debian', 'conan', 'cargo', 'generic'
);

-- Create repository_type enum
CREATE TYPE repository_type AS ENUM ('local', 'remote', 'virtual');

-- Create repositories table
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    format repository_format NOT NULL,
    repo_type repository_type NOT NULL,
    storage_backend VARCHAR(50) NOT NULL DEFAULT 'filesystem',
    storage_path VARCHAR(1024) NOT NULL,
    upstream_url VARCHAR(2048),
    is_public BOOLEAN NOT NULL DEFAULT false,
    quota_bytes BIGINT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT check_upstream_url CHECK (
        (repo_type = 'remote' AND upstream_url IS NOT NULL) OR
        (repo_type != 'remote')
    )
);

-- Create virtual_repo_members table
CREATE TABLE virtual_repo_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    virtual_repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    member_repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(virtual_repo_id, member_repo_id)
);

-- Add foreign key for permission_grants
ALTER TABLE permission_grants
ADD CONSTRAINT fk_permission_grants_repository
FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

-- Add foreign key for role_assignments
ALTER TABLE role_assignments
ADD CONSTRAINT fk_role_assignments_repository
FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;
