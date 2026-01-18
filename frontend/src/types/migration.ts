// Migration types for Artifactory to Artifact Keeper migration

export type AuthType = 'api_token' | 'basic_auth';

export type MigrationJobStatus =
  | 'pending'
  | 'assessing'
  | 'ready'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type MigrationJobType = 'full' | 'incremental' | 'assessment';

export type MigrationItemType =
  | 'repository'
  | 'artifact'
  | 'user'
  | 'group'
  | 'permission'
  | 'property';

export type MigrationItemStatus =
  | 'pending'
  | 'in_progress'
  | 'completed'
  | 'failed'
  | 'skipped';

export type ConflictResolution = 'skip' | 'overwrite' | 'rename';

export interface SourceConnection {
  id: string;
  name: string;
  url: string;
  auth_type: AuthType;
  created_at: string;
  verified_at?: string;
}

export interface CreateConnectionRequest {
  name: string;
  url: string;
  auth_type: AuthType;
  credentials: ConnectionCredentials;
}

export interface ConnectionCredentials {
  token?: string;
  username?: string;
  password?: string;
}

export interface ConnectionTestResult {
  success: boolean;
  message: string;
  artifactory_version?: string;
  license_type?: string;
}

export interface SourceRepository {
  key: string;
  type: 'local' | 'remote' | 'virtual';
  package_type: string;
  url: string;
  description?: string;
}

export interface MigrationConfig {
  include_repos?: string[];
  exclude_repos?: string[];
  exclude_paths?: string[];
  include_users?: boolean;
  include_groups?: boolean;
  include_permissions?: boolean;
  include_cached_remote?: boolean;
  dry_run?: boolean;
  conflict_resolution?: ConflictResolution;
  concurrent_transfers?: number;
  throttle_delay_ms?: number;
  date_from?: string;
  date_to?: string;
}

export interface CreateMigrationRequest {
  source_connection_id: string;
  job_type?: MigrationJobType;
  config: MigrationConfig;
}

export interface MigrationJob {
  id: string;
  source_connection_id: string;
  status: MigrationJobStatus;
  job_type: MigrationJobType;
  config: MigrationConfig;
  total_items: number;
  completed_items: number;
  failed_items: number;
  skipped_items: number;
  total_bytes: number;
  transferred_bytes: number;
  progress_percent?: number;
  estimated_time_remaining?: number;
  started_at?: string;
  finished_at?: string;
  created_at: string;
  error_summary?: string;
}

export interface MigrationItem {
  id: string;
  job_id: string;
  item_type: MigrationItemType;
  source_path: string;
  target_path?: string;
  status: MigrationItemStatus;
  size_bytes: number;
  checksum_source?: string;
  checksum_target?: string;
  error_message?: string;
  retry_count: number;
  started_at?: string;
  completed_at?: string;
}

export interface ItemSummary {
  total: number;
  migrated: number;
  failed: number;
  skipped: number;
}

export interface ReportSummary {
  duration_seconds: number;
  repositories: ItemSummary;
  artifacts: ItemSummary;
  users: ItemSummary;
  groups: ItemSummary;
  permissions: ItemSummary;
  total_bytes_transferred: number;
}

export interface ReportWarning {
  code: string;
  message: string;
  item_path?: string;
}

export interface ReportError {
  code: string;
  message: string;
  item_path?: string;
  stack_trace?: string;
}

export interface MigrationReport {
  id: string;
  job_id: string;
  generated_at: string;
  summary: ReportSummary;
  warnings: ReportWarning[];
  errors: ReportError[];
  recommendations: string[];
}

export interface RepositoryAssessment {
  key: string;
  type: 'local' | 'remote' | 'virtual';
  package_type: string;
  artifact_count: number;
  total_size_bytes: number;
  compatibility: 'full' | 'partial' | 'unsupported';
  warnings: string[];
}

export interface AssessmentResult {
  job_id: string;
  status: string;
  repositories: RepositoryAssessment[];
  users_count: number;
  groups_count: number;
  permissions_count: number;
  total_artifacts: number;
  total_size_bytes: number;
  estimated_duration_seconds: number;
  warnings: string[];
  blockers: string[];
}

export interface MigrationProgressEvent {
  type: 'progress' | 'item_complete' | 'item_failed' | 'job_complete' | 'job_failed';
  job_id: string;
  completed_items?: number;
  failed_items?: number;
  skipped_items?: number;
  transferred_bytes?: number;
  current_item?: string;
  error?: string;
}
