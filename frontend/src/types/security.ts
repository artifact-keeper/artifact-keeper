// Security scanning types

export interface DashboardSummary {
  repos_with_scanning: number;
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  policy_violations_blocked: number;
  repos_grade_a: number;
  repos_grade_f: number;
}

export interface RepoSecurityScore {
  id: string;
  repository_id: string;
  score: number;
  grade: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  acknowledged_count: number;
  last_scan_at: string | null;
  calculated_at: string;
}

export interface ScanResult {
  id: string;
  artifact_id: string;
  repository_id: string;
  scan_type: string;
  status: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  scanner_version: string | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface ScanFinding {
  id: string;
  scan_result_id: string;
  artifact_id: string;
  severity: string;
  title: string;
  description: string | null;
  cve_id: string | null;
  affected_component: string | null;
  affected_version: string | null;
  fixed_version: string | null;
  source: string | null;
  source_url: string | null;
  is_acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_reason: string | null;
  acknowledged_at: string | null;
  created_at: string;
}

export interface ScanPolicy {
  id: string;
  name: string;
  repository_id: string | null;
  max_severity: string;
  block_unscanned: boolean;
  block_on_fail: boolean;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ScanConfig {
  id: string;
  repository_id: string;
  scan_enabled: boolean;
  scan_on_upload: boolean;
  scan_on_proxy: boolean;
  block_on_policy_violation: boolean;
  severity_threshold: string;
  created_at: string;
  updated_at: string;
}

export interface RepoSecurityInfo {
  config: ScanConfig | null;
  score: RepoSecurityScore | null;
}

export interface CreatePolicyRequest {
  name: string;
  repository_id?: string | null;
  max_severity: string;
  block_unscanned: boolean;
  block_on_fail: boolean;
}

export interface UpdatePolicyRequest {
  name: string;
  max_severity: string;
  block_unscanned: boolean;
  block_on_fail: boolean;
  is_enabled: boolean;
}

export interface TriggerScanRequest {
  artifact_id?: string;
  repository_id?: string;
}

export interface TriggerScanResponse {
  message: string;
  artifacts_queued: number;
}

export interface UpsertScanConfigRequest {
  scan_enabled: boolean;
  scan_on_upload: boolean;
  scan_on_proxy: boolean;
  block_on_policy_violation: boolean;
  severity_threshold: string;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type GradeLevel = 'A' | 'B' | 'C' | 'D' | 'F';
