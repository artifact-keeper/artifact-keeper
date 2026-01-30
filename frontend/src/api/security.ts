import apiClient from './client';
import type {
  DashboardSummary,
  RepoSecurityScore,
  ScanResult,
  ScanFinding,
  ScanPolicy,
  ScanConfig,
  RepoSecurityInfo,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  TriggerScanRequest,
  TriggerScanResponse,
  UpsertScanConfigRequest,
} from '../types/security';

export interface ScanListResponse {
  items: ScanResult[];
  total: number;
}

export interface FindingListResponse {
  items: ScanFinding[];
  total: number;
}

export interface ListScansParams {
  repository_id?: string;
  status?: string;
  page?: number;
  per_page?: number;
}

export interface ListFindingsParams {
  page?: number;
  per_page?: number;
}

const securityApi = {
  // Dashboard
  getDashboard: async (): Promise<DashboardSummary> => {
    const { data } = await apiClient.get('/api/v1/security/dashboard');
    return data;
  },

  // Scores
  getAllScores: async (): Promise<RepoSecurityScore[]> => {
    const { data } = await apiClient.get('/api/v1/security/scores');
    return data;
  },

  // Scan operations
  triggerScan: async (req: TriggerScanRequest): Promise<TriggerScanResponse> => {
    const { data } = await apiClient.post('/api/v1/security/scan', req);
    return data;
  },

  listScans: async (params?: ListScansParams): Promise<ScanListResponse> => {
    const { data } = await apiClient.get('/api/v1/security/scans', { params });
    return data;
  },

  getScan: async (id: string): Promise<ScanResult> => {
    const { data } = await apiClient.get(`/api/v1/security/scans/${id}`);
    return data;
  },

  listFindings: async (scanId: string, params?: ListFindingsParams): Promise<FindingListResponse> => {
    const { data } = await apiClient.get(`/api/v1/security/scans/${scanId}/findings`, { params });
    return data;
  },

  // Finding acknowledgment
  acknowledgeFinding: async (findingId: string, reason: string): Promise<ScanFinding> => {
    const { data } = await apiClient.post(`/api/v1/security/findings/${findingId}/acknowledge`, { reason });
    return data;
  },

  revokeAcknowledgment: async (findingId: string): Promise<ScanFinding> => {
    const { data } = await apiClient.delete(`/api/v1/security/findings/${findingId}/acknowledge`);
    return data;
  },

  // Policy CRUD
  listPolicies: async (): Promise<ScanPolicy[]> => {
    const { data } = await apiClient.get('/api/v1/security/policies');
    return data;
  },

  createPolicy: async (req: CreatePolicyRequest): Promise<ScanPolicy> => {
    const { data } = await apiClient.post('/api/v1/security/policies', req);
    return data;
  },

  getPolicy: async (id: string): Promise<ScanPolicy> => {
    const { data } = await apiClient.get(`/api/v1/security/policies/${id}`);
    return data;
  },

  updatePolicy: async (id: string, req: UpdatePolicyRequest): Promise<ScanPolicy> => {
    const { data } = await apiClient.put(`/api/v1/security/policies/${id}`, req);
    return data;
  },

  deletePolicy: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/security/policies/${id}`);
  },

  // Repo-scoped security
  getRepoSecurity: async (repoKey: string): Promise<RepoSecurityInfo> => {
    const { data } = await apiClient.get(`/api/v1/repositories/${repoKey}/security`);
    return data;
  },

  updateRepoSecurity: async (repoKey: string, req: UpsertScanConfigRequest): Promise<ScanConfig> => {
    const { data } = await apiClient.put(`/api/v1/repositories/${repoKey}/security`, req);
    return data;
  },

  listRepoScans: async (repoKey: string, params?: ListScansParams): Promise<ScanListResponse> => {
    const { data } = await apiClient.get(`/api/v1/repositories/${repoKey}/security/scans`, { params });
    return data;
  },
};

export default securityApi;
