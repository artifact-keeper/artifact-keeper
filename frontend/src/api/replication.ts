import apiClient from './client';

export interface EdgeNode {
  id: string;
  name: string;
  endpoint_url: string;
  status: 'online' | 'offline' | 'syncing' | 'degraded';
  region?: string;
  cache_size_bytes: number;
  cache_used_bytes: number;
  last_heartbeat_at?: string;
  last_sync_at?: string;
}

export interface EdgeNodesResponse {
  items: EdgeNode[];
  total: number;
}

export interface EdgeNodePeer {
  id: string;
  target_node_id: string;
  status: string;
  latency_ms: number;
  bandwidth_estimate_bps: number;
  shared_artifacts_count: number;
  bytes_transferred_total: number;
  transfer_success_count: number;
  transfer_failure_count: number;
}

export interface EdgeNodePeersResponse {
  items: EdgeNodePeer[];
}

export interface AssignRepoRequest {
  repository_id: string;
  priority: number;
}

export interface ListEdgeNodesParams {
  status?: string;
  per_page?: number;
}

export const replicationApi = {
  listEdgeNodes: async (params: ListEdgeNodesParams = {}): Promise<EdgeNodesResponse> => {
    const response = await apiClient.get<EdgeNodesResponse>('/api/v1/edge-nodes', { params });
    return response.data;
  },

  getEdgeNode: async (id: string): Promise<EdgeNode> => {
    const response = await apiClient.get<EdgeNode>(`/api/v1/edge-nodes/${id}`);
    return response.data;
  },

  getEdgeNodePeers: async (nodeId: string): Promise<EdgeNodePeer[]> => {
    const response = await apiClient.get<EdgeNodePeersResponse>(
      `/api/v1/edge-nodes/${nodeId}/peers`
    );
    return response.data.items;
  },

  getEdgeNodeRepos: async (nodeId: string): Promise<string[]> => {
    const response = await apiClient.get<string[]>(
      `/api/v1/edge-nodes/${nodeId}/repositories`
    );
    return response.data;
  },

  assignRepoToEdge: async (nodeId: string, data: AssignRepoRequest): Promise<void> => {
    await apiClient.post(`/api/v1/edge-nodes/${nodeId}/repositories`, data);
  },
};

export default replicationApi;
