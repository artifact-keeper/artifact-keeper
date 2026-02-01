import apiClient from './client';

// Re-export types from the canonical types/ module
export type { TreeNodeType, TreeNode } from '../types/tree';
import type { TreeNode } from '../types/tree';

export interface GetChildrenParams {
  repository_key?: string;
  path?: string;
  include_metadata?: boolean;
}

export const treeApi = {
  getChildren: async (params: GetChildrenParams = {}): Promise<TreeNode[]> => {
    const response = await apiClient.get<{ nodes: TreeNode[] }>('/api/v1/tree', {
      params: {
        repository_key: params.repository_key,
        path: params.path,
        include_metadata: params.include_metadata,
      },
    });
    return response.data.nodes;
  },
};

export default treeApi;
