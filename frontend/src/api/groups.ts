import apiClient from './client';
import type { PaginatedResponse } from '../types';

// Re-export types from the canonical types/ module
export type { Group, GroupMember, CreateGroupRequest } from '../types/groups';
import type { Group, CreateGroupRequest } from '../types/groups';

export interface ListGroupsParams {
  page?: number;
  per_page?: number;
  search?: string;
}

export const groupsApi = {
  list: async (params: ListGroupsParams = {}): Promise<PaginatedResponse<Group>> => {
    const response = await apiClient.get<PaginatedResponse<Group>>('/api/v1/groups', {
      params,
    });
    return response.data;
  },

  get: async (groupId: string): Promise<Group> => {
    const response = await apiClient.get<Group>(`/api/v1/groups/${groupId}`);
    return response.data;
  },

  create: async (data: CreateGroupRequest): Promise<Group> => {
    const response = await apiClient.post<Group>('/api/v1/groups', data);
    return response.data;
  },

  update: async (groupId: string, data: Partial<CreateGroupRequest>): Promise<Group> => {
    const response = await apiClient.put<Group>(`/api/v1/groups/${groupId}`, data);
    return response.data;
  },

  delete: async (groupId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/groups/${groupId}`);
  },

  addMembers: async (groupId: string, userIds: string[]): Promise<void> => {
    await apiClient.post(`/api/v1/groups/${groupId}/members`, { user_ids: userIds });
  },

  removeMembers: async (groupId: string, userIds: string[]): Promise<void> => {
    await apiClient.delete(`/api/v1/groups/${groupId}/members`, {
      data: { user_ids: userIds },
    });
  },
};

export default groupsApi;
