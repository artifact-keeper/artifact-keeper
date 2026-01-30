import apiClient from './client';

export interface WebhookListResponse<T> {
  items: T[];
  total: number;
}

export type WebhookEvent =
  | 'artifact_uploaded'
  | 'artifact_deleted'
  | 'repository_created'
  | 'repository_deleted'
  | 'user_created'
  | 'user_deleted'
  | 'build_started'
  | 'build_completed'
  | 'build_failed';

export interface Webhook {
  id: string;
  name: string;
  url: string;
  events: WebhookEvent[];
  is_enabled: boolean;
  repository_id?: string;
  headers?: Record<string, string>;
  last_triggered_at?: string;
  created_at: string;
}

export interface CreateWebhookRequest {
  name: string;
  url: string;
  events: WebhookEvent[];
  secret?: string;
  repository_id?: string;
  headers?: Record<string, string>;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  payload: Record<string, unknown>;
  response_status?: number;
  response_body?: string;
  success: boolean;
  attempts: number;
  delivered_at?: string;
  created_at: string;
}

export interface WebhookTestResult {
  success: boolean;
  status_code?: number;
  response_body?: string;
  error?: string;
}

export interface ListWebhooksParams {
  repository_id?: string;
  enabled?: boolean;
  page?: number;
  per_page?: number;
}

export interface ListDeliveriesParams {
  status?: 'success';
  page?: number;
  per_page?: number;
}

export const webhooksApi = {
  list: async (params: ListWebhooksParams = {}): Promise<WebhookListResponse<Webhook>> => {
    const response = await apiClient.get<WebhookListResponse<Webhook>>('/api/v1/webhooks', { params });
    return response.data;
  },

  get: async (id: string): Promise<Webhook> => {
    const response = await apiClient.get<Webhook>(`/api/v1/webhooks/${id}`);
    return response.data;
  },

  create: async (data: CreateWebhookRequest): Promise<Webhook> => {
    const response = await apiClient.post<Webhook>('/api/v1/webhooks', data);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/webhooks/${id}`);
  },

  enable: async (id: string): Promise<void> => {
    await apiClient.post(`/api/v1/webhooks/${id}/enable`);
  },

  disable: async (id: string): Promise<void> => {
    await apiClient.post(`/api/v1/webhooks/${id}/disable`);
  },

  test: async (id: string): Promise<WebhookTestResult> => {
    const response = await apiClient.post<WebhookTestResult>(`/api/v1/webhooks/${id}/test`);
    return response.data;
  },

  listDeliveries: async (id: string, params: ListDeliveriesParams = {}): Promise<WebhookListResponse<WebhookDelivery>> => {
    const response = await apiClient.get<WebhookListResponse<WebhookDelivery>>(
      `/api/v1/webhooks/${id}/deliveries`,
      { params },
    );
    return response.data;
  },

  redeliver: async (webhookId: string, deliveryId: string): Promise<WebhookDelivery> => {
    const response = await apiClient.post<WebhookDelivery>(
      `/api/v1/webhooks/${webhookId}/deliveries/${deliveryId}/redeliver`,
    );
    return response.data;
  },
};

export default webhooksApi;
