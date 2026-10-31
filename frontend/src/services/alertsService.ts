import { apiClient } from "./apiClient";
import type {
  Alert,
  AlertFilters,
  AlertListResponse,
  AlertUpdate,
  Report,
  ThreatHistoryEntry,
} from "../types/api";

export const alertsService = {
  async list(filters: AlertFilters = {}): Promise<AlertListResponse> {
    const { data } = await apiClient.get<AlertListResponse>("/alerts", { params: filters });
    return data;
  },

  async getById(id: string): Promise<Alert> {
    const { data } = await apiClient.get<Alert>(`/alerts/${id}`);
    return data;
  },

  async update(id: string, payload: AlertUpdate): Promise<Alert> {
    const { data } = await apiClient.patch<Alert>(`/alerts/${id}`, payload);
    return data;
  },

  async getHistory(id: string): Promise<ThreatHistoryEntry[]> {
    const { data } = await apiClient.get<ThreatHistoryEntry[]>(`/alerts/${id}/history`);
    return data;
  },

  async getReports(id: string): Promise<Report[]> {
    const { data } = await apiClient.get<Report[]>(`/alerts/${id}/reports`);
    return data;
  },
};
