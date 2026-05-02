import axios from "axios";

import type {
  Alert,
  AlertDetail,
  AlertStatus,
  DashboardSummary,
  DetectionRule,
  IngestResponse,
  NormalizedEvent,
  Page,
  ThreatIndicator,
  User,
} from "../types";

const API_BASE_URL = import.meta.env.VITE_API_URL ?? "/api";

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("mini-siem-token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export async function login(username: string, password: string) {
  const { data } = await api.post<{ access_token: string; token_type: string; user: User }>("/auth/login", { username, password });
  return data;
}

export async function fetchDashboard() {
  const { data } = await api.get<DashboardSummary>("/dashboard/summary");
  return data;
}

export async function fetchEvents(params: Record<string, string | number | undefined>) {
  const { data } = await api.get<Page<NormalizedEvent>>("/events", { params: compact(params) });
  return data;
}

export async function fetchAlerts(params: Record<string, string | number | undefined>) {
  const { data } = await api.get<Page<Alert>>("/alerts", { params: compact(params) });
  return data;
}

export async function fetchAlert(id: number) {
  const { data } = await api.get<AlertDetail>(`/alerts/${id}`);
  return data;
}

export async function updateAlertStatus(id: number, status: AlertStatus) {
  const { data } = await api.patch<Alert>(`/alerts/${id}/status`, { status });
  return data;
}

export async function addAlertNote(id: number, note: string) {
  const { data } = await api.post(`/alerts/${id}/notes`, { note });
  return data;
}

export async function fetchRules(params: Record<string, string | number | boolean | undefined>) {
  const { data } = await api.get<Page<DetectionRule>>("/rules", { params: compact(params) });
  return data;
}

export async function toggleRule(id: number, enabled: boolean) {
  const { data } = await api.patch<DetectionRule>(`/rules/${id}/toggle`, { enabled });
  return data;
}

export async function createRule(payload: Partial<DetectionRule>) {
  const { data } = await api.post<DetectionRule>("/rules", payload);
  return data;
}

export async function uploadLogs(file: File, onProgress?: (progress: number) => void) {
  const form = new FormData();
  form.append("file", file);
  const { data } = await api.post<IngestResponse>("/logs/upload", form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress: (event) => {
      if (event.total && onProgress) onProgress(Math.round((event.loaded / event.total) * 100));
    },
  });
  return data;
}

export async function fetchIndicators(params: Record<string, string | number | undefined>) {
  const { data } = await api.get<Page<ThreatIndicator>>("/threat-intel", { params: compact(params) });
  return data;
}

export async function createIndicator(payload: Pick<ThreatIndicator, "type" | "value" | "description" | "severity">) {
  const { data } = await api.post<ThreatIndicator>("/threat-intel", payload);
  return data;
}

export async function deleteIndicator(id: number) {
  const { data } = await api.delete(`/threat-intel/${id}`);
  return data;
}

export async function fetchAdminStats() {
  const { data } = await api.get<Record<string, number>>("/admin/stats");
  return data;
}

export async function fetchUsers(params: Record<string, string | number | undefined>) {
  const { data } = await api.get<Page<User>>("/admin/users", { params: compact(params) });
  return data;
}

export async function createUser(payload: { username: string; email: string; password: string; role: string }) {
  const { data } = await api.post<User>("/admin/users", payload);
  return data;
}

export async function seedDemo() {
  const { data } = await api.post("/demo/seed");
  return data;
}

export async function clearDemo() {
  const { data } = await api.delete("/demo/clear");
  return data;
}

function compact<T extends Record<string, unknown>>(params: T) {
  return Object.fromEntries(Object.entries(params).filter(([, value]) => value !== undefined && value !== ""));
}

