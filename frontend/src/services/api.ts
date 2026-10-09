import axios from "axios";

import type {
  Alert,
  AlertDetail,
  AlertStatus,
  AITriageSummary,
  BehavioralModelStatus,
  BenchmarkComparisonResponse,
  DashboardSummary,
  DetectionQuality,
  DetectionRule,
  EvidencePackage,
  IngestResponse,
  NormalizedEvent,
  Page,
  ThreatIndicator,
  User,
  ValidationSummary,
  RuleHealthRecord,
  RuleHealthSummary,
  TelemetrySourcesResponse,
  ZeekReplayResponse,
  CrossSourceCorrelationRequest,
  CrossSourceCorrelationResult,
  IncidentGraphData,
  IncidentTimelineItem,
  UnifiedIncident,
  TelemetryConnectorStatus,
} from "../types";
import adversarialFallback from "../data/research/adversarial_robustness_v1.json";
import aiAnalystFallback from "../data/research/ai_analyst_v1.json";

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

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("mini-siem-token");
      localStorage.removeItem("mini-siem-user");
      if (typeof window !== "undefined" && window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

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

export async function fetchRulesHealthSummary() {
  const { data } = await api.get<RuleHealthSummary>("/rules/health/summary");
  return data;
}

export async function evaluateRule(ruleId: number) {
  const { data } = await api.post<{ message: string; health_score: number | null; health_tier: string }>(`/rules/${ruleId}/evaluate`);
  return data;
}

export async function evaluateAllRules() {
  const { data } = await api.post<{ message: string; evaluated_count: number }>("/rules/health/evaluate-all");
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

// Phase 11 Research & Evaluation Engine
export async function fetchBenchmarkMatrix(forceRun = false) {
  const { data } = await api.get<BenchmarkComparisonResponse>("/experiments/benchmark/matrix", {
    params: forceRun ? { force_run: true } : undefined,
  });
  return data;
}

export async function runBenchmarkExperiment(mode = "ALL", datasetVersion = "v1.0") {
  const { data } = await api.post<BenchmarkComparisonResponse>("/experiments/run", {
    mode,
    dataset_version: datasetVersion,
  });
  return data;
}

// Phase 5 Detection Quality Engine
export async function fetchDetectionQuality(alertId: number) {
  try {
    const { data } = await api.get<DetectionQuality>(`/detection-quality/alert/${alertId}`);
    return data;
  } catch {
    return null;
  }
}

// Phase 4 Evidence Packaging Engine
export async function fetchEvidencePackage(alertId: number) {
  try {
    const { data } = await api.get<EvidencePackage>(`/evidence/alert/${alertId}`);
    return data;
  } catch {
    return null;
  }
}

// Phase 8 AI Grounded Triage & Claims Audit
export async function fetchAITriage(alertId: number) {
  try {
    const { data } = await api.get<AITriageSummary>(`/ai-triage/alert/${alertId}`);
    return data;
  } catch {
    return null;
  }
}

export async function generateAITriage(alertId: number) {
  const { data } = await api.post<AITriageSummary>(`/ai-triage/alert/${alertId}`);
  return data;
}

export async function submitAIAgreement(alertId: number, agreed: boolean, feedbackText?: string) {
  const { data } = await api.post(`/ai-triage/alert/${alertId}/agreement`, {
    agreed,
    feedback_text: feedbackText || "",
  });
  return data;
}

// Phase 9 Analyst Feedback Loop
export async function submitAnalystFeedback(alertId: number, feedbackLabel: string, comments?: string) {
  const { data } = await api.post("/feedback", {
    alert_id: alertId,
    feedback_label: feedbackLabel,
    analyst_comments: comments || "",
  });
  return data;
}

// Phase 10 Detection Validation Engine
export async function fetchValidationSummary() {
  const { data } = await api.get<ValidationSummary>("/validation/summary");
  return data;
}

export async function runAllValidations() {
  const { data } = await api.post("/validation/run-all");
  return data;
}

// Phase 7 Behavioral ML Anomaly Detection
export async function fetchBehavioralStatus() {
  const { data } = await api.get<BehavioralModelStatus>("/behavioral/status");
  return data;
}

export async function trainBehavioralModel() {
  const { data } = await api.post("/behavioral/train", {});
  return data;
}

// Phase 3 Multi-Source Telemetry & Zeek Replay
export async function fetchTelemetrySources() {
  const { data } = await api.get<TelemetrySourcesResponse>("/telemetry/sources");
  return data;
}

export async function replayZeekTelemetry(payload: { raw_content: string; log_type?: string; mode?: string }) {
  const { data } = await api.post<ZeekReplayResponse>("/telemetry/zeek/replay", payload);
  return data;
}

export async function uploadZeekLog(file: File, logType?: string, mode?: string) {
  const formData = new FormData();
  formData.append("file", file);
  const params: Record<string, string> = {};
  if (logType) params.log_type = logType;
  if (mode) params.mode = mode;
  const { data } = await api.post<ZeekReplayResponse>("/telemetry/zeek/upload", formData, {
    params,
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

// Phase 6 Cross-Source Correlation & Unified Incidents
export async function fetchIncidents(params: Record<string, string | number | undefined>) {
  const { data } = await api.get<Page<UnifiedIncident>>("/incidents", { params: compact(params) });
  return data;
}

export async function fetchUnifiedIncident(incidentId: number) {
  const { data } = await api.get<UnifiedIncident>(`/incidents/${incidentId}/unified`);
  return data;
}

export async function fetchIncidentGraph(incidentId: number) {
  const { data } = await api.get<IncidentGraphData>(`/incidents/${incidentId}/graph`);
  return data;
}

export async function fetchIncidentTimeline(incidentId: number) {
  const { data } = await api.get<IncidentTimelineItem[]>(`/incidents/${incidentId}/timeline`);
  return data;
}

export async function triggerCorrelation(payload?: CrossSourceCorrelationRequest) {
  const { data } = await api.post<CrossSourceCorrelationResult>("/incidents/correlate", payload || {});
  return data;
}

export async function fetchAdversarialRobustness() {
  try {
    const { data } = await api.get<any>("/experiments/adversarial/robustness");
    return data;
  } catch (err: any) {
    if (err?.response?.status === 404 || !err?.response) {
      return adversarialFallback;
    }
    throw err;
  }
}

// Phase 8 Evidence-Grounded AI Analyst Assistant
export async function fetchIncidentAIAnalysis(incidentId: number, forceRefresh: boolean = false) {
  const { data } = await api.post<any>(`/ai/assistant/incident/${incidentId}`, null, {
    params: { force_refresh: forceRefresh }
  });
  return data;
}

export async function askIncidentAIQuestion(incidentId: number, question: string) {
  const { data } = await api.post<any>(`/ai/assistant/incident/${incidentId}/question`, { question });
  return data;
}

export async function fetchAIAnalystEvaluation() {
  try {
    const { data } = await api.get<any>("/ai/assistant/evaluation");
    return data;
  } catch (err: any) {
    if (err?.response?.status === 404 || !err?.response) {
      return aiAnalystFallback;
    }
    throw err;
  }
}

// Phase 9 Threat Hunting & Closed-Loop Detection Engineering
export async function fetchThreatHunts(status?: string) {
  const { data } = await api.get<any[]>("/threat-hunting/hunts", {
    params: status ? { status } : undefined,
  });
  return data;
}

export async function executeThreatHunt(huntId: string, overrideFilters?: any) {
  const { data } = await api.post<any>(`/threat-hunting/hunts/${huntId}/execute`, overrideFilters || {});
  return data;
}

export async function generateDetectionGap(huntId: string) {
  const { data } = await api.post<any>(`/threat-hunting/hunts/${huntId}/generate-gap`);
  return data;
}

export async function fetchDetectionGaps() {
  const { data } = await api.get<any[]>("/threat-hunting/gaps");
  return data;
}

export async function generateCandidateRule(gapId: string) {
  const { data } = await api.post<any>(`/threat-hunting/gaps/${gapId}/generate-candidate`);
  return data;
}

export async function fetchCandidateRules(status?: string) {
  const { data } = await api.get<any[]>("/threat-hunting/candidates", {
    params: status ? { status } : undefined,
  });
  return data;
}

export async function validateCandidateRule(candidateId: string) {
  const { data } = await api.post<any>(`/threat-hunting/candidates/${candidateId}/validate`);
  return data;
}

export async function runCandidateRegression(candidateId: string) {
  const { data } = await api.post<any>(`/threat-hunting/candidates/${candidateId}/regression-check`);
  return data;
}

export async function transitionCandidateRule(candidateId: string, targetStatus: string, changeReason: string) {
  const { data } = await api.post<any>(`/threat-hunting/candidates/${candidateId}/transition`, {
    target_status: targetStatus,
    change_reason: changeReason,
  });
  return data;
}

export async function fetchDetectionCoverageMatrix() {
  const { data } = await api.get<any>("/threat-hunting/coverage-matrix");
  return data;
}

export async function fetchThreatHuntingMetrics() {
  const { data } = await api.get<any>("/threat-hunting/metrics");
  return data;
}

export async function fetchTelemetryConnectorStatus(): Promise<TelemetryConnectorStatus> {
  const { data } = await api.get<TelemetryConnectorStatus>("/telemetry/connector/status");
  return data;
}

function compact<T extends Record<string, unknown>>(params: T) {
  return Object.fromEntries(Object.entries(params).filter(([, value]) => value !== undefined && value !== ""));
}



