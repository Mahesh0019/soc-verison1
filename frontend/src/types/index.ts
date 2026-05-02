export type Role = "admin" | "analyst" | "viewer";
export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "investigating" | "resolved" | "false_positive";

export interface User {
  id: number;
  username: string;
  email: string;
  role: Role;
  created_at: string;
  updated_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface SeriesPoint {
  label: string;
  value: number;
}

export interface LoginTrend {
  label: string;
  failed: number;
  successful: number;
}

export interface NormalizedEvent {
  id: number;
  raw_log_id: number | null;
  timestamp: string;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  hostname: string | null;
  event_type: string;
  event_category: string;
  severity: Severity;
  message: string;
  raw_log: string | null;
  user_agent: string | null;
  request_path: string | null;
  http_method: string | null;
  status_code: number | null;
  geo_country: string | null;
  created_at: string;
}

export interface Alert {
  id: number;
  rule_id: number | null;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  source_ip: string | null;
  affected_user: string | null;
  first_seen: string;
  last_seen: string;
  event_count: number;
  created_at: string;
  updated_at: string;
}

export interface AlertNote {
  id: number;
  user_id: number | null;
  note: string;
  created_at: string;
  user?: User | null;
}

export interface AlertDetail extends Alert {
  related_events: NormalizedEvent[];
  notes: AlertNote[];
}

export interface DetectionRule {
  id: number;
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  conditions_json: Record<string, unknown>;
  time_window_minutes: number;
  threshold: number;
  created_at: string;
  updated_at: string;
}

export interface ThreatIndicator {
  id: number;
  type: "ip" | "domain" | "username";
  value: string;
  description: string | null;
  severity: Severity;
  created_at: string;
  updated_at: string;
}

export interface DashboardSummary {
  total_events: number;
  total_alerts: number;
  open_critical_alerts: number;
  events_over_time: SeriesPoint[];
  alerts_by_severity: SeriesPoint[];
  top_source_ips: SeriesPoint[];
  top_usernames: SeriesPoint[];
  top_event_types: SeriesPoint[];
  event_category_distribution: SeriesPoint[];
  alert_status_distribution: SeriesPoint[];
  login_trends: LoginTrend[];
  recent_alerts: Alert[];
}

export interface IngestResponse {
  raw_log_id: number;
  parsed_count: number;
  alert_count: number;
  errors: string[];
  preview: NormalizedEvent[];
}

