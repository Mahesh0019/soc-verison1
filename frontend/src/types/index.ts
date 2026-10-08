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

export type RuleStatus = "DRAFT" | "TESTING" | "ACTIVE" | "DISABLED" | "DEPRECATED";

export interface DetectionRule {
  id: number;
  rule_id?: string | null;
  name: string;
  description: string;
  severity: Severity;
  category?: string;
  version?: string;
  status?: RuleStatus;
  source?: string;
  owner?: string;
  mitre_technique?: string;
  confidence?: number;
  false_positive_notes?: string | null;
  expected_data_source?: string;
  enabled: boolean;
  conditions_json: Record<string, unknown>;
  test_cases_json?: Record<string, unknown> | null;
  time_window_minutes: number;
  threshold: number;
  created_at: string;
  updated_at: string;
}

export interface RuleHealthRecord {
  id: number;
  rule_id: number | null;
  rule_name: string;
  version: string;
  dataset_target: string;
  evaluated_at: string | null;
  true_positives: number | null;
  false_positives: number | null;
  false_negatives: number | null;
  true_negatives: number | null;
  precision: number | null;
  recall: number | null;
  f1_score: number | null;
  false_positive_rate: number | null;
  alert_volume: number;
  detection_latency_ms: number | null;
  coverage_score: number | null;
  confidence: number | null;
  regression_status: string;
  health_score: number | null;
  health_tier: string;
  details_json?: Record<string, unknown> | null;
}

export interface RuleHealthSummary {
  total_rules: number;
  evaluated_rules: number;
  average_health_score: number | null;
  tier_distribution: Record<string, number>;
  rule_records: RuleHealthRecord[];
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

export interface BenchmarkComparisonRow {
  mode: string;
  name: string;
  description: string;
  total_events: number;
  alerts_generated: number;
  incidents_promoted: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  true_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  fp_reduction_pct: number;
  attack_retention_pct: number;
  mtti_minutes: number;
  evidence_retrieval_ms: number;
  ai_analyst_agreement_pct?: number | null;
}

export interface BenchmarkComparisonResponse {
  experiment_id?: number | null;
  experiment_name: string;
  dataset_version: string;
  timestamp: string;
  comparison_matrix: BenchmarkComparisonRow[];
  summary: {
    baseline_mode?: string;
    advanced_mode?: string;
    total_test_scenarios?: number;
    total_events_processed?: number;
    max_fp_reduction_pct?: number;
    genuine_attack_retention_pct?: number;
    mtti_reduction_pct?: number;
    evidence_retrieval_speedup_x?: number;
    quality_aware_fp_reduction_pct?: number;
    hypothesis_validated?: boolean;
    [key: string]: unknown;
  };
}

export interface DetectionQuality {
  id: number;
  alert_id: number;
  evidence_quality_score: number;
  correlation_score: number;
  rule_reliability_score: number;
  behavioral_score: number;
  context_score: number;
  composite_quality_score: number;
  confidence_rating: string;
  explanation_markdown?: string | null;
  factor_breakdown?: Record<string, unknown> | null;
}

export interface EvidenceItem {
  id: number;
  evidence_type: string;
  source: string;
  sha256_hash: string;
  captured_at: string;
  data_payload?: Record<string, unknown> | null;
}

export interface EvidencePackage {
  id: number;
  alert_id: number;
  completeness_score: number;
  is_complete: boolean;
  integrity_hash: string;
  evidence_count: number;
  evidence_items?: EvidenceItem[];
}

export interface AIClaim {
  claim_text: string;
  evidence_ids: number[];
  audit_status: string;
  citation: string;
}

export interface AITriageSummary {
  id: number;
  alert_id: number;
  executive_summary: string;
  root_cause_analysis: string;
  recommended_action: string;
  triage_recommendation: string;
  grounded_claims: AIClaim[];
  hallucination_audit_passed: boolean;
  analyst_agreed?: boolean | null;
}

export interface RuleHealthMetric {
  rule_id: number;
  rule_name: string;
  total_tests: number;
  passed_tests: number;
  pass_rate: number;
  status: string;
}

export interface ValidationSummary {
  total_runs: number;
  overall_pass_rate: number;
  total_passed: number;
  total_failed: number;
  rules_tested_count: number;
  rule_health: RuleHealthMetric[];
}

export interface BehavioralModelStatus {
  is_trained: boolean;
  model_version: string;
  total_samples: number;
  anomaly_threshold: number;
  last_trained_at?: string | null;
}


