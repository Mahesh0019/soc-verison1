import { useEffect, useState } from "react";
import {
  Award,
  Bot,
  CheckCircle2,
  ExternalLink,
  FileCheck2,
  FileText,
  Fingerprint,
  GitBranch,
  Layers,
  MessageSquarePlus,
  Network,
  Play,
  RefreshCw,
  Search,
  Share2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  ThumbsDown,
  ThumbsUp,
  X,
  Zap,
} from "lucide-react";

import { SeverityBadge, StatusBadge } from "../components/Badge";
import { EmptyState, LoadingState } from "../components/State";
import { useAuth } from "../components/AuthProvider";
import { useToast } from "../components/Toast";
import { IncidentGraphView } from "../components/IncidentGraphView";
import { IncidentTimelineView } from "../components/IncidentTimelineView";
import {
  addAlertNote,
  fetchAlert,
  fetchAlerts,
  fetchAITriage,
  fetchDetectionQuality,
  fetchEvidencePackage,
  fetchIncidents,
  fetchUnifiedIncident,
  generateAITriage,
  submitAIAgreement,
  submitAnalystFeedback,
  triggerCorrelation,
  updateAlertStatus,
} from "../services/api";
import type {
  AITriageSummary,
  Alert,
  AlertDetail,
  AlertStatus,
  DetectionQuality,
  EvidencePackage,
  Page,
  UnifiedIncident,
} from "../types";
import { formatDate } from "../utils/format";

export function AlertsPage() {
  const { notify } = useToast();
  const [viewMode, setViewMode] = useState<"alerts" | "incidents">("alerts");
  const [data, setData] = useState<Page<Alert> | null>(null);
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ q: "", severity: "", status: "", source_ip: "", username: "" });

  // Phase 6 Incidents State
  const [incidentsData, setIncidentsData] = useState<Page<UnifiedIncident> | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<UnifiedIncident | null>(null);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [correlationWindow, setCorrelationWindow] = useState<number>(300);
  const [correlating, setCorrelating] = useState(false);

  useEffect(() => {
    if (viewMode === "alerts") {
      setLoading(true);
      fetchAlerts({ ...filters, page_size: 30 })
        .then(setData)
        .finally(() => setLoading(false));
    } else {
      loadIncidents();
    }
  }, [filters, viewMode]);

  async function loadIncidents() {
    setIncidentsLoading(true);
    try {
      const res = await fetchIncidents({ q: filters.q, severity: filters.severity, status: filters.status, page_size: 30 });
      setIncidentsData(res);
    } catch {
      notify("Failed to fetch unified incidents", "error");
    } finally {
      setIncidentsLoading(false);
    }
  }

  async function handleRunCorrelation() {
    setCorrelating(true);
    try {
      const res = await triggerCorrelation({ window_seconds: correlationWindow });
      notify(`Cross-source correlation complete: ${res.correlated_incidents_count} incident(s) reconstructed in ${res.execution_time_ms}ms`, "success");
      await loadIncidents();
    } catch {
      notify("Failed to run correlation engine", "error");
    } finally {
      setCorrelating(false);
    }
  }

  async function openDetail(alert: Alert) {
    setDetail(await fetchAlert(alert.id));
  }

  async function openIncidentDetail(incidentId: number) {
    try {
      const inc = await fetchUnifiedIncident(incidentId);
      setSelectedIncident(inc);
    } catch {
      notify("Failed to fetch unified incident graph details", "error");
    }
  }

  return (
    <div className="space-y-4">
      {/* Top View Mode Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-surface-border bg-surface-raised p-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setViewMode("alerts")}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold transition ${
              viewMode === "alerts"
                ? "bg-indigo-600 text-white shadow"
                : "bg-surface-base text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <ShieldAlert className="h-4 w-4" />
            <span>Alerts Queue</span>
            {data && <span className="ml-1 rounded-full bg-black/30 px-2 py-0.5 text-xs">{data.total}</span>}
          </button>

          <button
            type="button"
            onClick={() => setViewMode("incidents")}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold transition ${
              viewMode === "incidents"
                ? "bg-indigo-600 text-white shadow"
                : "bg-surface-base text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <GitBranch className="h-4 w-4" />
            <span>Unified Incidents (Phase 6 Cross-Source)</span>
            {incidentsData && <span className="ml-1 rounded-full bg-black/30 px-2 py-0.5 text-xs">{incidentsData.total}</span>}
          </button>
        </div>

        {/* Action Controls for Incidents */}
        {viewMode === "incidents" && (
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs text-zinc-400">
              <span>Time Window:</span>
              {[
                { label: "±30s", val: 30 },
                { label: "±2m", val: 120 },
                { label: "±5m (Default)", val: 300 },
                { label: "±10m", val: 600 },
              ].map(({ label, val }) => (
                <button
                  key={val}
                  type="button"
                  onClick={() => setCorrelationWindow(val)}
                  className={`rounded px-2.5 py-1 text-xs font-medium transition ${
                    correlationWindow === val
                      ? "bg-indigo-600 text-white font-semibold"
                      : "bg-surface-inset text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <button
              type="button"
              disabled={correlating}
              onClick={handleRunCorrelation}
              className="flex items-center gap-2 rounded-lg bg-emerald-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {correlating ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              <span>{correlating ? "Correlating..." : "Run Cross-Source Correlation"}</span>
            </button>
          </div>
        )}
      </div>

      {/* Filter Bar */}
      <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
        <div className="grid gap-3 md:grid-cols-[minmax(180px,1.5fr)_repeat(4,minmax(120px,1fr))]">
          <label className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
            <input
              className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset py-2 pl-9 pr-3 text-sm"
              placeholder={viewMode === "alerts" ? "Search alerts" : "Search incidents"}
              value={filters.q}
              onChange={(event) => setFilters((current) => ({ ...current, q: event.target.value }))}
            />
          </label>
          <Select
            value={filters.severity}
            onChange={(severity) => setFilters((current) => ({ ...current, severity }))}
            options={["", "critical", "high", "medium", "low"]}
            label="Severity"
          />
          <Select
            value={filters.status}
            onChange={(status) => setFilters((current) => ({ ...current, status }))}
            options={["", "open", "investigating", "resolved", "false_positive"]}
            label="Status"
          />
          <Text
            value={filters.source_ip}
            onChange={(source_ip) => setFilters((current) => ({ ...current, source_ip }))}
            label="Source IP"
          />
          <Text
            value={filters.username}
            onChange={(username) => setFilters((current) => ({ ...current, username }))}
            label="Username"
          />
        </div>
      </div>

      {/* Content Section */}
      {viewMode === "alerts" ? (
        loading ? (
          <LoadingState label="Loading alerts" />
        ) : data && data.items.length > 0 ? (
          <AlertsTable alerts={data.items} onSelect={openDetail} />
        ) : (
          <EmptyState title="No alerts found" />
        )
      ) : incidentsLoading ? (
        <LoadingState label="Loading correlated incidents" />
      ) : incidentsData && incidentsData.items.length > 0 ? (
        <IncidentsTable
          incidents={incidentsData.items}
          onSelect={(inc) => openIncidentDetail(inc.incident_id)}
        />
      ) : (
        <div className="rounded-lg border border-surface-border bg-surface-raised p-8 text-center space-y-3">
          <GitBranch className="mx-auto h-8 w-8 text-indigo-400" />
          <h3 className="text-base font-semibold text-zinc-200">No Correlated Incidents Reconstructed Yet</h3>
          <p className="text-sm text-zinc-400 max-w-md mx-auto">
            Click "Run Cross-Source Correlation" above to evaluate telemetry events across Web, Zeek, and Sysmon within the configured temporal window.
          </p>
          <button
            type="button"
            onClick={handleRunCorrelation}
            disabled={correlating}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500"
          >
            <Play className="h-4 w-4" />
            <span>Run Correlation Engine</span>
          </button>
        </div>
      )}

      {/* Alert Drawer */}
      {detail ? (
        <AlertDrawer
          detail={detail}
          onClose={() => setDetail(null)}
          onRefresh={async () => setDetail(await fetchAlert(detail.id))}
          onOpenIncident={openIncidentDetail}
        />
      ) : null}

      {/* Phase 6 Incident Graph & Timeline Modal */}
      {selectedIncident && (
        <IncidentModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onSelectAlert={async (alertId) => {
            const al = await fetchAlert(alertId);
            setDetail(al);
          }}
          onRefresh={async () => {
            const inc = await fetchUnifiedIncident(selectedIncident.incident_id);
            setSelectedIncident(inc);
            await loadIncidents();
          }}
        />
      )}
    </div>
  );
}

function AlertsTable({ alerts, onSelect }: { alerts: Alert[]; onSelect: (alert: Alert) => void }) {
  return (
    <div className="overflow-hidden rounded-lg border border-surface-border bg-surface-raised">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[920px] text-left text-sm">
          <thead className="bg-surface-inset text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">User</th>
              <th className="px-4 py-3">Events</th>
              <th className="px-4 py-3">Last seen</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id} className="border-t border-surface-border hover:bg-surface-inset/70">
                <td className="max-w-sm px-4 py-3 text-zinc-200">
                  <div className="font-medium">{alert.title}</div>
                  <div className="text-xs text-zinc-500 line-clamp-1">{alert.description}</div>
                </td>
                <td className="px-4 py-3">
                  <SeverityBadge value={alert.severity} />
                </td>
                <td className="px-4 py-3">
                  <StatusBadge value={alert.status} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">{alert.source_ip ?? "-"}</td>
                <td className="px-4 py-3 text-zinc-300">{alert.affected_user ?? "-"}</td>
                <td className="px-4 py-3 text-zinc-300">{alert.event_count}</td>
                <td className="px-4 py-3 text-zinc-400">{formatDate(alert.last_seen)}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
                    onClick={() => onSelect(alert)}
                    title="Investigate Alert Details"
                  >
                    <FileText className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AlertDrawer({
  detail,
  onClose,
  onRefresh,
  onOpenIncident,
}: {
  detail: AlertDetail;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onOpenIncident?: (incidentId: number) => void;
}) {
  const { can } = useAuth();
  const { notify } = useToast();
  const [note, setNote] = useState("");
  const [activeTab, setActiveTab] = useState<"timeline" | "quality" | "evidence" | "ai_triage">("timeline");
  const canInvestigate = can("admin", "analyst");

  // Advanced Phase Entities
  const [quality, setQuality] = useState<DetectionQuality | null>(null);
  const [evidence, setEvidence] = useState<EvidencePackage | null>(null);
  const [triage, setTriage] = useState<AITriageSummary | null>(null);
  const [generatingTriage, setGeneratingTriage] = useState(false);
  const [feedbackComments, setFeedbackComments] = useState("");

  useEffect(() => {
    fetchDetectionQuality(detail.id).then(setQuality);
    fetchEvidencePackage(detail.id).then(setEvidence);
    fetchAITriage(detail.id).then(setTriage);
  }, [detail.id]);

  async function changeStatus(status: AlertStatus) {
    await updateAlertStatus(detail.id, status);
    notify("Alert status updated", "success");
    await onRefresh();
  }

  async function submitNote() {
    if (!note.trim()) return;
    await addAlertNote(detail.id, note);
    setNote("");
    notify("Note added", "success");
    await onRefresh();
  }

  async function handleGenerateTriage() {
    try {
      setGeneratingTriage(true);
      const res = await generateAITriage(detail.id);
      setTriage(res);
      notify("Evidence-grounded AI triage generated", "success");
    } catch {
      notify("Failed to generate AI triage", "error");
    } finally {
      setGeneratingTriage(false);
    }
  }

  async function handleAgreement(agreed: boolean) {
    try {
      await submitAIAgreement(detail.id, agreed);
      notify(agreed ? "Marked as agreed with AI analysis" : "Marked as disagreed with AI analysis", "success");
      setTriage((prev) => (prev ? { ...prev, analyst_agreed: agreed } : null));
    } catch {
      notify("Failed to record agreement", "error");
    }
  }

  async function handleFeedback(label: "TRUE_POSITIVE" | "FALSE_POSITIVE") {
    try {
      await submitAnalystFeedback(detail.id, label, feedbackComments);
      notify(`Analyst feedback recorded: ${label.replace("_", " ")}`, "success");
      setFeedbackComments("");
      await onRefresh();
    } catch {
      notify("Failed to submit feedback", "error");
    }
  }

  return (
    <div className="fixed inset-0 z-40 bg-black/70">
      <aside className="ml-auto flex h-full w-full max-w-3xl flex-col border-l border-surface-border bg-surface-base shadow-glow">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-surface-border px-5 py-4">
          <div className="space-y-2">
            <h2 className="text-lg font-semibold text-zinc-50">{detail.title}</h2>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge value={detail.severity} />
              <StatusBadge value={detail.status} />

              {/* Quality score quick badge */}
              {quality && (
                <span className="inline-flex items-center gap-1 rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 text-xs font-semibold text-purple-300">
                  <Award className="h-3 w-3 text-purple-400" />
                  Quality: {Math.round(quality.composite_quality_score * 100)}% ({quality.confidence_rating})
                </span>
              )}

              {/* Evidence package completeness quick badge */}
              {evidence && (
                <span className="inline-flex items-center gap-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-0.5 text-xs font-semibold text-cyan-300">
                  <FileCheck2 className="h-3 w-3 text-cyan-400" />
                  Evidence: {Math.round(evidence.completeness_score * 100)}% Complete
                </span>
              )}
            </div>
          </div>
          <button
            className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-surface-inset hover:text-zinc-100"
            onClick={onClose}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-surface-border bg-surface-raised/30 px-5 text-xs font-medium">
          <button
            onClick={() => setActiveTab("timeline")}
            className={`border-b-2 py-3 px-3 transition ${
              activeTab === "timeline" ? "border-cyan-400 text-cyan-400" : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Timeline & Notes
          </button>
          <button
            onClick={() => setActiveTab("quality")}
            className={`flex items-center gap-1.5 border-b-2 py-3 px-3 transition ${
              activeTab === "quality" ? "border-purple-400 text-purple-400" : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            Detection Quality (Phase 5)
          </button>
          <button
            onClick={() => setActiveTab("evidence")}
            className={`flex items-center gap-1.5 border-b-2 py-3 px-3 transition ${
              activeTab === "evidence" ? "border-cyan-400 text-cyan-400" : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <Fingerprint className="h-3.5 w-3.5" />
            Evidence Package (Phase 4)
          </button>
          <button
            onClick={() => setActiveTab("ai_triage")}
            className={`flex items-center gap-1.5 border-b-2 py-3 px-3 transition ${
              activeTab === "ai_triage" ? "border-emerald-400 text-emerald-400" : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <Bot className="h-3.5 w-3.5" />
            AI Triage & Audit (Phase 8/9)
          </button>
        </div>

        {/* Tab Content */}
        <div className="flex-1 space-y-6 overflow-y-auto p-5">
          {/* Quick status actions */}
          {canInvestigate && (
            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-surface-border bg-surface-raised p-3">
              <span className="text-xs font-medium text-zinc-400">Set Status:</span>
              {(["open", "investigating", "resolved", "false_positive"] as AlertStatus[]).map((status) => (
                <button
                  key={status}
                  className="focus-ring rounded-lg border border-surface-border bg-surface-base px-2.5 py-1 text-xs capitalize text-zinc-200 hover:bg-surface-inset"
                  onClick={() => changeStatus(status)}
                >
                  {status.replace("_", " ")}
                </button>
              ))}
            </div>
          )}

          {/* TAB 1: Timeline & Notes */}
          {activeTab === "timeline" && (
            <div className="space-y-6">
              <p className="rounded-lg border border-surface-border bg-surface-raised p-3 text-sm text-zinc-300">
                {detail.description}
              </p>

              <section>
                <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-100">
                  <CheckCircle2 className="h-4 w-4 text-cyan-200" />
                  Correlated Event Timeline
                </h3>
                <div className="space-y-3">
                  {detail.related_events.slice(0, 15).map((event) => (
                    <div key={event.id} className="rounded-lg border border-surface-border bg-surface-raised p-3">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                        <span>{formatDate(event.timestamp)}</span>
                        <span>{event.source_ip ?? "-"}</span>
                        <SeverityBadge value={event.severity} />
                        {event.request_path && (
                          <span className="font-mono text-zinc-400">{event.request_path}</span>
                        )}
                      </div>
                      <p className="mt-2 text-sm text-zinc-200">{event.message}</p>
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-100">
                  <MessageSquarePlus className="h-4 w-4 text-emerald-200" />
                  Analyst Notes
                </h3>
                <div className="space-y-2">
                  {detail.notes.map((item) => (
                    <div
                      key={item.id}
                      className="rounded-lg border border-surface-border bg-surface-raised p-3 text-sm text-zinc-300"
                    >
                      <div className="mb-1 text-xs text-zinc-500">
                        {item.user?.username ?? "analyst"} - {formatDate(item.created_at)}
                      </div>
                      {item.note}
                    </div>
                  ))}
                  {canInvestigate && (
                    <div className="flex gap-2">
                      <textarea
                        className="focus-ring min-h-20 flex-1 rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm"
                        value={note}
                        onChange={(event) => setNote(event.target.value)}
                        placeholder="Add investigation findings or operational notes..."
                      />
                      <button
                        className="focus-ring rounded-lg bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-950 hover:bg-white"
                        onClick={submitNote}
                      >
                        Add
                      </button>
                    </div>
                  )}
                </div>
              </section>
            </div>
          )}

          {/* TAB 2: Detection Quality (Phase 5) */}
          {activeTab === "quality" && (
            <div className="space-y-5">
              {quality ? (
                <>
                  <div className="rounded-xl border border-purple-500/30 bg-purple-500/5 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Award className="h-5 w-5 text-purple-400" />
                        <h4 className="font-semibold text-zinc-100">5-Factor Explainable Quality Score</h4>
                      </div>
                      <span className="font-mono text-lg font-bold text-purple-400">
                        {Math.round(quality.composite_quality_score * 100)}%
                      </span>
                    </div>
                    <div className="text-xs text-zinc-400">
                      Confidence Level: <strong className="text-zinc-200">{quality.confidence_rating}</strong>
                    </div>
                  </div>

                  {/* 5 Factor Breakdown Bars */}
                  <div className="space-y-3 rounded-lg border border-surface-border bg-surface-raised p-4 text-xs">
                    <h5 className="font-semibold text-zinc-200">Factor Decomposition</h5>

                    {[
                      { label: "Evidence Completeness (F_evid)", score: quality.evidence_quality_score, color: "bg-cyan-500" },
                      { label: "Correlation Robustness (F_corr)", score: quality.correlation_score, color: "bg-blue-500" },
                      { label: "Rule Reliability (F_rule)", score: quality.rule_reliability_score, color: "bg-purple-500" },
                      { label: "Behavioral Consistency (F_behav)", score: quality.behavioral_score, color: "bg-emerald-500" },
                      { label: "Context Completeness (F_context)", score: quality.context_score, color: "bg-amber-500" },
                    ].map((f) => (
                      <div key={f.label} className="space-y-1">
                        <div className="flex justify-between">
                          <span className="text-zinc-300">{f.label}</span>
                          <span className="font-mono font-semibold text-zinc-200">
                            {Math.round(f.score * 100)}%
                          </span>
                        </div>
                        <div className="h-1.5 w-full rounded-full bg-zinc-800">
                          <div
                            className={`h-1.5 rounded-full ${f.color}`}
                            style={{ width: `${Math.round(f.score * 100)}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>

                  {quality.explanation_markdown && (
                    <div className="rounded-lg border border-surface-border bg-surface-base p-4 text-xs text-zinc-300 space-y-2">
                      <div className="font-semibold text-zinc-200">Quality Diagnostic Insights:</div>
                      <p className="leading-relaxed whitespace-pre-wrap">{quality.explanation_markdown}</p>
                    </div>
                  )}
                </>
              ) : (
                <EmptyState title="Detection quality score calculating or not available for this alert" />
              )}
            </div>
          )}

          {/* TAB 3: Evidence Package (Phase 4) */}
          {activeTab === "evidence" && (
            <div className="space-y-5">
              {evidence ? (
                <>
                  <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5 text-cyan-400" />
                        <h4 className="font-semibold text-zinc-100">Cryptographic Evidence Package</h4>
                      </div>
                      <span className="font-mono text-sm font-bold text-cyan-400">
                        {Math.round(evidence.completeness_score * 100)}% Complete
                      </span>
                    </div>

                    <div className="font-mono text-[11px] text-zinc-400 break-all">
                      <span className="text-zinc-500">SHA-256 Hash: </span>
                      {evidence.integrity_hash}
                    </div>
                  </div>

                  {/* Evidence Items */}
                  <div className="space-y-3">
                    <h5 className="text-xs font-semibold text-zinc-300">
                      Packaged Forensic Evidence Items ({evidence.evidence_items?.length || 0})
                    </h5>

                    {(evidence.evidence_items || []).map((item) => (
                      <div
                        key={item.id}
                        className="rounded-lg border border-surface-border bg-surface-raised p-3.5 space-y-2 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold uppercase tracking-wider text-cyan-400">
                            {item.evidence_type}
                          </span>
                          <span className="text-zinc-500">{formatDate(item.captured_at)}</span>
                        </div>

                        <div className="font-mono text-[10px] text-zinc-400 break-all">
                          Hash: {item.sha256_hash}
                        </div>

                        {item.data_payload && (
                          <pre className="max-h-36 overflow-x-auto rounded bg-zinc-950 p-2 font-mono text-[11px] text-zinc-300">
                            {JSON.stringify(item.data_payload, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <EmptyState title="No cryptographic evidence package attached to this alert" />
              )}
            </div>
          )}

          {/* TAB 4: AI Grounded Triage & Claims Audit (Phase 8 & 9) */}
          {activeTab === "ai_triage" && (
            <div className="space-y-5">
              {!triage ? (
                <div className="rounded-xl border border-surface-border bg-surface-raised p-6 text-center space-y-3">
                  <Bot className="mx-auto h-8 w-8 text-emerald-400" />
                  <h4 className="font-semibold text-zinc-100">Evidence-Grounded AI Triage Assistance</h4>
                  <p className="text-xs text-zinc-400 max-w-md mx-auto">
                    Generate an audited incident triage synthesis with automated claims verification. Every claim is verified
                    against cryptographic evidence items.
                  </p>
                  <button
                    onClick={handleGenerateTriage}
                    disabled={generatingTriage}
                    className="focus-ring inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-600 px-4 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-emerald-500 disabled:opacity-50"
                  >
                    <Sparkles className={`h-3.5 w-3.5 ${generatingTriage ? "animate-spin" : ""}`} />
                    {generatingTriage ? "Synthesizing Triage..." : "Generate AI Triage"}
                  </button>
                </div>
              ) : (
                <>
                  {/* Executive Summary */}
                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Bot className="h-5 w-5 text-emerald-400" />
                        <h4 className="font-semibold text-zinc-100">AI Triage Synthesis</h4>
                      </div>
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
                        <CheckCircle2 className="h-3 w-3" />
                        Claims Audit Verified
                      </span>
                    </div>

                    <p className="text-xs leading-relaxed text-zinc-200">{triage.executive_summary}</p>

                    <div className="border-t border-emerald-500/20 pt-2 text-xs text-zinc-300">
                      <strong>Recommended Action: </strong>
                      <span className="text-emerald-300">{triage.recommended_action}</span>
                    </div>
                  </div>

                  {/* Grounded Claims Audit List */}
                  <div className="space-y-2 rounded-lg border border-surface-border bg-surface-raised p-4">
                    <h5 className="text-xs font-semibold text-zinc-200 flex items-center gap-1.5">
                      <FileCheck2 className="h-4 w-4 text-cyan-400" />
                      Claims Audit Checklist ({triage.grounded_claims?.length || 0} Citations Verified)
                    </h5>

                    <div className="space-y-2 pt-1">
                      {(triage.grounded_claims || []).map((claim, idx) => (
                        <div
                          key={idx}
                          className="rounded border border-surface-border/60 bg-surface-base/80 p-2.5 text-xs space-y-1"
                        >
                          <div className="flex items-center justify-between">
                            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400">
                              <CheckCircle2 className="h-3 w-3" />
                              VERIFIED
                            </span>
                            <span className="text-[10px] text-zinc-500 font-mono">
                              Citation: {claim.citation}
                            </span>
                          </div>
                          <p className="text-zinc-300">{claim.claim_text}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Analyst Agreement (Phase 8 Feedback) */}
                  <div className="rounded-lg border border-surface-border bg-surface-raised p-4 space-y-3">
                    <h5 className="text-xs font-semibold text-zinc-200">Analyst Agreement on AI Assessment</h5>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => handleAgreement(true)}
                        className={`focus-ring inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                          triage.analyst_agreed === true
                            ? "border-emerald-500 bg-emerald-500/20 text-emerald-300"
                            : "border-surface-border bg-surface-base text-zinc-300 hover:bg-surface-inset"
                        }`}
                      >
                        <ThumbsUp className="h-3.5 w-3.5 text-emerald-400" />
                        Agree with AI
                      </button>
                      <button
                        onClick={() => handleAgreement(false)}
                        className={`focus-ring inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                          triage.analyst_agreed === false
                            ? "border-rose-500 bg-rose-500/20 text-rose-300"
                            : "border-surface-border bg-surface-base text-zinc-300 hover:bg-surface-inset"
                        }`}
                      >
                        <ThumbsDown className="h-3.5 w-3.5 text-rose-400" />
                        Disagree with AI
                      </button>
                    </div>
                  </div>

                  {/* Analyst Feedback Loop (Phase 9 Ground Truth & Tuning) */}
                  <div className="rounded-lg border border-surface-border bg-surface-raised p-4 space-y-3">
                    <h5 className="text-xs font-semibold text-zinc-200">
                      Ground Truth Feedback & Rule Tuning Loop (Phase 9)
                    </h5>
                    <p className="text-[11px] text-zinc-400">
                      Record formal ground truth to improve model confusion matrices and enable auto-tuning safeguards.
                    </p>

                    <input
                      className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-1.5 text-xs"
                      placeholder="Optional analyst remarks for rule tuning..."
                      value={feedbackComments}
                      onChange={(e) => setFeedbackComments(e.target.value)}
                    />

                    <div className="flex gap-2">
                      <button
                        onClick={() => handleFeedback("TRUE_POSITIVE")}
                        className="focus-ring inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-500/20"
                      >
                        <ShieldAlert className="h-3.5 w-3.5" />
                        Confirm True Positive Attack
                      </button>
                      <button
                        onClick={() => handleFeedback("FALSE_POSITIVE")}
                        className="focus-ring inline-flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold text-rose-400 hover:bg-rose-500/20"
                      >
                        <Zap className="h-3.5 w-3.5" />
                        Mark as Benign False Positive
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <select
      className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    >
      {options.map((option) => (
        <option key={option || "all"} value={option}>
          {option || label}
        </option>
      ))}
    </select>
  );
}

function Text({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <input
      className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm"
      placeholder={label}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

function IncidentsTable({
  incidents,
  onSelect,
}: {
  incidents: UnifiedIncident[];
  onSelect: (incident: UnifiedIncident) => void;
}) {
  return (
    <div className="overflow-hidden rounded-lg border border-surface-border bg-surface-raised">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[960px] text-left text-sm">
          <thead className="bg-surface-inset text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3">Incident</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Attack Chain Status</th>
              <th className="px-4 py-3">Sources</th>
              <th className="px-4 py-3">Primary Entity</th>
              <th className="px-4 py-3">Correlation Score</th>
              <th className="px-4 py-3">Telemetry</th>
              <th className="px-4 py-3">Last Seen</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((inc) => {
              const statusColor =
                inc.attack_chain_status === "POTENTIAL ATTACK CHAIN"
                  ? "bg-amber-950/40 text-amber-300 border-amber-500/30"
                  : inc.attack_chain_status === "CORRELATED ACTIVITY"
                  ? "bg-blue-950/40 text-blue-300 border-blue-500/30"
                  : "bg-zinc-800 text-zinc-400 border-zinc-700";

              const scorePct = inc.correlation_score ? Math.round(inc.correlation_score * 100) : 50;

              return (
                <tr key={inc.incident_id} className="border-t border-surface-border hover:bg-surface-inset/70">
                  <td className="max-w-xs px-4 py-3 text-zinc-200">
                    <div className="font-mono text-xs font-semibold text-indigo-400">{inc.incident_number}</div>
                    <div className="font-medium truncate">{inc.title}</div>
                    <div className="text-xs text-zinc-500 line-clamp-1">{inc.description}</div>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge value={inc.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${statusColor}`}>
                      {inc.attack_chain_status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {inc.source_types && inc.source_types.length > 0 ? (
                        inc.source_types.map((src) => (
                          <span key={src} className="rounded bg-surface-inset px-1.5 py-0.5 text-[10px] font-mono text-zinc-300 border border-surface-border">
                            {src}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-zinc-500">WEB</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-amber-300">
                    {inc.primary_entity || "-"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-zinc-200">{scorePct}%</span>
                        <span className="text-[10px] text-zinc-400 uppercase">{inc.confidence}</span>
                      </div>
                      <div className="h-1.5 w-24 rounded-full bg-zinc-800 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            scorePct >= 75 ? "bg-emerald-500" : scorePct >= 50 ? "bg-blue-500" : "bg-amber-500"
                          }`}
                          style={{ width: `${scorePct}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-300">
                    <div>{inc.alerts?.length || 0} Alerts</div>
                    <div className="text-zinc-500">{inc.events?.length || 0} Events</div>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-400">
                    {formatDate(inc.updated_at || inc.created_at)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => onSelect(inc)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600/20 border border-indigo-500/30 px-3 py-1.5 text-xs font-semibold text-indigo-300 hover:bg-indigo-600 hover:text-white transition"
                    >
                      <GitBranch className="h-3.5 w-3.5" />
                      <span>Investigate</span>
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function IncidentModal({
  incident,
  onClose,
  onSelectAlert,
  onRefresh,
}: {
  incident: UnifiedIncident;
  onClose: () => void;
  onSelectAlert?: (alertId: number) => void;
  onRefresh?: () => Promise<void>;
}) {
  const [modalTab, setModalTab] = useState<"graph" | "timeline" | "evidence" | "alerts">("graph");

  const scorePct = incident.correlation_score ? Math.round(incident.correlation_score * 100) : 50;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
      <div className="flex h-[92vh] w-full max-w-6xl flex-col rounded-xl border border-surface-border bg-surface-base shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex flex-wrap items-center justify-between border-b border-surface-border bg-surface-raised px-6 py-4 gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono text-sm font-bold text-indigo-400">
                {incident.incident_number}
              </span>
              <SeverityBadge value={incident.severity} />
              <span className="rounded-full border border-surface-border bg-surface-inset px-2.5 py-0.5 text-xs font-semibold text-zinc-200">
                Status: {incident.status}
              </span>
              <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
                incident.attack_chain_status === "POTENTIAL ATTACK CHAIN"
                  ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                  : "border-blue-500/40 bg-blue-500/10 text-blue-300"
              }`}>
                {incident.attack_chain_status}
              </span>
              <span className="rounded-full border border-purple-500/40 bg-purple-500/10 px-2.5 py-0.5 text-xs font-semibold text-purple-300">
                Correlation Score: {scorePct}% ({incident.confidence})
              </span>
              <span className="rounded-full border border-rose-500/40 bg-rose-500/10 px-2.5 py-0.5 text-xs font-semibold text-rose-300">
                Risk Score: {Math.round(incident.risk_score)}/100
              </span>
            </div>
            <h2 className="text-base font-semibold text-zinc-100">{incident.title}</h2>
            <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-400">
              <span>Primary Entity: <span className="font-mono text-amber-300">{incident.primary_entity || "Unspecified"}</span></span>
              <span>•</span>
              <span>Telemetry Sources: {incident.source_types?.join(", ") || "WEB"}</span>
              <span>•</span>
              <span>Created: {formatDate(incident.created_at)}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-zinc-400 hover:bg-surface-inset hover:text-zinc-100"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Navigation Tabs */}
        <div className="flex border-b border-surface-border bg-surface-base px-6 text-xs font-semibold">
          <button
            type="button"
            onClick={() => setModalTab("graph")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 transition ${
              modalTab === "graph"
                ? "border-indigo-400 text-indigo-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <Share2 className="h-4 w-4" />
            <span>Investigation Graph</span>
            {incident.graph?.nodes && (
              <span className="rounded-full bg-surface-inset px-2 py-0.5 text-[10px] text-zinc-300">
                {incident.graph.nodes.length}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setModalTab("timeline")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 transition ${
              modalTab === "timeline"
                ? "border-indigo-400 text-indigo-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <CheckCircle2 className="h-4 w-4" />
            <span>Chronological Telemetry Timeline</span>
            {incident.timeline && (
              <span className="rounded-full bg-surface-inset px-2 py-0.5 text-[10px] text-zinc-300">
                {incident.timeline.length}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setModalTab("evidence")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 transition ${
              modalTab === "evidence"
                ? "border-indigo-400 text-indigo-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <Fingerprint className="h-4 w-4" />
            <span>Cross-Source Evidence ({incident.evidence?.length || 0})</span>
          </button>

          <button
            type="button"
            onClick={() => setModalTab("alerts")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 transition ${
              modalTab === "alerts"
                ? "border-indigo-400 text-indigo-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <ShieldAlert className="h-4 w-4" />
            <span>Correlated Alerts ({incident.alerts?.length || 0})</span>
          </button>
        </div>

        {/* Modal Tab Body */}
        <div className="flex-1 overflow-y-auto p-6 bg-surface-inset/40">
          {modalTab === "graph" && (
            <IncidentGraphView
              graphData={incident.graph}
              onSelectAlert={onSelectAlert}
            />
          )}

          {modalTab === "timeline" && (
            <IncidentTimelineView
              timeline={incident.timeline}
              onSelectAlert={onSelectAlert}
            />
          )}

          {modalTab === "evidence" && (
            <div className="space-y-4">
              <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
                <h4 className="text-sm font-semibold text-zinc-200 mb-1">
                  Cross-Source Correlation Evidence Items
                </h4>
                <p className="text-xs text-zinc-400">
                  Tamper-evident cryptographic evidence packages documenting deterministic entity matches, temporal deltas, and multi-source attack progression.
                </p>
              </div>

              {incident.evidence && incident.evidence.length > 0 ? (
                incident.evidence.map((ev) => (
                  <div key={ev.id} className="rounded-lg border border-surface-border bg-surface-raised p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-indigo-950/40 border border-indigo-500/30 px-2 py-0.5 text-xs font-mono font-semibold text-indigo-300">
                          {ev.evidence_type}
                        </span>
                        <span className="text-sm font-semibold text-zinc-200">{ev.title}</span>
                      </div>
                      {ev.sha256_hash && (
                        <span className="font-mono text-[10px] text-zinc-500 truncate max-w-xs" title={ev.sha256_hash}>
                          SHA256: {ev.sha256_hash}
                        </span>
                      )}
                    </div>

                    <div className="text-xs text-zinc-300">{ev.description}</div>

                    {ev.data_json && (
                      <div className="rounded bg-surface-inset p-3 font-mono text-xs space-y-1">
                        <div className="text-zinc-400 font-semibold mb-1">Evidence Breakdown:</div>
                        {Object.entries(ev.data_json).map(([k, v]) => (
                          <div key={k} className="flex justify-between gap-4">
                            <span className="text-zinc-500">{k}:</span>
                            <span className="text-zinc-200 text-right break-all">
                              {typeof v === "object" ? JSON.stringify(v) : String(v)}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="py-8 text-center text-sm text-zinc-400">
                  No explicit cross-source evidence records persisted for this incident.
                </div>
              )}
            </div>
          )}

          {modalTab === "alerts" && (
            <div className="space-y-3">
              {incident.alerts && incident.alerts.length > 0 ? (
                incident.alerts.map((al) => (
                  <div
                    key={al.id}
                    className="flex items-center justify-between rounded-lg border border-surface-border bg-surface-raised p-4 hover:bg-surface-inset transition"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge value={al.severity} />
                        <span className="text-sm font-semibold text-zinc-200">{al.title}</span>
                      </div>
                      <div className="text-xs text-zinc-400">{al.description}</div>
                      <div className="flex items-center gap-3 text-xs text-zinc-500 font-mono">
                        <span>IP: {al.source_ip || "-"}</span>
                        <span>User: {al.affected_user || "-"}</span>
                        <span>Events: {al.event_count}</span>
                        <span>Seen: {formatDate(al.last_seen)}</span>
                      </div>
                    </div>

                    {onSelectAlert && (
                      <button
                        type="button"
                        onClick={() => onSelectAlert(al.id)}
                        className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500"
                      >
                        Inspect Alert
                      </button>
                    )}
                  </div>
                ))
              ) : (
                <div className="py-8 text-center text-sm text-zinc-400">
                  No alerts linked to this incident.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

