import { FormEvent, useCallback, useEffect, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Clock,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ToggleLeft,
  ToggleRight,
  TrendingUp,
  XCircle,
} from "lucide-react";

import { SeverityBadge } from "../components/Badge";
import { EmptyState, LoadingState } from "../components/State";
import { useAuth } from "../components/AuthProvider";
import { useToast } from "../components/Toast";
import {
  createRule,
  evaluateAllRules,
  evaluateRule,
  fetchRules,
  fetchRulesHealthSummary,
  toggleRule,
} from "../services/api";
import type { DetectionRule, Page, RuleHealthRecord, RuleHealthSummary, Severity } from "../types";

export function RulesPage() {
  const [data, setData] = useState<Page<DetectionRule> | null>(null);
  const [healthSummary, setHealthSummary] = useState<RuleHealthSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [evaluatingAll, setEvaluatingAll] = useState(false);
  const [evaluatingRuleId, setEvaluatingRuleId] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  const { can } = useAuth();
  const { notify } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [rulesRes, healthRes] = await Promise.all([
        fetchRules({ q: query, page_size: 100 }),
        fetchRulesHealthSummary().catch(() => null),
      ]);
      setData(rulesRes);
      if (healthRes) {
        setHealthSummary(healthRes);
      }
    } finally {
      setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    load();
  }, [load]);

  async function onToggle(rule: DetectionRule) {
    await toggleRule(rule.id, !rule.enabled);
    notify(`Rule ${!rule.enabled ? "enabled" : "disabled"}`, "success");
    await load();
  }

  async function onEvaluateAll() {
    setEvaluatingAll(true);
    try {
      const res = await evaluateAllRules();
      notify(res.message, "success");
      await load();
    } catch {
      notify("Failed to evaluate rules", "error");
    } finally {
      setEvaluatingAll(false);
    }
  }

  async function onEvaluateSingle(ruleId: number) {
    setEvaluatingRuleId(ruleId);
    try {
      const res = await evaluateRule(ruleId);
      notify(res.message, "success");
      await load();
    } catch {
      notify("Failed to evaluate rule", "error");
    } finally {
      setEvaluatingRuleId(null);
    }
  }

  // Build a lookup map of rule_id -> RuleHealthRecord
  const healthByRuleId = new Map<number, RuleHealthRecord>();
  if (healthSummary) {
    for (const rec of healthSummary.rule_records) {
      if (rec.rule_id != null) {
        healthByRuleId.set(rec.rule_id, rec);
      }
    }
  }

  const filteredRules = (data?.items || []).filter((rule) => {
    if (statusFilter !== "ALL" && (rule.status || "ACTIVE") !== statusFilter) {
      return false;
    }
    if (severityFilter !== "ALL" && rule.severity !== severityFilter) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-5">
      {/* Detection Quality & Rule Health Overview Header */}
      <section className="rounded-xl border border-surface-border bg-surface-raised p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-400" />
              <h1 className="text-lg font-bold text-zinc-100">Detection Engineering & Quality Center</h1>
            </div>
            <p className="mt-1 text-sm text-zinc-400">
              Measurable Detection-as-Code lifecycle: automated regression assertions, explainable health scoring, and persistent quality tracking.
            </p>
          </div>

          {can("admin") ? (
            <button
              onClick={onEvaluateAll}
              disabled={evaluatingAll}
              className="focus-ring inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${evaluatingAll ? "animate-spin" : ""}`} />
              {evaluatingAll ? "Running Test Suite..." : "Evaluate All Rules"}
            </button>
          ) : null}
        </div>

        {healthSummary ? (
          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-lg border border-surface-border bg-surface-inset p-3">
              <div className="text-xs font-medium text-zinc-400">Total Rules</div>
              <div className="mt-1 text-2xl font-bold text-zinc-100">{healthSummary.total_rules}</div>
              <div className="mt-0.5 text-xs text-zinc-500">{healthSummary.evaluated_rules} tested in suite</div>
            </div>

            <div className="rounded-lg border border-surface-border bg-surface-inset p-3">
              <div className="text-xs font-medium text-zinc-400">Average Health Score</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-emerald-400">
                  {healthSummary.average_health_score != null ? `${healthSummary.average_health_score}` : "NO DATA"}
                </span>
                {healthSummary.average_health_score != null ? (
                  <span className="text-xs text-zinc-400">/ 100</span>
                ) : null}
              </div>
              <div className="mt-0.5 text-xs text-zinc-500">Weighted multi-factor score</div>
            </div>

            <div className="rounded-lg border border-surface-border bg-surface-inset p-3">
              <div className="text-xs font-medium text-zinc-400">Healthy / Excellent</div>
              <div className="mt-1 text-2xl font-bold text-emerald-300">
                {(healthSummary.tier_distribution["EXCELLENT"] || 0) + (healthSummary.tier_distribution["HEALTHY"] || 0)}
              </div>
              <div className="mt-0.5 text-xs text-zinc-500">Passing zero regression SLA</div>
            </div>

            <div className="rounded-lg border border-surface-border bg-surface-inset p-3">
              <div className="text-xs font-medium text-zinc-400">Degraded / Unhealthy</div>
              <div className="mt-1 text-2xl font-bold text-amber-400">
                {(healthSummary.tier_distribution["DEGRADED"] || 0) + (healthSummary.tier_distribution["UNHEALTHY"] || 0)}
              </div>
              <div className="mt-0.5 text-xs text-zinc-500">
                {healthSummary.tier_distribution["INSUFFICIENT_DATA"] || 0} unevaluated
              </div>
            </div>
          </div>
        ) : null}
      </section>

      {/* Main Grid: Rules List + Custom Rule Form */}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <section className="rounded-xl border border-surface-border bg-surface-raised">
          {/* Filter & Search Bar */}
          <div className="flex flex-col gap-3 border-b border-surface-border p-4 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
              <input
                className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset py-2 pl-9 pr-3 text-sm text-zinc-200 placeholder-zinc-500"
                placeholder="Search by rule name, rule ID, description..."
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>

            <div className="flex gap-2">
              <select
                className="focus-ring rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-xs text-zinc-300"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="ALL">All Lifecycles</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="TESTING">TESTING</option>
                <option value="DRAFT">DRAFT</option>
                <option value="DISABLED">DISABLED</option>
                <option value="DEPRECATED">DEPRECATED</option>
              </select>

              <select
                className="focus-ring rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-xs text-zinc-300"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="ALL">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          {loading ? (
            <LoadingState label="Loading detection rules and quality metrics..." />
          ) : filteredRules.length ? (
            <RuleList
              rules={filteredRules}
              healthMap={healthByRuleId}
              canEdit={can("admin")}
              evaluatingRuleId={evaluatingRuleId}
              onToggle={onToggle}
              onEvaluateSingle={onEvaluateSingle}
            />
          ) : (
            <EmptyState title="No detection rules match your criteria" />
          )}
        </section>

        {can("admin") ? <CustomRuleForm onCreated={load} /> : null}
      </div>
    </div>
  );
}

function RuleList({
  rules,
  healthMap,
  canEdit,
  evaluatingRuleId,
  onToggle,
  onEvaluateSingle,
}: {
  rules: DetectionRule[];
  healthMap: Map<number, RuleHealthRecord>;
  canEdit: boolean;
  evaluatingRuleId: number | null;
  onToggle: (rule: DetectionRule) => void;
  onEvaluateSingle: (ruleId: number) => void;
}) {
  return (
    <div className="divide-y divide-surface-border">
      {rules.map((rule) => {
        const health = healthMap.get(rule.id);
        const status = rule.status || "ACTIVE";
        const ruleIdTag = rule.rule_id || `RULE-${String(rule.id).padStart(3, "0")}`;
        const versionTag = `v${rule.version || "1.0"}`;

        return (
          <article key={rule.id} className="p-4 transition hover:bg-surface-inset/40">
            {/* Header: Rule ID, Title, Badges & Toggles */}
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-cyan-950/80 px-2 py-0.5 font-mono text-xs font-semibold text-cyan-300 border border-cyan-800/60">
                    {ruleIdTag}
                  </span>
                  <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-300">
                    {versionTag}
                  </span>
                  <StatusBadge status={status} />
                  <SeverityBadge value={rule.severity} />
                  <h2 className="text-sm font-semibold text-zinc-100">{rule.name}</h2>
                </div>

                <p className="mt-2 text-xs leading-relaxed text-zinc-400">{rule.description}</p>

                {/* Metadata tags */}
                <div className="mt-2.5 flex flex-wrap gap-2 text-xs text-zinc-400">
                  <span className="rounded bg-surface-inset px-2 py-0.5 text-zinc-400">
                    Cat: <span className="text-zinc-200">{rule.category || "web_attack"}</span>
                  </span>
                  <span className="rounded bg-surface-inset px-2 py-0.5 text-zinc-400">
                    MITRE: <span className="font-mono text-cyan-300">{rule.mitre_technique || "NOT_MAPPED"}</span>
                  </span>
                  <span className="rounded bg-surface-inset px-2 py-0.5 text-zinc-400">
                    Owner: <span className="text-zinc-300">{rule.owner || "secops-team"}</span>
                  </span>
                  <span className="rounded bg-surface-inset px-2 py-0.5 text-zinc-400">
                    Source: <span className="text-zinc-300">{rule.expected_data_source || "web_telemetry"}</span>
                  </span>
                  <span className="rounded bg-surface-inset px-2 py-0.5 text-zinc-400">
                    Confidence: <span className="text-zinc-200">{((rule.confidence ?? 0.8) * 100).toFixed(0)}%</span>
                  </span>
                </div>
              </div>

              {/* Action Controls */}
              <div className="flex items-center gap-2">
                {canEdit ? (
                  <button
                    disabled={evaluatingRuleId === rule.id}
                    onClick={() => onEvaluateSingle(rule.id)}
                    title="Run regression tests and recalculate health score"
                    className="focus-ring flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-inset px-2.5 py-1.5 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-50"
                  >
                    <Play className={`h-3.5 w-3.5 ${evaluatingRuleId === rule.id ? "animate-spin text-cyan-400" : "text-emerald-400"}`} />
                    {evaluatingRuleId === rule.id ? "Testing..." : "Test"}
                  </button>
                ) : null}

                <button
                  className="focus-ring flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-inset px-2.5 py-1.5 text-xs text-zinc-200 transition hover:bg-zinc-800"
                  disabled={!canEdit}
                  onClick={() => onToggle(rule)}
                >
                  {rule.enabled ? (
                    <ToggleRight className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <ToggleLeft className="h-4 w-4 text-zinc-500" />
                  )}
                  <span>{rule.enabled ? "Active" : "Disabled"}</span>
                </button>
              </div>
            </div>

            {/* Quality & Detection Engineering Metrics Grid */}
            <div className="mt-3.5 grid grid-cols-2 gap-2 rounded-lg border border-surface-border/70 bg-surface-inset/60 p-3 sm:grid-cols-4 lg:grid-cols-8">
              {/* Health Score */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Health Score</div>
                {health?.health_score != null ? (
                  <div className="flex items-center gap-1 font-mono text-xs font-semibold text-emerald-300">
                    <Activity className="h-3 w-3" />
                    <span>{health.health_score}</span>
                    <span className="text-[10px] text-zinc-500">/100</span>
                  </div>
                ) : (
                  <span className="font-mono text-xs text-zinc-500">NO DATA</span>
                )}
              </div>

              {/* Precision */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Precision</div>
                <div className="font-mono text-xs text-zinc-200">
                  {health?.precision != null ? `${(health.precision * 100).toFixed(1)}%` : "NO DATA"}
                </div>
              </div>

              {/* Recall */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Recall</div>
                <div className="font-mono text-xs text-zinc-200">
                  {health?.recall != null ? `${(health.recall * 100).toFixed(1)}%` : "NO DATA"}
                </div>
              </div>

              {/* F1 Score */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">F1 Score</div>
                <div className="font-mono text-xs text-zinc-200">
                  {health?.f1_score != null ? health.f1_score.toFixed(3) : "NO DATA"}
                </div>
              </div>

              {/* False Positive Rate */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">FPR</div>
                <div className="font-mono text-xs text-zinc-200">
                  {health?.false_positive_rate != null ? `${(health.false_positive_rate * 100).toFixed(1)}%` : "NO DATA"}
                </div>
              </div>

              {/* Alert Volume */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Alert Vol</div>
                <div className="font-mono text-xs text-zinc-200">{health?.alert_volume ?? 0}</div>
              </div>

              {/* Detection Latency */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Latency</div>
                <div className="font-mono text-xs text-zinc-200">
                  {health?.detection_latency_ms != null ? `${health.detection_latency_ms} ms` : "NO DATA"}
                </div>
              </div>

              {/* Regression Status */}
              <div className="space-y-0.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Regression</div>
                <div>
                  {health?.regression_status === "PASSED" ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400">
                      <CheckCircle2 className="h-3 w-3" /> PASSED
                    </span>
                  ) : health?.regression_status === "FAILED" ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-rose-400">
                      <XCircle className="h-3 w-3" /> FAILED
                    </span>
                  ) : (
                    <span className="text-[11px] text-zinc-500">UNTESTED</span>
                  )}
                </div>
              </div>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    ACTIVE: "bg-emerald-950/80 text-emerald-300 border-emerald-800/60",
    TESTING: "bg-amber-950/80 text-amber-300 border-amber-800/60",
    DRAFT: "bg-blue-950/80 text-blue-300 border-blue-800/60",
    DISABLED: "bg-zinc-900 text-zinc-400 border-zinc-700/60",
    DEPRECATED: "bg-rose-950/80 text-rose-300 border-rose-800/60",
  };
  const current = styles[status] || styles["ACTIVE"];
  return (
    <span className={`rounded border px-1.5 py-0.2 font-mono text-[10px] font-bold ${current}`}>
      {status}
    </span>
  );
}

function CustomRuleForm({ onCreated }: { onCreated: () => Promise<void> }) {
  const { notify } = useToast();
  const [form, setForm] = useState({
    rule_id: "",
    name: "",
    description: "",
    category: "web_attack",
    mitre_technique: "NOT_MAPPED",
    severity: "medium" as Severity,
    eventType: "failed_login",
    threshold: 3,
    window: 10,
  });

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      await createRule({
        rule_id: form.rule_id ? form.rule_id.toUpperCase() : undefined,
        name: form.name,
        description: form.description,
        category: form.category,
        mitre_technique: form.mitre_technique,
        severity: form.severity,
        version: "1.0",
        status: "ACTIVE",
        enabled: true,
        threshold: form.threshold,
        time_window_minutes: form.window,
        conditions_json: { type: "threshold", filters: { event_type: form.eventType }, group_by: ["source_ip"] },
      });
      notify("Custom rule created successfully", "success");
      setForm({
        rule_id: "",
        name: "",
        description: "",
        category: "web_attack",
        mitre_technique: "NOT_MAPPED",
        severity: "medium",
        eventType: "failed_login",
        threshold: 3,
        window: 10,
      });
      await onCreated();
    } catch {
      notify("Failed to create rule. Check rule ID or name uniqueness.", "error");
    }
  }

  return (
    <form onSubmit={submit} className="rounded-xl border border-surface-border bg-surface-raised p-4">
      <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-zinc-100">
        <Plus className="h-4 w-4 text-cyan-300" />
        New Detection-as-Code Rule
      </h2>
      <div className="space-y-3">
        <Input
          label="Rule ID (e.g. RULE-015)"
          value={form.rule_id}
          onChange={(rule_id) => setForm((c) => ({ ...c, rule_id }))}
        />
        <Input
          label="Rule Name"
          value={form.name}
          onChange={(name) => setForm((c) => ({ ...c, name }))}
        />
        <Input
          label="Description"
          value={form.description}
          onChange={(description) => setForm((c) => ({ ...c, description }))}
        />
        <div className="grid grid-cols-2 gap-2">
          <Input
            label="Category"
            value={form.category}
            onChange={(category) => setForm((c) => ({ ...c, category }))}
          />
          <Input
            label="MITRE (e.g. T1110)"
            value={form.mitre_technique}
            onChange={(mitre_technique) => setForm((c) => ({ ...c, mitre_technique }))}
          />
        </div>
        <Input
          label="Event Type"
          value={form.eventType}
          onChange={(eventType) => setForm((c) => ({ ...c, eventType }))}
        />
        <select
          className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm text-zinc-200"
          value={form.severity}
          onChange={(e) => setForm((c) => ({ ...c, severity: e.target.value as Severity }))}
        >
          {["low", "medium", "high", "critical"].map((severity) => (
            <option key={severity} value={severity}>
              {severity.toUpperCase()}
            </option>
          ))}
        </select>
        <div className="grid grid-cols-2 gap-3">
          <NumberInput
            label="Threshold"
            value={form.threshold}
            onChange={(threshold) => setForm((c) => ({ ...c, threshold }))}
          />
          <NumberInput
            label="Window (min)"
            value={form.window}
            onChange={(window) => setForm((c) => ({ ...c, window }))}
          />
        </div>
        <button className="focus-ring flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-500">
          <Plus className="h-4 w-4" />
          Deploy Rule
        </button>
      </div>
    </form>
  );
}

function Input({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <input
      required
      className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm text-zinc-200 placeholder-zinc-500"
      placeholder={label}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

function NumberInput({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <input
      required
      min={1}
      className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm text-zinc-200 placeholder-zinc-500"
      placeholder={label}
      type="number"
      value={value}
      onChange={(event) => onChange(Number(event.target.value))}
    />
  );
}
