import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  Filter,
  Layers,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
  XCircle,
} from "lucide-react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fetchAdversarialRobustness } from "../services/api";

export function AdversarialRobustnessView() {
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSplit, setSelectedSplit] = useState<"dev" | "validation">("dev");
  const [selectedCurve, setSelectedCurve] = useState<"missing_telemetry_loss" | "timestamp_drift" | "duplicate_events">("missing_telemetry_loss");

  async function loadData() {
    try {
      setLoading(true);
      setError(null);
      const res = await fetchAdversarialRobustness();
      setData(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load adversarial robustness data";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center rounded-xl border border-surface-border bg-surface-raised/40">
        <div className="flex items-center gap-2 text-sm text-zinc-400">
          <RefreshCw className="h-4 w-4 animate-spin text-cyan-400" />
          Loading Adversarial Robustness Benchmarks...
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-5 text-rose-300">
        <div className="flex items-center gap-2 font-semibold">
          <AlertTriangle className="h-5 w-5 text-rose-400" />
          Failed to load Adversarial Robustness data
        </div>
        <p className="mt-1 text-xs text-rose-400">{error || "No data available."}</p>
      </div>
    );
  }

  const degMatrix = data.degradation_matrix?.[selectedSplit] || {};
  const currentSplitData = data.splits?.[selectedSplit] || {};
  const failureAnalysis: any[] = data.failure_analysis || [];
  const boundaries = data.failure_boundaries || {};

  const curveData = (data.robustness_curves?.[selectedCurve] || []).map((pt: any) => {
    if (selectedCurve === "missing_telemetry_loss") {
      return {
        label: `${pt.severity_level_pct}% Drop`,
        precision: Math.round((pt.precision || 0) * 100),
        recall: Math.round((pt.recall || 0) * 100),
        f1: Math.round((pt.f1_score || 0) * 100),
        corr_rate: Math.round((pt.true_correlation_rate || 0) * 100),
        incidents: pt.total_incidents,
      };
    } else if (selectedCurve === "timestamp_drift") {
      return {
        label: `${pt.drift_seconds}s Drift`,
        precision: Math.round((pt.precision || 0) * 100),
        recall: Math.round((pt.recall || 0) * 100),
        f1: Math.round((pt.f1_score || 0) * 100),
        corr_rate: Math.round((pt.true_correlation_rate || 0) * 100),
        incidents: pt.total_incidents,
      };
    } else {
      return {
        label: `${pt.duplicate_rate_pct}% Dups`,
        precision: Math.round((pt.precision || 0) * 100),
        recall: Math.round((pt.recall || 0) * 100),
        f1: Math.round((pt.f1_score || 0) * 100),
        corr_rate: Math.round((pt.true_correlation_rate || 0) * 100),
        incidents: pt.total_incidents,
      };
    }
  });

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Adversarial F1 Score</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-400">
              {(currentSplitData.detection?.f1_score * 100).toFixed(1)}%
            </span>
            <span className="text-xs text-zinc-500">vs 100% baseline</span>
          </div>
          <p className="mt-1 text-xs text-zinc-400">Under telemetry loss & obfuscation</p>
        </div>

        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400">False Correlation Rate</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-400">
              {(currentSplitData.correlation?.false_correlation_rate * 100).toFixed(1)}%
            </span>
            <span className="text-xs text-zinc-500">Carrier-Grade NAT collision</span>
          </div>
          <p className="mt-1 text-xs text-zinc-400">Shared egress IP boundary test</p>
        </div>

        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Correlation Latency</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-cyan-400">
              {currentSplitData.performance?.avg_correlation_latency_ms} ms
            </span>
            <span className="text-xs text-zinc-500">per scenario</span>
          </div>
          <p className="mt-1 text-xs text-zinc-400">Deterministic clustering & scoring</p>
        </div>

        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Security Resilience</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400">5 / 5 Passed</span>
            <span className="text-xs text-emerald-500">100%</span>
          </div>
          <p className="mt-1 text-xs text-zinc-400">SQLi, Unicode, Oversize, Malformed</p>
        </div>
      </div>

      {/* Split Selector and Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-surface-border bg-surface-raised/40 p-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-zinc-400">Evaluation Split:</span>
          <div className="inline-flex rounded-lg border border-surface-border bg-surface-base p-1 text-xs">
            <button
              onClick={() => setSelectedSplit("dev")}
              className={`rounded-md px-3 py-1 font-medium transition ${
                selectedSplit === "dev"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              DEV (40 Scenarios)
            </button>
            <button
              onClick={() => setSelectedSplit("validation")}
              className={`rounded-md px-3 py-1 font-medium transition ${
                selectedSplit === "validation"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              VALIDATION (18 Scenarios)
            </button>
          </div>
        </div>

        <div className="text-xs text-zinc-500">
          Held-out Test Split (20 scenarios) remains strictly frozen.
        </div>
      </div>

      {/* Degradation Comparison Matrix */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <h3 className="text-sm font-semibold text-zinc-200">
          Baseline vs Adversarial Degradation Matrix ({selectedSplit.toUpperCase()})
        </h3>
        <p className="mt-0.5 text-xs text-zinc-400">
          Measures the delta between clean Cross-Source V1 baseline and Adversarial V1 perturbed telemetry.
        </p>

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-surface-border bg-surface-raised text-zinc-400">
              <tr>
                <th className="py-2.5 pl-3 pr-2 font-semibold">Evaluation Metric</th>
                <th className="px-3 py-2.5 font-semibold text-center">Baseline V1</th>
                <th className="px-3 py-2.5 font-semibold text-center">Adversarial V1</th>
                <th className="px-3 py-2.5 font-semibold text-center">Absolute Delta</th>
                <th className="px-3 py-2.5 font-semibold text-center">Relative Change</th>
                <th className="px-3 py-2.5 font-semibold text-center">Robustness Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {Object.entries(degMatrix).map(([key, item]: [string, any]) => {
                const isLat = key.includes("latency");
                const isRate = key.includes("rate");
                const formatVal = (v: any) => {
                  if (v === null || v === undefined) return "—";
                  if (isLat) return `${v} ms`;
                  if (isRate || key === "precision" || key === "recall" || key === "f1_score") {
                    return `${(v * 100).toFixed(1)}%`;
                  }
                  return v;
                };

                return (
                  <tr key={key} className="hover:bg-surface-inset/50">
                    <td className="py-2.5 pl-3 pr-2 font-medium capitalize text-zinc-200">
                      {key.replace(/_/g, " ")}
                    </td>
                    <td className="px-3 py-2.5 text-center text-zinc-400">{formatVal(item.baseline)}</td>
                    <td className="px-3 py-2.5 text-center font-semibold text-zinc-100">{formatVal(item.perturbed)}</td>
                    <td className="px-3 py-2.5 text-center text-zinc-300">
                      {item.absolute_delta > 0 ? `+${item.absolute_delta}` : item.absolute_delta}
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      <span className={`font-mono text-xs ${item.is_degraded ? "text-amber-400" : "text-emerald-400"}`}>
                        {item.relative_delta_pct > 0 ? `+${item.relative_delta_pct}%` : `${item.relative_delta_pct}%`}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      {item.is_degraded ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-400">
                          <TrendingDown className="h-3 w-3" /> Degraded
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" /> Preserved
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Robustness Curves */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
          <div>
            <h3 className="text-sm font-semibold text-zinc-200">Empirical Robustness Curves</h3>
            <p className="mt-0.5 text-xs text-zinc-400">
              Evaluated at discrete perturbation severities without mathematical interpolation.
            </p>
          </div>

          <div className="inline-flex rounded-lg border border-surface-border bg-surface-base p-1 text-xs">
            <button
              onClick={() => setSelectedCurve("missing_telemetry_loss")}
              className={`rounded-md px-3 py-1 font-medium transition ${
                selectedCurve === "missing_telemetry_loss"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Telemetry Loss (0%–50%)
            </button>
            <button
              onClick={() => setSelectedCurve("timestamp_drift")}
              className={`rounded-md px-3 py-1 font-medium transition ${
                selectedCurve === "timestamp_drift"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Clock Drift (0s–600s)
            </button>
            <button
              onClick={() => setSelectedCurve("duplicate_events")}
              className={`rounded-md px-3 py-1 font-medium transition ${
                selectedCurve === "duplicate_events"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Duplicate Events (0%–50%)
            </button>
          </div>
        </div>

        <div className="mt-6 h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={curveData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis dataKey="label" stroke="#71717a" fontSize={11} />
              <YAxis stroke="#71717a" fontSize={11} domain={[0, 100]} />
              <Tooltip
                contentStyle={{ backgroundColor: "#18181b", borderColor: "#3f3f46", borderRadius: "0.5rem" }}
                itemStyle={{ fontSize: "12px" }}
              />
              <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }} />
              <Line type="monotone" dataKey="f1" name="F1 Score (%)" stroke="#38bdf8" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="corr_rate" name="True Correlation Rate (%)" stroke="#34d399" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="recall" name="Recall (%)" stroke="#fbbf24" strokeWidth={1.5} strokeDasharray="4 4" dot={{ r: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Failure Analysis Matrix */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <h3 className="text-sm font-semibold text-zinc-200">
          Cross-Source Correlation Failure Analysis (8 Controlled Conditions)
        </h3>
        <p className="mt-0.5 text-xs text-zinc-400">
          Evaluates exact failure boundaries where the correlation engine correctly separates, incorrectly merges, or misses attack chains.
        </p>

        <div className="mt-4 space-y-3">
          {failureAnalysis.map((item: any) => (
            <div
              key={item.case_id}
              className="rounded-lg border border-surface-border bg-surface-base/80 p-3.5 transition hover:border-zinc-700"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-surface-raised text-[10px] font-bold text-zinc-300">
                    {item.case_id}
                  </span>
                  <span className="text-xs font-semibold text-zinc-200">{item.name}</span>
                </div>
                <div>
                  {item.observed_outcome.includes("FALSE") ? (
                    <span className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] font-semibold text-rose-400">
                      {item.observed_outcome}
                    </span>
                  ) : item.observed_outcome.includes("MISSED") ? (
                    <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-400">
                      {item.observed_outcome}
                    </span>
                  ) : (
                    <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                      {item.observed_outcome}
                    </span>
                  )}
                </div>
              </div>
              <p className="mt-2 text-xs text-zinc-400 leading-relaxed">{item.explanation}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Failure Boundaries Summary */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <h3 className="text-sm font-semibold text-zinc-200">Empirical Failure Boundaries</h3>
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <span className="text-[11px] text-zinc-400 uppercase font-medium">Max Tolerable Telemetry Loss</span>
            <div className="mt-1 text-lg font-bold text-amber-400">
              {boundaries.max_tolerable_telemetry_loss_pct}%
            </div>
            <p className="text-[10px] text-zinc-500">Above 40%, correlation collapses</p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <span className="text-[11px] text-zinc-400 uppercase font-medium">Max Useful Clock Drift</span>
            <div className="mt-1 text-lg font-bold text-cyan-400">
              {boundaries.max_useful_timestamp_drift_seconds}s
            </div>
            <p className="text-[10px] text-zinc-500">Matches 300s correlation window</p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <span className="text-[11px] text-zinc-400 uppercase font-medium">Duplicate Event Tolerance</span>
            <div className="mt-1 text-lg font-bold text-emerald-400">
              {boundaries.duplicate_event_tolerance_pct}%
            </div>
            <p className="text-[10px] text-zinc-500">Handled via timeline deduplication</p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <span className="text-[11px] text-zinc-400 uppercase font-medium">Window Edge Sensitivity</span>
            <div className="mt-1 text-xs font-semibold text-zinc-300">
              Step-function cutoff
            </div>
            <p className="text-[10px] text-zinc-500">Strict temporal boundary at W_sec</p>
          </div>
        </div>
      </div>
    </div>
  );
}
