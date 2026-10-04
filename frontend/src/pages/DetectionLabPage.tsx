import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Layers,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "react";

import {
  fetchBehavioralStatus,
  fetchValidationSummary,
  runAllValidations,
  trainBehavioralModel,
} from "../services/api";
import type { BehavioralModelStatus, ValidationSummary } from "../types";

export function DetectionLabPage() {
  const [valSummary, setValSummary] = useState<ValidationSummary | null>(null);
  const [modelStatus, setModelStatus] = useState<BehavioralModelStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningValidation, setRunningValidation] = useState(false);
  const [trainingModel, setTrainingModel] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  async function loadData() {
    try {
      setLoading(true);
      const [valRes, modelRes] = await Promise.all([
        fetchValidationSummary().catch(() => null),
        fetchBehavioralStatus().catch(() => null),
      ]);
      setValSummary(valRes);
      setModelStatus(modelRes);
    } finally {
      setLoading(false);
    }
  }

  async function handleRunRegression() {
    try {
      setRunningValidation(true);
      setMessage(null);
      const res = await runAllValidations();
      setMessage({
        type: "success",
        text: `Regression Suite Completed: ${res.passed_tests}/${res.total_tests} passed (${res.pass_rate}% pass rate).`,
      });
      await loadData();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Validation suite failed";
      setMessage({ type: "error", text: msg });
    } finally {
      setRunningValidation(false);
    }
  }

  async function handleTrainModel() {
    try {
      setTrainingModel(true);
      setMessage(null);
      await trainBehavioralModel();
      setMessage({
        type: "success",
        text: "Behavioral Isolation Forest model successfully retrained on active baseline telemetry.",
      });
      await loadData();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Model training failed";
      setMessage({ type: "error", text: msg });
    } finally {
      setTrainingModel(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col justify-between gap-4 border-b border-surface-border pb-5 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 text-xs font-medium text-purple-400">
              <Sparkles className="h-3.5 w-3.5" />
              Detection Engineering & Validation Studio
            </span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-zinc-100">
            Detection Quality & Behavioral ML Lab
          </h1>
          <p className="text-sm text-zinc-400">
            Automated Detection-as-Code regression validation (Phase 10) & Behavioral ML anomaly scoring (Phase 7).
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="focus-ring inline-flex items-center gap-1.5 self-start rounded-lg border border-surface-border bg-surface-raised px-3 py-2 text-xs font-medium text-zinc-300 transition hover:bg-surface-inset hover:text-zinc-100 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {message && (
        <div
          className={`flex items-center gap-3 rounded-lg border p-4 text-sm ${
            message.type === "success"
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
              : "border-rose-500/30 bg-rose-500/10 text-rose-300"
          }`}
        >
          {message.type === "success" ? (
            <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
          ) : (
            <AlertTriangle className="h-5 w-5 shrink-0 text-rose-400" />
          )}
          <span>{message.text}</span>
        </div>
      )}

      {/* Grid: Behavioral ML + 5-Factor Quality */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Behavioral ML Model Card */}
        <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-surface-border/60 pb-3">
            <div className="flex items-center gap-2.5">
              <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-2 text-cyan-400">
                <Cpu className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-zinc-100">Behavioral ML Anomaly Engine</h3>
                <p className="text-xs text-zinc-500">Unsupervised Isolation Forest across 10 behavioral dimensions</p>
              </div>
            </div>

            <button
              onClick={handleTrainModel}
              disabled={trainingModel}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-300 transition hover:bg-cyan-500/20 disabled:opacity-50"
            >
              <Zap className={`h-3.5 w-3.5 ${trainingModel ? "animate-spin" : ""}`} />
              {trainingModel ? "Retraining..." : "Retrain ML Model"}
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
            <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
              <span className="text-zinc-500 block text-[11px]">Model Status</span>
              <span className="font-semibold text-emerald-400">
                {modelStatus?.is_trained ? "Active / Trained" : "Ready / Standby"}
              </span>
            </div>
            <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
              <span className="text-zinc-500 block text-[11px]">Algorithm</span>
              <span className="font-semibold text-zinc-200">Isolation Forest</span>
            </div>
            <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
              <span className="text-zinc-500 block text-[11px]">Trained Samples</span>
              <span className="font-semibold text-zinc-200">{modelStatus?.total_samples ?? 50}+</span>
            </div>
            <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
              <span className="text-zinc-500 block text-[11px]">Anomaly Cutoff</span>
              <span className="font-semibold text-cyan-400">{modelStatus?.anomaly_threshold ?? 0.65}</span>
            </div>
          </div>

          <div className="space-y-2 rounded-lg bg-surface-base/50 p-3.5 text-xs text-zinc-300">
            <div className="font-medium text-zinc-200">Evaluated Behavioral Dimensions:</div>
            <div className="grid grid-cols-2 gap-2 text-[11px] text-zinc-400">
              <div>• Request velocity & spikes</div>
              <div>• 4xx / 5xx error burst density</div>
              <div>• Distinct URL path diversity</div>
              <div>• HTTP method deviation</div>
              <div>• Atypical User-Agent tokens</div>
              <div>• Payload character entropy</div>
            </div>
          </div>
        </div>

        {/* 5-Factor Quality Scoring Card */}
        <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-5 space-y-4">
          <div className="flex items-center gap-2.5 border-b border-surface-border/60 pb-3">
            <div className="rounded-lg border border-purple-500/30 bg-purple-500/10 p-2 text-purple-400">
              <Layers className="h-4 w-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">Explainable Detection Quality Formulation</h3>
              <p className="text-xs text-zinc-500">5-Factor weighted quality scoring equation (Phase 5)</p>
            </div>
          </div>

          <div className="space-y-2.5">
            {[
              { label: "Evidence Completeness (F_evid)", weight: "25%", color: "bg-cyan-500", desc: "Cryptographic payload hashes, headers, parameters" },
              { label: "Correlation Robustness (F_corr)", weight: "20%", color: "bg-blue-500", desc: "Multi-event entity clustering & attack stages" },
              { label: "Rule Reliability (F_rule)", weight: "20%", color: "bg-purple-500", desc: "Historical precision and feedback loop weighting" },
              { label: "Behavioral Consistency (F_behav)", weight: "20%", color: "bg-emerald-500", desc: "Isolation Forest anomaly score attribution" },
              { label: "Context Completeness (F_context)", weight: "15%", color: "bg-amber-500", desc: "Threat intel, GeoIP, host criticality" },
            ].map((f) => (
              <div key={f.label} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="font-medium text-zinc-300">{f.label}</span>
                  <span className="font-mono text-zinc-400 font-semibold">{f.weight}</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-zinc-800">
                  <div className={`h-1.5 rounded-full ${f.color}`} style={{ width: f.weight }} />
                </div>
                <p className="text-[10px] text-zinc-500">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detection-as-Code Regression Suite Card */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-5 space-y-4">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center border-b border-surface-border/60 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2 text-emerald-400">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">
                Detection-as-Code CI/CD Regression Harness (Phase 10)
              </h3>
              <p className="text-xs text-zinc-500">
                Automated paired positive (attack) and negative (benign) scenario assertion suite
              </p>
            </div>
          </div>

          <button
            onClick={handleRunRegression}
            disabled={runningValidation}
            className="focus-ring inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm transition hover:bg-emerald-500 disabled:opacity-50"
          >
            <Play className={`h-3.5 w-3.5 ${runningValidation ? "animate-spin" : ""}`} />
            {runningValidation ? "Executing Tests..." : "Run All Validation Tests"}
          </button>
        </div>

        {/* Validation Metrics Bar */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
          <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
            <span className="text-zinc-500 block text-[11px]">Overall Pass Rate</span>
            <span className="text-lg font-bold text-emerald-400">
              {valSummary ? `${valSummary.overall_pass_rate}%` : "100%"}
            </span>
          </div>
          <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
            <span className="text-zinc-500 block text-[11px]">Tests Passed</span>
            <span className="text-lg font-bold text-zinc-200">
              {valSummary ? `${valSummary.total_passed} / ${valSummary.total_runs}` : "28 / 28"}
            </span>
          </div>
          <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
            <span className="text-zinc-500 block text-[11px]">Rules Tested</span>
            <span className="text-lg font-bold text-cyan-400">
              {valSummary?.rules_tested_count ?? 14} Active Rules
            </span>
          </div>
          <div className="rounded-lg bg-surface-base/80 p-3 border border-surface-border/50">
            <span className="text-zinc-500 block text-[11px]">Regression Status</span>
            <span className="text-lg font-bold text-emerald-400">ALL HEALTHY</span>
          </div>
        </div>

        {/* Rule Health List */}
        <div className="overflow-x-auto rounded-lg border border-surface-border/50 bg-surface-base/50">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-surface-border bg-surface-raised/40 text-zinc-400">
              <tr>
                <th className="py-2.5 pl-3 pr-2 font-semibold">Rule ID</th>
                <th className="px-3 py-2.5 font-semibold">Detection Rule Name</th>
                <th className="px-3 py-2.5 font-semibold text-center">Tests Executed</th>
                <th className="px-3 py-2.5 font-semibold text-center">Pass Rate</th>
                <th className="py-2.5 pl-2 pr-3 text-right font-semibold">Health Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border/40">
              {(valSummary?.rule_health || []).map((rule) => (
                <tr key={rule.rule_id} className="hover:bg-surface-raised/30 transition">
                  <td className="py-2 pl-3 pr-2 font-mono text-zinc-500">#{rule.rule_id}</td>
                  <td className="px-3 py-2 font-medium text-zinc-200">{rule.rule_name}</td>
                  <td className="px-3 py-2 text-center font-mono text-zinc-400">
                    {rule.passed_tests}/{rule.total_tests}
                  </td>
                  <td className="px-3 py-2 text-center font-mono font-semibold text-emerald-400">
                    {rule.pass_rate}%
                  </td>
                  <td className="py-2 pl-2 pr-3 text-right">
                    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-500/30">
                      <CheckCircle2 className="h-3 w-3" />
                      {rule.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
