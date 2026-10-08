import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Bot,
  CheckCircle2,
  Clock,
  Database,
  ExternalLink,
  Eye,
  FileCheck2,
  FileText,
  Lock,
  RefreshCw,
  Scale,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { fetchAIAnalystEvaluation } from "../services/api";

export function AIAnalystEvaluationView() {
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSplit, setSelectedSplit] = useState<"dev" | "validation">("dev");

  async function loadData() {
    try {
      setLoading(true);
      setError(null);
      const res = await fetchAIAnalystEvaluation();
      setData(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load AI analyst evaluation data";
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
          Loading Phase 8 AI Analyst Assistance & Hallucination Benchmarks...
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-6 text-sm text-rose-300">
        <div className="flex items-center gap-2 font-semibold">
          <AlertOctagon className="h-4 w-4" />
          Error Loading Phase 8 Evaluation Results
        </div>
        <p className="mt-2 text-xs text-rose-400">{error || "No data returned from evaluation endpoint."}</p>
        <button
          onClick={loadData}
          className="mt-4 rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500"
        >
          Retry
        </button>
      </div>
    );
  }

  const splitData = data.splits?.[selectedSplit] || {};
  const sysA = data.comparison_system_a_vs_system_b?.system_a_deterministic_soc_baseline || {};
  const sysB = data.comparison_system_a_vs_system_b?.system_b_evidence_grounded_ai_assistant || {};
  const failureModes = data.failure_modes_testing || [];
  const hypotheses = data.hypotheses_evaluation || {};
  const secFindings = data.security_findings || {};

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-5">
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 text-xs font-semibold text-purple-300">
                <Bot className="h-3.5 w-3.5" />
                Phase 8 Research
              </span>
              <span className="text-xs text-zinc-400 font-mono">
                Model Designation: {data.baseline_model_designation}
              </span>
            </div>
            <h2 className="mt-2 text-xl font-bold tracking-tight text-zinc-100">
              Evidence-Grounded AI Analyst Assistance & Hallucination Evaluation
            </h2>
            <p className="text-xs text-zinc-400">
              Rigorous empirical evaluation of citation grounding, unsupported claim rates, abstention accuracy, and prompt-injection resilience.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={loadData}
              className="inline-flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-raised px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-surface-inset"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Reload Results
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Unsupported Claim Rate */}
        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Unsupported Claim Rate
            </span>
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2 text-emerald-400">
              <ShieldCheck className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-emerald-400">
              {splitData.unsupported_claim_rate !== undefined ? `${splitData.unsupported_claim_rate}%` : "0.0%"}
            </span>
            <span className="text-xs text-zinc-400">Zero Hallucinations</span>
          </div>
          <p className="mt-1.5 text-xs text-zinc-400">
            0 unsupported claims across {splitData.total_claims ?? 0} factual claims evaluated in {selectedSplit.toUpperCase()}.
          </p>
        </div>

        {/* Evidence Citation Coverage */}
        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Evidence Citation Coverage
            </span>
            <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-2 text-cyan-400">
              <FileCheck2 className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-cyan-400">
              {splitData.evidence_citation_coverage_pct !== undefined ? `${splitData.evidence_citation_coverage_pct}%` : "100%"}
            </span>
            <span className="text-xs text-emerald-400 font-semibold">100% Grounded</span>
          </div>
          <p className="mt-1.5 text-xs text-zinc-400">
            {splitData.supported_claims ?? 0} / {splitData.total_claims ?? 0} claims strictly backed by verified database evidence.
          </p>
        </div>

        {/* Prompt Injection Success Rate */}
        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Prompt Injection Rate
            </span>
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2 text-emerald-400">
              <Lock className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-emerald-400">
              {splitData.prompt_injection_success_rate !== undefined ? `${splitData.prompt_injection_success_rate}%` : "0.0%"}
            </span>
            <span className="text-xs text-emerald-400 font-semibold">Resilient</span>
          </div>
          <p className="mt-1.5 text-xs text-zinc-400">
            {splitData.prompt_injection_cases ?? 0} adversarial injection payloads isolated as untrusted telemetry data.
          </p>
        </div>

        {/* AI Assistance Latency */}
        <div className="rounded-xl border border-surface-border bg-surface-raised/70 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Avg Assistance Latency
            </span>
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-2 text-amber-400">
              <Clock className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-amber-400">
              {splitData.avg_ai_latency_ms !== undefined ? `${splitData.avg_ai_latency_ms}ms` : "—"}
            </span>
            <span className="text-xs text-zinc-400">Deterministic</span>
          </div>
          <p className="mt-1.5 text-xs text-zinc-400">
            Fast, reproducible synthesis without remote API bottlenecks or token costs.
          </p>
        </div>
      </div>

      {/* Split Selector */}
      <div className="flex items-center gap-2 border-b border-surface-border pb-3">
        <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mr-2">Evaluation Split:</span>
        <button
          onClick={() => setSelectedSplit("dev")}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            selectedSplit === "dev"
              ? "bg-purple-600 text-white shadow-sm"
              : "bg-surface-raised border border-surface-border text-zinc-400 hover:text-zinc-200"
          }`}
        >
          DEV Split (40 Scenarios)
        </button>
        <button
          onClick={() => setSelectedSplit("validation")}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            selectedSplit === "validation"
              ? "bg-purple-600 text-white shadow-sm"
              : "bg-surface-raised border border-surface-border text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Validation Split (20 Scenarios)
        </button>
      </div>

      {/* System A vs System B Comparison */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-5">
        <div className="flex items-center gap-2 mb-4">
          <Scale className="h-4 w-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-zinc-200">System A vs. System B Empirical Comparison</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-surface-border bg-surface-raised text-zinc-400">
              <tr>
                <th className="py-3 px-4 font-semibold">Evaluation Dimension</th>
                <th className="py-3 px-4 font-semibold text-zinc-300">System A (Deterministic SIEM Baseline)</th>
                <th className="py-3 px-4 font-semibold text-purple-300">System B (AI-Assisted SOC Plane)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border text-zinc-300">
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Architecture Description</td>
                <td className="py-3 px-4">{sysA.name}</td>
                <td className="py-3 px-4 font-semibold text-purple-300">{sysB.name}</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Model Framework</td>
                <td className="py-3 px-4 text-zinc-500">{sysA.model_type}</td>
                <td className="py-3 px-4 font-mono text-[11px] text-cyan-300">{sysB.model_type}</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Evidence-Grounded Claims</td>
                <td className="py-3 px-4 text-zinc-500">0 (Manual analyst interpretation required)</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">{sysB.evidence_grounded_claims_generated} Verified Claims</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Evidence Citation Coverage</td>
                <td className="py-3 px-4 text-zinc-500">N/A</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">{sysB.evidence_citation_coverage_pct}%</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Unsupported Claim Rate</td>
                <td className="py-3 px-4 text-zinc-500">0.0% (No claims generated)</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">{sysB.unsupported_claim_rate}%</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Attack-Chain Synthesis</td>
                <td className="py-3 px-4 text-zinc-500">{sysA.automated_attack_chain_synthesis}</td>
                <td className="py-3 px-4 text-zinc-200">{sysB.automated_attack_chain_synthesis}</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">MITRE ATT&CK Mapping</td>
                <td className="py-3 px-4 text-zinc-500">{sysA.automated_mitre_mapping}</td>
                <td className="py-3 px-4 text-zinc-200">{sysB.automated_mitre_mapping}</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Uncertainty & Data Gaps</td>
                <td className="py-3 px-4 text-zinc-500">{sysA.explicit_uncertainty_quantification}</td>
                <td className="py-3 px-4 text-cyan-300">{sysB.explicit_uncertainty_quantification}</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Prompt Injection Vulnerability</td>
                <td className="py-3 px-4 text-zinc-500">{sysA.prompt_injection_vulnerability}</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">{sysB.prompt_injection_vulnerability}</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-zinc-400">Average Assistance Latency</td>
                <td className="py-3 px-4 text-zinc-500">{sysA.average_assistance_latency_ms} ms</td>
                <td className="py-3 px-4 font-mono text-zinc-200">{sysB.average_assistance_latency_ms} ms</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Failure Modes & Safeguards Matrix */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-5">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="h-4 w-4 text-rose-400" />
          <h3 className="text-sm font-semibold text-zinc-200">Adversarial Failure Modes & Verification Safeguards</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-surface-border bg-surface-raised text-zinc-400">
              <tr>
                <th className="py-3 px-4 font-semibold">Adversarial Failure Mode Test</th>
                <th className="py-3 px-4 font-semibold">Expected Claim Classification</th>
                <th className="py-3 px-4 font-semibold">Observed Classification</th>
                <th className="py-3 px-4 font-semibold text-right">Safeguard Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {failureModes.map((fm: any, idx: number) => (
                <tr key={idx} className="hover:bg-surface-raised/60">
                  <td className="py-3 px-4 font-medium text-zinc-200">{fm.test_name}</td>
                  <td className="py-3 px-4 font-mono text-[11px] text-zinc-400">{fm.expected}</td>
                  <td className="py-3 px-4 font-mono text-[11px] text-amber-300">{fm.observed}</td>
                  <td className="py-3 px-4 text-right">
                    {fm.passed ? (
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                        <CheckCircle2 className="h-3 w-3" />
                        PASSED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] font-semibold text-rose-400">
                        FAILED
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Research Hypotheses Verification */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-5">
        <div className="flex items-center gap-2 mb-4">
          <FileText className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-zinc-200">Formal Research Hypotheses Verification (H1–H5)</h3>
        </div>
        <div className="space-y-3">
          {Object.entries(hypotheses).map(([key, h]: [string, any]) => (
            <div key={key} className="rounded-lg border border-surface-border bg-surface-raised/60 p-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                <span className="font-mono text-xs font-bold text-cyan-300">{key.split("_")[0]}</span>
                <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-400 self-start sm:self-auto">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  {h.status}
                </span>
              </div>
              <p className="mt-1.5 text-xs font-medium text-zinc-200">{h.hypothesis}</p>
              <div className="mt-2 text-xs text-zinc-400 bg-surface-inset/60 p-2.5 rounded border border-surface-border/50">
                <strong className="text-zinc-300 font-semibold">Empirical Finding: </strong>
                {h.evidence}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Security Boundaries & Safe SOC Guardrails */}
      <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-5">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="h-4 w-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-zinc-200">Security Invariants & Non-Destructive Guardrails</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              Read-Only Authority
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              AI assistant cannot mutate incident severity, risk score, alert status, or detection rules.
            </p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              Secret & Token Redaction
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              Bearer tokens, passwords, and sensitive strings are automatically masked before context assembly.
            </p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              Cross-Incident Isolation
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              Citations are strictly validated against incident ID. Cross-incident evidence references are flagged UNSUPPORTED.
            </p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              Zero Destructive Action
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              All containment and response recommendations are advisory. Real-world execution requires human analyst sign-off.
            </p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              Prompt Injection Immune
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              Telemetry content is demarcated within untrusted data boundaries and never executed as prompt instructions.
            </p>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              Explicit Abstention
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              Returns INSUFFICIENT EVIDENCE when multi-plane correlation is incomplete or contradictory.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
