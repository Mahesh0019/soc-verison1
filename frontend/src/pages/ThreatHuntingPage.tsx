import {
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  Crosshair,
  Database,
  ExternalLink,
  FileCode,
  GitBranch,
  History,
  Layers,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "react";

import {
  executeThreatHunt,
  fetchCandidateRules,
  fetchDetectionCoverageMatrix,
  fetchDetectionGaps,
  fetchThreatHuntingMetrics,
  fetchThreatHunts,
  generateCandidateRule,
  generateDetectionGap,
  runCandidateRegression,
  transitionCandidateRule,
  validateCandidateRule,
} from "../services/api";

type TabMode = "hunts" | "gaps" | "lifecycle" | "coverage";

export function ThreatHuntingPage() {
  const [activeTab, setActiveTab] = useState<TabMode>("hunts");
  const [hunts, setHunts] = useState<any[]>([]);
  const [selectedHunt, setSelectedHunt] = useState<any | null>(null);
  const [gaps, setGaps] = useState<any[]>([]);
  const [candidates, setCandidates] = useState<any[]>([]);
  const [coverage, setCoverage] = useState<any | null>(null);
  const [metrics, setMetrics] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [executing, setExecuting] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [huntsRes, gapsRes, candRes, covRes, metRes] = await Promise.all([
        fetchThreatHunts(),
        fetchDetectionGaps(),
        fetchCandidateRules(),
        fetchDetectionCoverageMatrix(),
        fetchThreatHuntingMetrics(),
      ]);
      setHunts(huntsRes);
      if (huntsRes.length > 0 && !selectedHunt) {
        setSelectedHunt(huntsRes[0]);
      }
      setGaps(gapsRes);
      setCandidates(candRes);
      setCoverage(covRes);
      setMetrics(metRes);
    } catch (err: any) {
      console.error("Failed to load threat hunting data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleExecuteHunt = async (huntId: string) => {
    setExecuting(true);
    setActionMessage(null);
    try {
      const res = await executeThreatHunt(huntId);
      setActionMessage(`Hunt executed: Result=${res.result}, Classification=${res.classification}`);
      await loadData();
      const updated = hunts.find((h) => h.hunt_id === huntId);
      if (updated) setSelectedHunt(updated);
    } catch (err: any) {
      setActionMessage(`Execution failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setExecuting(false);
    }
  };

  const handleGenerateGap = async (huntId: string) => {
    try {
      await generateDetectionGap(huntId);
      setActionMessage(`Detection gap created for hunt ${huntId}`);
      await loadData();
      setActiveTab("gaps");
    } catch (err: any) {
      setActionMessage(`Failed to create gap: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleGenerateCandidate = async (gapId: string) => {
    try {
      await generateCandidateRule(gapId);
      setActionMessage(`Candidate rule created in status DRAFT for gap ${gapId}`);
      await loadData();
      setActiveTab("lifecycle");
    } catch (err: any) {
      setActionMessage(`Failed to create candidate: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleValidateCandidate = async (candidateId: string) => {
    try {
      const res = await validateCandidateRule(candidateId);
      setActionMessage(`Quality Gate evaluated for ${candidateId}: ${res.passed ? "PASSED" : "FAILED"} (Precision: ${res.precision}, Recall: ${res.recall}, FPR: ${res.fpr})`);
      await loadData();
    } catch (err: any) {
      setActionMessage(`Validation failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleRegressionCheck = async (candidateId: string) => {
    try {
      const res = await runCandidateRegression(candidateId);
      setActionMessage(`Regression check for ${candidateId}: ${res.status} (TP delta: +${res.tp_delta}, FP delta: ${res.fp_delta}, F1 delta: +${res.f1_delta})`);
      await loadData();
    } catch (err: any) {
      setActionMessage(`Regression check failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleTransitionLifecycle = async (candidateId: string, targetStatus: string, reason: string) => {
    try {
      await transitionCandidateRule(candidateId, targetStatus, reason);
      setActionMessage(`Candidate rule ${candidateId} transitioned to ${targetStatus}`);
      await loadData();
    } catch (err: any) {
      setActionMessage(`Transition failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header with Title and Quality Metrics */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Crosshair className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl font-bold tracking-tight text-zinc-50">
              Threat Hunting & Detection Engineering
            </h1>
          </div>
          <p className="mt-1 text-sm text-zinc-400">
            Closed-loop detection engineering: Telemetry &rarr; Hunt &rarr; Gap &rarr; Candidate &rarr; Quality Gate &rarr; Versioned Rule &rarr; Regression Protection.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="focus-ring flex items-center gap-2 rounded-lg border border-surface-border bg-surface-raised px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Workspace
        </button>
      </div>

      {/* Metrics Banner */}
      {metrics && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-3">
            <div className="text-xs font-medium text-zinc-400">Hunt Precision</div>
            <div className="mt-1 text-lg font-bold text-cyan-300">
              {(metrics.hunt_precision * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-zinc-500">Confirmed / Positives</div>
          </div>
          <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-3">
            <div className="text-xs font-medium text-zinc-400">Gap Yield</div>
            <div className="mt-1 text-lg font-bold text-emerald-300">
              {(metrics.detection_gap_yield * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-zinc-500">Gaps / Completed Hunts</div>
          </div>
          <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-3">
            <div className="text-xs font-medium text-zinc-400">Acceptance Rate</div>
            <div className="mt-1 text-lg font-bold text-indigo-300">
              {(metrics.candidate_acceptance_rate * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-zinc-500">Active / Generated</div>
          </div>
          <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-3">
            <div className="text-xs font-medium text-zinc-400">False Lead Rate</div>
            <div className="mt-1 text-lg font-bold text-amber-300">
              {(metrics.false_lead_rate * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-zinc-500">Benign Lookalikes</div>
          </div>
          <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-3">
            <div className="text-xs font-medium text-zinc-400">Regression Failure</div>
            <div className="mt-1 text-lg font-bold text-rose-300">
              {(metrics.candidate_regression_failure_rate * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-zinc-500">Zero Degradation Gate</div>
          </div>
          <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-3">
            <div className="text-xs font-medium text-zinc-400">Coverage Score</div>
            <div className="mt-1 text-lg font-bold text-teal-300">
              {coverage ? `${coverage.coverage_percentage}%` : "--"}
            </div>
            <div className="text-[10px] text-zinc-500">MITRE Matrix Coverage</div>
          </div>
        </div>
      )}

      {/* Action Notification Message */}
      {actionMessage && (
        <div className="flex items-center justify-between rounded-lg border border-cyan-500/30 bg-cyan-950/40 px-4 py-2 text-xs text-cyan-200">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-cyan-400 hover:text-cyan-200">
            &times;
          </button>
        </div>
      )}

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-surface-border text-sm">
        <button
          onClick={() => setActiveTab("hunts")}
          className={`flex items-center gap-2 border-b-2 px-4 py-2 font-medium transition-colors ${
            activeTab === "hunts"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <Search className="h-4 w-4" />
          Threat Hunts ({hunts.length})
        </button>
        <button
          onClick={() => setActiveTab("gaps")}
          className={`flex items-center gap-2 border-b-2 px-4 py-2 font-medium transition-colors ${
            activeTab === "gaps"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <ShieldAlert className="h-4 w-4" />
          Detection Gaps ({gaps.length})
        </button>
        <button
          onClick={() => setActiveTab("lifecycle")}
          className={`flex items-center gap-2 border-b-2 px-4 py-2 font-medium transition-colors ${
            activeTab === "lifecycle"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <GitBranch className="h-4 w-4" />
          Detection Lifecycle Board ({candidates.length})
        </button>
        <button
          onClick={() => setActiveTab("coverage")}
          className={`flex items-center gap-2 border-b-2 px-4 py-2 font-medium transition-colors ${
            activeTab === "coverage"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <Layers className="h-4 w-4" />
          Coverage Matrix
        </button>
      </div>

      {/* Tab 1: Threat Hunts View */}
      {activeTab === "hunts" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left Column: Hunt List */}
          <div className="space-y-3 lg:col-span-5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
              Evaluated Hunt Hypotheses (HUNT-001 to HUNT-010)
            </h2>
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
              {hunts.map((h) => {
                const isSelected = selectedHunt?.hunt_id === h.hunt_id;
                let badgeColor = "bg-zinc-800 text-zinc-400 border-zinc-700";
                if (h.classification === "DETECTION_GAP") badgeColor = "bg-amber-950/60 text-amber-300 border-amber-800";
                else if (h.classification === "ALREADY_COVERED_BY_EXISTING_RULE") badgeColor = "bg-cyan-950/60 text-cyan-300 border-cyan-800";
                else if (h.classification === "FALSE_LEAD") badgeColor = "bg-emerald-950/60 text-emerald-300 border-emerald-800";
                else if (h.classification === "INSUFFICIENT_DATA") badgeColor = "bg-rose-950/60 text-rose-300 border-rose-800";

                return (
                  <div
                    key={h.hunt_id}
                    onClick={() => setSelectedHunt(h)}
                    className={`cursor-pointer rounded-xl border p-3.5 transition-all ${
                      isSelected
                        ? "border-cyan-500/50 bg-cyan-950/20 shadow-md shadow-cyan-950/30"
                        : "border-surface-border bg-surface-raised/40 hover:bg-surface-raised"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-cyan-300">
                        {h.hunt_id}
                      </span>
                      <span className={`rounded border px-2 py-0.5 text-[10px] font-medium ${badgeColor}`}>
                        {h.classification.replace(/_/g, " ")}
                      </span>
                    </div>
                    <div className="mt-1 text-sm font-medium text-zinc-200 line-clamp-1">
                      {h.title}
                    </div>
                    <div className="mt-1 text-xs text-zinc-400 line-clamp-2">
                      {h.hypothesis}
                    </div>
                    <div className="mt-2 flex items-center gap-2 text-[10px] text-zinc-500">
                      <span>Sources: {h.data_sources_json?.join(", ") || "ALL"}</span>
                      <span>&bull;</span>
                      <span>Confidence: {(h.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Selected Hunt Details & Execution Workspace */}
          <div className="space-y-4 lg:col-span-7">
            {selectedHunt ? (
              <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-3">
                  <div>
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {selectedHunt.hunt_id}
                    </span>
                    <h3 className="text-base font-semibold text-zinc-50">{selectedHunt.title}</h3>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleExecuteHunt(selectedHunt.hunt_id)}
                      disabled={executing}
                      className="focus-ring flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white shadow hover:bg-cyan-500 disabled:opacity-50"
                    >
                      <Play className="h-3.5 w-3.5 fill-current" />
                      {executing ? "Executing Query..." : "Execute Hunt"}
                    </button>
                    {selectedHunt.classification === "DETECTION_GAP" && !selectedHunt.detection_gap_id && (
                      <button
                        onClick={() => handleGenerateGap(selectedHunt.hunt_id)}
                        className="focus-ring flex items-center gap-1.5 rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white shadow hover:bg-amber-500"
                      >
                        <ShieldAlert className="h-3.5 w-3.5" />
                        Log Detection Gap
                      </button>
                    )}
                  </div>
                </div>

                {/* Hypothesis and Behavior */}
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="rounded-lg bg-surface-base p-3">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                      Hunt Hypothesis
                    </div>
                    <div className="mt-1 text-xs text-zinc-200 leading-relaxed">
                      {selectedHunt.hypothesis}
                    </div>
                  </div>
                  <div className="rounded-lg bg-surface-base p-3">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                      Expected Behavior
                    </div>
                    <div className="mt-1 text-xs text-zinc-200 leading-relaxed">
                      {selectedHunt.expected_behavior}
                    </div>
                  </div>
                </div>

                {/* Observation and Classification */}
                <div className="rounded-lg border border-surface-border bg-surface-base/80 p-3.5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-zinc-300">Observed Behavior:</span>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-zinc-400">Result:</span>
                      <span className="font-semibold text-cyan-300">{selectedHunt.result}</span>
                    </div>
                  </div>
                  <p className="text-xs text-zinc-300 italic">
                    {selectedHunt.observed_behavior || "Query not yet executed or no matching telemetry found in current sliding window."}
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-zinc-400">
                    <span>Classification: <strong className="text-zinc-200">{selectedHunt.classification}</strong></span>
                    <span>&bull;</span>
                    <span>Matched Events: {selectedHunt.related_events_json?.length || 0}</span>
                    <span>&bull;</span>
                    <span>Related Alerts: {selectedHunt.related_alerts_json?.length || 0}</span>
                  </div>
                </div>

                {/* Query & Parameter Bounds */}
                <div>
                  <h4 className="text-xs font-semibold text-zinc-400">Query Filter Bounds</h4>
                  <pre className="mt-1.5 overflow-x-auto rounded-lg bg-black/50 p-2.5 font-mono text-[11px] text-zinc-300">
                    {JSON.stringify(selectedHunt.query_filter_json || {}, null, 2)}
                  </pre>
                </div>

                {/* Evidence References */}
                {selectedHunt.evidence_refs_json && selectedHunt.evidence_refs_json.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-400">
                      Telemetry Evidence Artifacts ({selectedHunt.evidence_refs_json.length})
                    </h4>
                    <div className="mt-1.5 max-h-48 overflow-y-auto rounded-lg border border-surface-border bg-surface-base">
                      <table className="w-full text-left text-[11px]">
                        <thead className="border-b border-surface-border bg-surface-raised/80 text-zinc-400">
                          <tr>
                            <th className="p-2">Event ID</th>
                            <th className="p-2">Source</th>
                            <th className="p-2">Process / Cmd</th>
                            <th className="p-2">Endpoints</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-surface-border text-zinc-300">
                          {selectedHunt.evidence_refs_json.map((ev: any, idx: number) => (
                            <tr key={idx} className="hover:bg-zinc-800/40">
                              <td className="p-2 font-mono text-cyan-300">#{ev.event_id}</td>
                              <td className="p-2">{ev.source_type}</td>
                              <td className="p-2 font-mono text-[10px] max-w-[200px] truncate" title={ev.command_line || ev.process}>
                                {ev.command_line || ev.process || "--"}
                              </td>
                              <td className="p-2 font-mono text-[10px]">
                                {ev.source_ip || ""}:{ev.destination_port || ""}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="rounded-xl border border-surface-border bg-surface-raised/20 p-8 text-center text-sm text-zinc-500">
                Select a threat hunt from the list to view its parameters and execute telemetry analysis.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Detection Gaps View */}
      {activeTab === "gaps" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-zinc-200">
              Identified Detection Gaps (Awaiting Candidate Rule Engineering)
            </h2>
          </div>
          {gaps.length === 0 ? (
            <div className="rounded-xl border border-surface-border bg-surface-raised/30 p-8 text-center text-sm text-zinc-500">
              No detection gaps currently identified. Execute hunts with uncovered behaviors (e.g. HUNT-006) to identify genuine telemetry detection gaps.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {gaps.map((gap) => (
                <div key={gap.gap_id} className="rounded-xl border border-surface-border bg-surface-raised/60 p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-amber-400">{gap.gap_id}</span>
                    <span className="rounded bg-amber-950/60 border border-amber-800 px-2 py-0.5 text-[10px] font-medium text-amber-300">
                      {gap.status}
                    </span>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-zinc-100">{gap.affected_behavior}</h4>
                    <p className="mt-1 text-xs text-zinc-400">{gap.description}</p>
                  </div>
                  <div className="rounded-lg bg-surface-base p-2.5 text-xs text-zinc-300">
                    <span className="text-zinc-500 font-medium">Missing Capability: </span>
                    {gap.missing_detection_capability}
                  </div>
                  <div className="flex items-center justify-between pt-2 border-t border-surface-border text-xs">
                    <span className="text-zinc-500">Source: {gap.affected_source} &bull; Severity: {gap.severity}</span>
                    {!gap.candidate_rule_id && (
                      <button
                        onClick={() => handleGenerateCandidate(gap.gap_id)}
                        className="focus-ring flex items-center gap-1 rounded bg-cyan-600 px-2.5 py-1 text-xs font-semibold text-white hover:bg-cyan-500"
                      >
                        <FileCode className="h-3.5 w-3.5" />
                        Generate Candidate Rule
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Detection Engineering Lifecycle Kanban Board */}
      {activeTab === "lifecycle" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-zinc-200">
                Detection Engineering Lifecycle (DRAFT &rarr; TESTING &rarr; VALIDATING &rarr; ACTIVE &rarr; DEPRECATED)
              </h2>
              <p className="text-xs text-zinc-400">
                Candidate detections undergo quality gate assertions and historical regression verification before production promotion.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
            {["DRAFT", "TESTING", "VALIDATING", "ACTIVE", "DEPRECATED"].map((colStatus) => {
              const rulesInCol = candidates.filter((c) => c.status === colStatus);
              let colBadge = "border-zinc-700 text-zinc-400";
              if (colStatus === "DRAFT") colBadge = "border-zinc-500 text-zinc-300";
              else if (colStatus === "TESTING") colBadge = "border-blue-700 text-blue-300";
              else if (colStatus === "VALIDATING") colBadge = "border-amber-700 text-amber-300";
              else if (colStatus === "ACTIVE") colBadge = "border-emerald-700 text-emerald-300";
              else if (colStatus === "DEPRECATED") colBadge = "border-rose-700 text-rose-300";

              return (
                <div key={colStatus} className="rounded-xl border border-surface-border bg-surface-raised/40 p-3 space-y-3">
                  <div className="flex items-center justify-between border-b border-surface-border pb-2">
                    <span className={`text-xs font-bold uppercase tracking-wider ${colBadge}`}>
                      {colStatus}
                    </span>
                    <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-400">
                      {rulesInCol.length}
                    </span>
                  </div>

                  <div className="space-y-3 min-h-[300px]">
                    {rulesInCol.map((cand) => (
                      <div
                        key={cand.candidate_rule_id}
                        className="rounded-lg border border-surface-border bg-surface-base p-3 space-y-2.5 text-xs shadow-sm"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] font-semibold text-cyan-400">
                            {cand.candidate_rule_id} v{cand.version}
                          </span>
                          <span className="text-[10px] text-zinc-500">{cand.source}</span>
                        </div>
                        <div className="font-semibold text-zinc-200 line-clamp-2">{cand.name}</div>
                        <p className="text-[11px] text-zinc-400 line-clamp-2">{cand.description}</p>

                        {/* Validation Result Box */}
                        {cand.validation_result_json && (
                          <div className="rounded bg-zinc-900/90 p-2 text-[10px] space-y-1">
                            <div className="flex items-center justify-between font-semibold">
                              <span>Quality Gate:</span>
                              <span className={cand.validation_result_json.passed ? "text-emerald-400" : "text-rose-400"}>
                                {cand.validation_result_json.passed ? "PASSED" : "FAILED"}
                              </span>
                            </div>
                            <div className="text-zinc-400">
                              Prec: {cand.validation_result_json.precision} &bull; Rec: {cand.validation_result_json.recall} &bull; FPR: {cand.validation_result_json.fpr}
                            </div>
                          </div>
                        )}

                        {/* Action buttons based on status */}
                        <div className="pt-2 border-t border-surface-border flex flex-col gap-1.5">
                          {colStatus === "DRAFT" && (
                            <button
                              onClick={() => handleTransitionLifecycle(cand.candidate_rule_id, "TESTING", "Promoting draft to testing")}
                              className="w-full rounded bg-blue-600/80 px-2 py-1 text-[11px] font-semibold text-white hover:bg-blue-600"
                            >
                              Move to Testing &rarr;
                            </button>
                          )}
                          {colStatus === "TESTING" && (
                            <button
                              onClick={() => handleTransitionLifecycle(cand.candidate_rule_id, "VALIDATING", "Moving to automated validation gate")}
                              className="w-full rounded bg-amber-600/80 px-2 py-1 text-[11px] font-semibold text-white hover:bg-amber-600"
                            >
                              Run Validation &rarr;
                            </button>
                          )}
                          {colStatus === "VALIDATING" && (
                            <>
                              <button
                                onClick={() => handleValidateCandidate(cand.candidate_rule_id)}
                                className="w-full rounded bg-zinc-800 px-2 py-1 text-[11px] text-zinc-200 hover:bg-zinc-700"
                              >
                                Test Quality Gate
                              </button>
                              <button
                                onClick={() => handleRegressionCheck(cand.candidate_rule_id)}
                                className="w-full rounded bg-indigo-600/80 px-2 py-1 text-[11px] font-semibold text-white hover:bg-indigo-600"
                              >
                                Check Historical Regression
                              </button>
                              <button
                                onClick={() => handleTransitionLifecycle(cand.candidate_rule_id, "ACTIVE", "Passed quality gates and regression checks")}
                                className="w-full rounded bg-emerald-600 px-2 py-1 text-[11px] font-semibold text-white hover:bg-emerald-500"
                              >
                                Activate Rule (Deploy)
                              </button>
                            </>
                          )}
                          {colStatus === "ACTIVE" && (
                            <button
                              onClick={() => handleTransitionLifecycle(cand.candidate_rule_id, "DEPRECATED", "Deprecated by detection engineering review")}
                              className="w-full rounded bg-rose-950 text-rose-300 border border-rose-800 px-2 py-1 text-[11px] hover:bg-rose-900"
                            >
                              Deprecate
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 4: Detection Coverage Matrix View */}
      {activeTab === "coverage" && coverage && (
        <div className="space-y-4">
          <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-zinc-100">
                  MITRE ATT&CK & Behavioral Coverage Assessment
                </h3>
                <p className="text-xs text-zinc-400">
                  Evaluates enterprise behavioral threats against active production SIEM rules and candidate hunting detections.
                </p>
              </div>
              <div className="flex items-center gap-4 text-xs font-medium">
                <div className="flex items-center gap-1.5 text-emerald-400">
                  <span className="h-2 w-2 rounded-full bg-emerald-400" />
                  Full ({coverage.full_coverage_count})
                </div>
                <div className="flex items-center gap-1.5 text-amber-400">
                  <span className="h-2 w-2 rounded-full bg-amber-400" />
                  Partial ({coverage.partial_coverage_count})
                </div>
                <div className="flex items-center gap-1.5 text-rose-400">
                  <span className="h-2 w-2 rounded-full bg-rose-400" />
                  Missing ({coverage.missing_coverage_count})
                </div>
              </div>
            </div>

            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-surface-border text-zinc-400">
                  <tr>
                    <th className="py-2.5 px-3">Behavioral Threat</th>
                    <th className="py-2.5 px-3">Telemetry Source</th>
                    <th className="py-2.5 px-3">MITRE Technique</th>
                    <th className="py-2.5 px-3">Active Rule ID</th>
                    <th className="py-2.5 px-3">Coverage Status</th>
                    <th className="py-2.5 px-3">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-border text-zinc-200">
                  {coverage.items.map((item: any, idx: number) => {
                    let covBadge = "bg-rose-950/60 text-rose-300 border-rose-800";
                    if (item.coverage === "FULL") covBadge = "bg-emerald-950/60 text-emerald-300 border-emerald-800";
                    else if (item.coverage === "PARTIAL") covBadge = "bg-amber-950/60 text-amber-300 border-amber-800";

                    return (
                      <tr key={idx} className="hover:bg-zinc-800/40">
                        <td className="py-2.5 px-3 font-medium">
                          {item.behavior}
                          {item.known_gap && (
                            <div className="text-[10px] text-amber-400/80 font-normal">
                              Gap: {item.known_gap}
                            </div>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">{item.telemetry_source}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-cyan-300">
                          {item.mitre_technique} <span className="text-zinc-500 font-sans">({item.technique_name})</span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-indigo-300">{item.existing_rule || "--"}</td>
                        <td className="py-2.5 px-3">
                          <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${covBadge}`}>
                            {item.coverage}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">
                          {(item.confidence * 100).toFixed(0)}%
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
