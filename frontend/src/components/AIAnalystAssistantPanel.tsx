import React, { useEffect, useState } from "react";
import {
  Bot,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  RefreshCw,
  Send,
  ExternalLink,
  Lock,
  Search,
  CheckCircle,
  XCircle,
  FileText,
} from "lucide-react";
import { fetchIncidentAIAnalysis, askIncidentAIQuestion } from "../services/api";

interface EvidenceCitation {
  evidence_id: number | null;
  source_type: string;
  field: string;
  value: string;
  provenance: string;
}

interface AttackChainStep {
  stage_order: number;
  stage_name: string;
  description: string;
  source_type: string;
  evidence_ids: number[];
}

interface MITREItem {
  tactic: string;
  technique_id: string;
  technique_name: string;
  evidence_ids: number[];
  confidence: number;
}

interface AIAnalysisData {
  incident_id: number;
  model_name: string;
  prompt_version: string;
  summary: string;
  assessment: string;
  confidence: number;
  abstain: boolean;
  abstention_reason?: string;
  facts: string[];
  inferences: string[];
  recommendations: string[];
  uncertainties: string[];
  supporting_evidence: EvidenceCitation[];
  contradicting_evidence: EvidenceCitation[];
  missing_evidence: string[];
  attack_chain: AttackChainStep[];
  mitre_context: MITREItem[];
  citation_coverage_pct: number;
  unsupported_claims_count: number;
}

export function AIAnalystAssistantPanel({
  incidentId,
  onSelectEvidence,
}: {
  incidentId: number;
  onSelectEvidence?: (evidenceId: number) => void;
}) {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<AIAnalysisData | null>(null);
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [qaHistory, setQaHistory] = useState<Array<{ q: string; a: string; citations: EvidenceCitation[] }>>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAnalysis();
  }, [incidentId]);

  async function loadAnalysis(forceRefresh: boolean = false) {
    try {
      setLoading(true);
      setError(null);
      const res = await fetchIncidentAIAnalysis(incidentId, forceRefresh);
      setData(res);
    } catch (err: any) {
      setError(err?.message || "Failed to load AI analyst assistance");
    } finally {
      setLoading(false);
    }
  }

  async function handleAskQuestion(e: React.FormEvent) {
    e.preventDefault();
    if (!question.trim()) return;

    const currentQ = question.trim();
    setAsking(true);
    try {
      const res = await askIncidentAIQuestion(incidentId, currentQ);
      setQaHistory((prev) => [
        ...prev,
        { q: currentQ, a: res.answer, citations: res.evidence_citations || [] },
      ]);
      setQuestion("");
    } catch {
      setQaHistory((prev) => [
        ...prev,
        {
          q: currentQ,
          a: "Error querying incident context. Inquiry could not be evaluated.",
          citations: [],
        },
      ]);
    } finally {
      setAsking(false);
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 space-y-3">
        <RefreshCw className="h-6 w-6 animate-spin text-indigo-400" />
        <span className="text-xs text-zinc-400">
          Generating evidence-grounded AI analyst assistance...
        </span>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-6 text-center space-y-3">
        <AlertTriangle className="h-6 w-6 text-rose-400 mx-auto" />
        <div className="text-sm font-semibold text-rose-200">AI Assistant Unavailable</div>
        <div className="text-xs text-rose-400">{error || "No analysis available."}</div>
        <button
          onClick={() => loadAnalysis(true)}
          className="rounded-lg bg-surface-inset px-3 py-1.5 text-xs text-zinc-200 hover:bg-surface-raised"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner / Assessment Card */}
      <div className="rounded-xl border border-surface-border bg-surface-raised p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="rounded-lg bg-indigo-500/10 p-2 border border-indigo-500/20 text-indigo-400">
              <Bot className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-zinc-100">
                  Evidence-Grounded AI Analyst Assessment
                </h3>
                <span className="rounded bg-black/40 px-2 py-0.5 text-[10px] font-mono text-zinc-400">
                  {data.model_name}
                </span>
              </div>
              <p className="text-xs text-zinc-400">
                Authoritative verification status & advisory triage guidance
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => loadAnalysis(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-inset px-3 py-1.5 text-xs text-zinc-300 hover:bg-surface-raised hover:text-white transition"
              title="Re-run assessment"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2">
          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <div className="text-[11px] uppercase tracking-wider text-zinc-500">Assessment</div>
            <div className="mt-1 flex items-center gap-1.5">
              {data.abstain ? (
                <span className="inline-flex items-center gap-1 text-amber-400 font-bold text-xs">
                  <AlertTriangle className="h-3.5 w-3.5" /> INSUFFICIENT EVIDENCE (ABSTAIN)
                </span>
              ) : data.assessment === "TRUE_POSITIVE" ? (
                <span className="inline-flex items-center gap-1 text-emerald-400 font-bold text-xs">
                  <ShieldAlert className="h-3.5 w-3.5" /> TRUE POSITIVE INTRUSION
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-blue-400 font-bold text-xs">
                  <HelpCircle className="h-3.5 w-3.5" /> {data.assessment}
                </span>
              )}
            </div>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <div className="text-[11px] uppercase tracking-wider text-zinc-500">Grounded Confidence</div>
            <div className="mt-1 font-mono text-sm font-bold text-indigo-300">
              {Math.round(data.confidence * 100)}%
            </div>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <div className="text-[11px] uppercase tracking-wider text-zinc-500">Citation Coverage</div>
            <div className="mt-1 font-mono text-sm font-bold text-emerald-400">
              {data.citation_coverage_pct}%
            </div>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface-base p-3">
            <div className="text-[11px] uppercase tracking-wider text-zinc-500">Unsupported Claims</div>
            <div className="mt-1 font-mono text-sm font-bold text-zinc-200">
              {data.unsupported_claims_count}
            </div>
          </div>
        </div>

        {/* Narrative Summary */}
        <div className="rounded-lg border border-indigo-500/20 bg-indigo-950/20 p-4">
          <div className="text-xs font-semibold text-indigo-300 mb-1 flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5" />
            Executive Synthesis
          </div>
          <p className="text-xs leading-relaxed text-zinc-200">{data.summary}</p>
          {data.abstain && data.abstention_reason && (
            <div className="mt-2 text-xs font-medium text-amber-300 bg-amber-950/40 border border-amber-500/30 rounded p-2">
              ⚠️ Abstention Rationale: {data.abstention_reason}
            </div>
          )}
        </div>
      </div>

      {/* Grid: Verified Facts & Inferences */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Verified Facts */}
        <div className="rounded-xl border border-surface-border bg-surface-raised p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-surface-border pb-2">
            <CheckCircle className="h-4 w-4 text-emerald-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-200">
              Verified Authoritative Facts ({data.facts.length})
            </h4>
          </div>
          <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
            {data.facts.length > 0 ? (
              data.facts.map((fact, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-surface-border bg-surface-base p-2.5 text-xs text-zinc-200 flex items-start gap-2"
                >
                  <span className="rounded bg-emerald-500/20 text-emerald-400 font-mono text-[10px] px-1.5 py-0.5 mt-0.5">
                    F{idx + 1}
                  </span>
                  <span className="leading-snug">{fact}</span>
                </div>
              ))
            ) : (
              <div className="text-xs text-zinc-500 italic p-2">No verified facts recorded.</div>
            )}
          </div>
        </div>

        {/* Analytical Inferences */}
        <div className="rounded-xl border border-surface-border bg-surface-raised p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-surface-border pb-2">
            <Search className="h-4 w-4 text-indigo-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-200">
              Analytical Inferences ({data.inferences.length})
            </h4>
          </div>
          <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
            {data.inferences.length > 0 ? (
              data.inferences.map((inf, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-surface-border bg-surface-base p-2.5 text-xs text-zinc-200 flex items-start gap-2"
                >
                  <span className="rounded bg-indigo-500/20 text-indigo-400 font-mono text-[10px] px-1.5 py-0.5 mt-0.5">
                    INF
                  </span>
                  <span className="leading-snug">{inf}</span>
                </div>
              ))
            ) : (
              <div className="text-xs text-zinc-500 italic p-2">No inferences generated.</div>
            )}
          </div>
        </div>
      </div>

      {/* Multi-Plane Attack Chain */}
      {data.attack_chain && data.attack_chain.length > 0 && (
        <div className="rounded-xl border border-surface-border bg-surface-raised p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-surface-border pb-2">
            <ShieldCheck className="h-4 w-4 text-purple-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-200">
              Reconstructed Multi-Plane Attack Chain
            </h4>
          </div>
          <div className="space-y-2.5">
            {data.attack_chain.map((step) => (
              <div
                key={step.stage_order}
                className="flex items-center justify-between rounded-lg border border-surface-border bg-surface-base p-3 text-xs"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-500/20 font-mono text-xs font-bold text-indigo-400">
                    {step.stage_order}
                  </div>
                  <div>
                    <div className="font-semibold text-zinc-100 flex items-center gap-2">
                      <span>{step.stage_name}</span>
                      <span className="rounded bg-zinc-800 border border-zinc-700 px-1.5 py-0.2 text-[10px] text-zinc-300">
                        {step.source_type}
                      </span>
                    </div>
                    <div className="text-zinc-400 text-[11px] mt-0.5">{step.description}</div>
                  </div>
                </div>

                {step.evidence_ids && step.evidence_ids.length > 0 && (
                  <div className="flex items-center gap-1.5">
                    {step.evidence_ids.map((evId) => (
                      <button
                        key={evId}
                        onClick={() => onSelectEvidence && onSelectEvidence(evId)}
                        className="inline-flex items-center gap-1 rounded bg-indigo-950/60 border border-indigo-500/30 px-2 py-0.5 font-mono text-[10px] font-semibold text-indigo-300 hover:bg-indigo-900 transition"
                        title={`Jump to Evidence #${evId}`}
                      >
                        <span>EVID-{evId}</span>
                        <ExternalLink className="h-2.5 w-2.5" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Context & Recommendations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* MITRE Context */}
        <div className="rounded-xl border border-surface-border bg-surface-raised p-4 space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-200">
            MITRE ATT&CK Context
          </h4>
          <div className="space-y-2">
            {data.mitre_context && data.mitre_context.length > 0 ? (
              data.mitre_context.map((m, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-surface-border bg-surface-base p-2.5 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-purple-400 font-bold">{m.technique_id}</span>
                    <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">
                      {m.tactic}
                    </span>
                  </div>
                  <div className="text-zinc-200 font-medium">{m.technique_name}</div>
                </div>
              ))
            ) : (
              <div className="text-xs text-zinc-500 italic p-2">
                No specific MITRE techniques mapped for this incident.
              </div>
            )}
          </div>
        </div>

        {/* Advisory Recommendations */}
        <div className="rounded-xl border border-surface-border bg-surface-raised p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-200">
              Advisory Recommendations
            </h4>
            <span className="rounded bg-amber-500/10 border border-amber-500/20 text-amber-300 text-[10px] px-1.5 py-0.5 font-medium">
              Analyst Authorization Required
            </span>
          </div>
          <div className="space-y-2">
            {data.recommendations && data.recommendations.length > 0 ? (
              data.recommendations.map((rec, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-surface-border bg-surface-base p-2.5 text-xs text-zinc-200 flex items-start gap-2"
                >
                  <span className="text-indigo-400 font-bold mt-0.5">•</span>
                  <span className="leading-snug">{rec}</span>
                </div>
              ))
            ) : (
              <div className="text-xs text-zinc-500 italic p-2">No recommendations generated.</div>
            )}
          </div>
        </div>
      </div>

      {/* Uncertainties & Telemetry Gaps */}
      {data.uncertainties && data.uncertainties.length > 0 && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/10 p-4 space-y-2">
          <div className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
            <AlertTriangle className="h-4 w-4" />
            Explicit Data Gaps & Uncertainties
          </div>
          <ul className="list-disc list-inside space-y-1 text-xs text-zinc-300">
            {data.uncertainties.map((u, idx) => (
              <li key={idx} className="leading-relaxed">
                {u}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Interactive Evidence-Grounded Q&A */}
      <div className="rounded-xl border border-surface-border bg-surface-raised p-5 space-y-4">
        <div className="flex items-center gap-2">
          <HelpCircle className="h-4 w-4 text-indigo-400" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-200">
            Ask Evidence-Grounded Assistant
          </h4>
        </div>

        {/* Q&A Thread */}
        {qaHistory.length > 0 && (
          <div className="space-y-3 max-h-64 overflow-y-auto pr-1">
            {qaHistory.map((qa, idx) => (
              <div key={idx} className="rounded-lg border border-surface-border bg-surface-base p-3 space-y-2 text-xs">
                <div className="flex items-center gap-1.5 font-semibold text-indigo-300">
                  <span className="text-zinc-500">Q:</span> {qa.q}
                </div>
                <div className="text-zinc-200 leading-relaxed pl-3 border-l-2 border-indigo-500/40">
                  {qa.a}
                </div>
              </div>
            ))}
          </div>
        )}

        <form onSubmit={handleAskQuestion} className="flex gap-2">
          <input
            type="text"
            className="focus-ring flex-1 rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-xs text-zinc-200 placeholder:text-zinc-500"
            placeholder="Ask a question strictly bounded to verified incident evidence (e.g. 'What process was executed?')..."
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            disabled={asking}
          />
          <button
            type="submit"
            disabled={asking || !question.trim()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-50 transition"
          >
            {asking ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            <span>Ask</span>
          </button>
        </form>
      </div>

      {/* Safety Notice */}
      <div className="rounded-lg border border-surface-border bg-surface-inset/60 p-3 text-[11px] text-zinc-500 flex items-center gap-2">
        <Lock className="h-3.5 w-3.5 text-zinc-400 shrink-0" />
        <span>
          Safety Constraint: The AI Assistant is advisory and read-only. Authoritative incident status, risk, and detection scores remain deterministically controlled by the SOC engine.
        </span>
      </div>
    </div>
  );
}
