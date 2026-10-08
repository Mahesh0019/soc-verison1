import { useState, useMemo } from "react";
import {
  Clock,
  Filter,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Server,
  Globe,
  Terminal,
  Activity,
} from "lucide-react";
import type { IncidentTimelineItem } from "../types";
import { formatDate } from "../utils/format";

interface IncidentTimelineViewProps {
  timeline: IncidentTimelineItem[];
  onSelectAlert?: (alertId: number) => void;
}

const SOURCE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  WEB: { bg: "bg-blue-950/40", text: "text-blue-400", border: "border-blue-500/30" },
  AUTH: { bg: "bg-purple-950/40", text: "text-purple-400", border: "border-purple-500/30" },
  ZEEK: { bg: "bg-emerald-950/40", text: "text-emerald-400", border: "border-emerald-500/30" },
  SYSMON: { bg: "bg-amber-950/40", text: "text-amber-400", border: "border-amber-500/30" },
  FIREWALL: { bg: "bg-orange-950/40", text: "text-orange-400", border: "border-orange-500/30" },
  DETECTION_ALERT: { bg: "bg-rose-950/40", text: "text-rose-400", border: "border-rose-500/30" },
};

export function IncidentTimelineView({ timeline, onSelectAlert }: IncidentTimelineViewProps) {
  const [sourceFilter, setSourceFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedIndices, setExpandedIndices] = useState<Set<number>>(new Set());

  const toggleExpand = (idx: number) => {
    setExpandedIndices((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const filteredTimeline = useMemo(() => {
    if (!timeline) return [];
    return timeline.filter((item) => {
      if (sourceFilter !== "ALL" && item.source_type.toUpperCase() !== sourceFilter) {
        return false;
      }
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const inTitle = item.title.toLowerCase().includes(q);
        const inDesc = item.description.toLowerCase().includes(q);
        const inEntities = JSON.stringify(item.entities || {}).toLowerCase().includes(q);
        return inTitle || inDesc || inEntities;
      }
      return true;
    });
  }, [timeline, sourceFilter, searchQuery]);

  return (
    <div className="rounded-lg border border-surface-border bg-surface-raised overflow-hidden">
      {/* Header and Filter Controls */}
      <div className="flex flex-wrap items-center justify-between border-b border-surface-border bg-surface-base px-4 py-3 gap-3">
        <div className="flex items-center gap-2">
          <Clock className="h-5 w-5 text-indigo-400" />
          <h3 className="text-sm font-semibold text-zinc-100">Chronological Telemetry Timeline</h3>
          <span className="text-xs text-zinc-400">
            ({filteredTimeline.length} events from actual telemetry)
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search box */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-400" />
            <input
              type="text"
              placeholder="Search timeline events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rounded bg-surface-inset py-1 pl-8 pr-3 text-xs text-zinc-200 border border-surface-border focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* Source filters */}
          <div className="flex items-center gap-1.5">
            <Filter className="h-3.5 w-3.5 text-zinc-400" />
            {["ALL", "WEB", "ZEEK", "SYSMON", "DETECTION_ALERT"].map((src) => (
              <button
                key={src}
                type="button"
                onClick={() => setSourceFilter(src)}
                className={`rounded px-2 py-0.5 text-xs font-medium transition-colors ${
                  sourceFilter === src
                    ? "bg-indigo-600 text-white"
                    : "bg-surface-inset text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {src}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="p-4 space-y-4 max-h-[600px] overflow-y-auto">
        {filteredTimeline.length === 0 ? (
          <div className="py-8 text-center text-sm text-zinc-400">
            No telemetry events match current filters.
          </div>
        ) : (
          <div className="relative border-l-2 border-surface-border pl-6 ml-4 space-y-6">
            {filteredTimeline.map((item, idx) => {
              const prevItem = idx > 0 ? filteredTimeline[idx - 1] : null;
              let deltaStr = "";
              if (prevItem) {
                const dt = Math.abs(
                  (new Date(item.timestamp).getTime() - new Date(prevItem.timestamp).getTime()) / 1000
                );
                deltaStr = `+${dt.toFixed(1)}s`;
              }

              const colors = SOURCE_COLORS[item.source_type.toUpperCase()] || {
                bg: "bg-zinc-800",
                text: "text-zinc-300",
                border: "border-zinc-700",
              };

              const isExpanded = expandedIndices.has(idx);

              return (
                <div key={idx} className="relative group">
                  {/* Timeline dot */}
                  <div className={`absolute -left-[31px] top-1.5 h-3.5 w-3.5 rounded-full border-2 ${colors.border} bg-surface-base`} />

                  <div className={`rounded-lg border ${colors.border} bg-surface-inset/60 p-3 hover:bg-surface-inset transition-colors`}>
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className={`rounded px-2 py-0.5 text-[11px] font-semibold ${colors.bg} ${colors.text}`}>
                          {item.source_type}
                        </span>
                        <span className="rounded bg-zinc-800 px-2 py-0.5 text-[11px] font-mono text-zinc-400">
                          {item.stage}
                        </span>
                        {deltaStr && (
                          <span className="text-[11px] font-mono text-indigo-400">
                            ({deltaStr})
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
                        <span>{item.timestamp}</span>
                        {item.alert_id && onSelectAlert && (
                          <button
                            type="button"
                            onClick={() => onSelectAlert(item.alert_id!)}
                            className="flex items-center gap-1 text-rose-400 hover:text-rose-300 font-semibold"
                          >
                            <ShieldAlert className="h-3 w-3" />
                            <span>Alert #{item.alert_id}</span>
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="text-sm font-semibold text-zinc-200">
                      {item.title}
                    </div>
                    <div className="text-xs text-zinc-400 mt-0.5">
                      {item.description}
                    </div>

                    {/* Entities preview chips */}
                    {item.entities && Object.keys(item.entities).length > 0 && (
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        {Object.entries(item.entities).slice(0, 4).map(([k, v]) => (
                          <span
                            key={k}
                            className="inline-flex items-center gap-1 rounded bg-surface-base px-2 py-0.5 text-[11px] font-mono text-zinc-300 border border-surface-border"
                          >
                            <span className="text-zinc-500">{k}:</span>
                            <span className="text-amber-300">{String(v)}</span>
                          </span>
                        ))}
                        {Object.keys(item.entities).length > 4 && (
                          <button
                            type="button"
                            onClick={() => toggleExpand(idx)}
                            className="text-[11px] text-indigo-400 hover:text-indigo-300 underline"
                          >
                            +{Object.keys(item.entities).length - 4} more
                          </button>
                        )}
                      </div>
                    )}

                    {/* Expandable full telemetry drawer */}
                    {isExpanded && item.entities && (
                      <div className="mt-3 rounded border border-surface-border bg-surface-base p-2 text-xs font-mono space-y-1">
                        <div className="text-[10px] uppercase font-bold text-zinc-400 mb-1">
                          Full Telemetry Context
                        </div>
                        {Object.entries(item.entities).map(([k, v]) => (
                          <div key={k} className="flex justify-between gap-4">
                            <span className="text-zinc-500">{k}:</span>
                            <span className="text-zinc-300 text-right break-all">{String(v)}</span>
                          </div>
                        ))}
                        {item.raw_reference && (
                          <div className="flex justify-between gap-4 border-t border-surface-border pt-1">
                            <span className="text-zinc-500">raw_reference:</span>
                            <span className="text-emerald-400">{item.raw_reference}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
