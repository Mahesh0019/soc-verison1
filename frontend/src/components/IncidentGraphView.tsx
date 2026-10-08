import { useState, useMemo } from "react";
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Database,
  Filter,
  Globe,
  HardDrive,
  Maximize2,
  Minimize2,
  Server,
  Share2,
  Shield,
  Terminal,
  User,
  X,
  Zap,
} from "lucide-react";
import type { IncidentGraphData, IncidentGraphNode, IncidentGraphEdge } from "../types";

interface IncidentGraphViewProps {
  graphData: IncidentGraphData;
  onSelectAlert?: (alertId: number) => void;
}

const TYPE_COLORS: Record<string, { bg: string; border: string; text: string; icon: any }> = {
  Incident: { bg: "bg-red-950/40", border: "border-red-500", text: "text-red-400", icon: Shield },
  Alert: { bg: "bg-rose-950/40", border: "border-rose-500", text: "text-rose-400", icon: AlertTriangle },
  Event: { bg: "bg-cyan-950/40", border: "border-cyan-500", text: "text-cyan-400", icon: Activity },
  IP: { bg: "bg-blue-950/40", border: "border-blue-500", text: "text-blue-400", icon: Globe },
  Host: { bg: "bg-purple-950/40", border: "border-purple-500", text: "text-purple-400", icon: Server },
  User: { bg: "bg-emerald-950/40", border: "border-emerald-500", text: "text-emerald-400", icon: User },
  Process: { bg: "bg-amber-950/40", border: "border-amber-500", text: "text-amber-400", icon: Terminal },
  Domain: { bg: "bg-teal-950/40", border: "border-teal-500", text: "text-teal-400", icon: HardDrive },
  URL: { bg: "bg-indigo-950/40", border: "border-indigo-500", text: "text-indigo-400", icon: Database },
};

export function IncidentGraphView({ graphData, onSelectAlert }: IncidentGraphViewProps) {
  const [selectedNode, setSelectedNode] = useState<IncidentGraphNode | null>(null);
  const [sourceFilter, setSourceFilter] = useState<string>("ALL");
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());

  // Filter nodes & edges
  const filteredNodes = useMemo(() => {
    if (!graphData?.nodes) return [];
    if (sourceFilter === "ALL") return graphData.nodes;
    return graphData.nodes.filter((node) => {
      const src = String(node.properties?.source_type || "").toUpperCase();
      if (node.type === "Incident" || node.type === "Alert") return true;
      return src === sourceFilter;
    });
  }, [graphData, sourceFilter]);

  const activeNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    if (!graphData?.edges) return [];
    return graphData.edges.filter((e) => activeNodeIds.has(e.source) && activeNodeIds.has(e.target));
  }, [graphData, activeNodeIds]);

  const toggleExpand = (nodeId: string) => {
    setExpandedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  };

  // Compute simple deterministic coordinate layout for canvas view
  const positionedNodes = useMemo(() => {
    const countsByType: Record<string, number> = {};
    const typeOrder = ["Incident", "Alert", "Host", "IP", "Process", "Domain", "URL", "Event", "User"];
    
    return filteredNodes.map((node) => {
      const t = node.type || "Event";
      const col = Math.max(0, typeOrder.indexOf(t));
      const row = countsByType[t] || 0;
      countsByType[t] = row + 1;

      // Coordinate mapping (columns spread across width, rows stacked vertically)
      const x = 50 + col * 140;
      const y = 60 + row * 85;
      return { ...node, x, y };
    });
  }, [filteredNodes]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, typeof positionedNodes[0]>();
    positionedNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [positionedNodes]);

  const totalWidth = Math.max(850, 100 + 9 * 140);
  const totalHeight = Math.max(450, 100 + Math.max(...Object.values(positionedNodes.reduce((acc, n) => {
    acc[n.type] = (acc[n.type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>)), 1) * 85);

  return (
    <div className="flex flex-col rounded-lg border border-surface-border bg-surface-raised overflow-hidden">
      {/* Header & Controls */}
      <div className="flex flex-wrap items-center justify-between border-b border-surface-border bg-surface-base px-4 py-3 gap-3">
        <div className="flex items-center gap-2">
          <Share2 className="h-5 w-5 text-indigo-400" />
          <h3 className="text-sm font-semibold text-zinc-100">Telemetry Incident Graph</h3>
          <span className="text-xs text-zinc-400">
            ({filteredNodes.length} nodes, {filteredEdges.length} telemetry-backed edges)
          </span>
        </div>

        {/* Source Filter */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-zinc-400" />
          <span className="text-xs text-zinc-400">Filter Source:</span>
          {["ALL", "WEB", "ZEEK", "SYSMON"].map((src) => (
            <button
              key={src}
              type="button"
              onClick={() => setSourceFilter(src)}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
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

      {/* Main View: Graph Canvas + Details Drawer */}
      <div className="relative flex flex-1 min-h-[460px] overflow-hidden">
        {/* SVG Graph Canvas */}
        <div className="flex-1 overflow-auto bg-surface-inset/80 p-4">
          <svg width={totalWidth} height={totalHeight} className="min-w-full">
            <defs>
              <marker
                id="arrowhead"
                markerWidth="8"
                markerHeight="6"
                refX="7"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#71717a" />
              </marker>
              <marker
                id="arrowhead-highlight"
                markerWidth="8"
                markerHeight="6"
                refX="7"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#6366f1" />
              </marker>
            </defs>

            {/* Edges */}
            {filteredEdges.map((edge, idx) => {
              const srcNode = nodeMap.get(edge.source);
              const tgtNode = nodeMap.get(edge.target);
              if (!srcNode || !tgtNode) return null;

              const isHighlighted = selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target);
              const midX = (srcNode.x + tgtNode.x) / 2;
              const midY = (srcNode.y + tgtNode.y) / 2;

              return (
                <g key={`edge-${idx}`}>
                  <line
                    x1={srcNode.x + 50}
                    y1={srcNode.y + 15}
                    x2={tgtNode.x + 50}
                    y2={tgtNode.y + 15}
                    stroke={isHighlighted ? "#818cf8" : "#3f3f46"}
                    strokeWidth={isHighlighted ? 2.5 : 1.2}
                    markerEnd={isHighlighted ? "url(#arrowhead-highlight)" : "url(#arrowhead)"}
                  />
                  <text
                    x={midX + 50}
                    y={midY + 12}
                    textAnchor="middle"
                    fill={isHighlighted ? "#c7d2fe" : "#71717a"}
                    fontSize="9"
                    fontFamily="monospace"
                    className="select-none pointer-events-none"
                  >
                    {edge.relationship}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {positionedNodes.map((node) => {
              const style = TYPE_COLORS[node.type] || TYPE_COLORS.Event;
              const Icon = style.icon;
              const isSelected = selectedNode?.id === node.id;

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setSelectedNode(node)}
                  className="cursor-pointer transition-transform hover:scale-105"
                >
                  <rect
                    width="115"
                    height="32"
                    rx="6"
                    className={`${style.bg} ${style.border} stroke-1 ${
                      isSelected ? "stroke-2 stroke-indigo-400 ring-2 ring-indigo-500/50" : ""
                    }`}
                  />
                  <foreignObject width="115" height="32" className="pointer-events-none">
                    <div className="flex h-full items-center gap-1.5 px-2">
                      <Icon className={`h-3.5 w-3.5 shrink-0 ${style.text}`} />
                      <div className="truncate text-[11px] font-medium text-zinc-200">
                        {node.label}
                      </div>
                    </div>
                  </foreignObject>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="w-80 border-l border-surface-border bg-surface-raised p-4 overflow-y-auto space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-surface-border pb-3">
              <div className="flex items-center gap-2">
                <span className={`rounded px-2 py-0.5 text-xs font-semibold ${TYPE_COLORS[selectedNode.type]?.bg} ${TYPE_COLORS[selectedNode.type]?.text}`}>
                  {selectedNode.type}
                </span>
                <h4 className="text-sm font-semibold text-zinc-100 truncate max-w-[170px]">
                  {selectedNode.label}
                </h4>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-zinc-400 hover:text-zinc-200"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="text-zinc-400">Node Identifier:</div>
              <div className="font-mono text-zinc-300 break-all bg-surface-inset p-2 rounded">
                {selectedNode.id}
              </div>
            </div>

            {/* Properties */}
            {Boolean(selectedNode.properties && Object.keys(selectedNode.properties).length > 0) ? (
              <div className="space-y-2">
                <div className="text-xs font-semibold text-zinc-300">Telemetry Properties</div>
                <div className="rounded bg-surface-inset p-2 space-y-1.5 text-xs">
                  {Object.entries(selectedNode.properties).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2">
                      <span className="text-zinc-400 font-mono">{k}:</span>
                      <span className="text-zinc-200 font-mono text-right break-all">
                        {String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {/* Direct Connected Relationships */}
            <div className="space-y-2">
              <div className="text-xs font-semibold text-zinc-300">Telemetry Edges</div>
              <div className="space-y-1">
                {filteredEdges
                  .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                  .map((e, idx) => {
                    const isOutgoing = e.source === selectedNode.id;
                    const otherId = isOutgoing ? e.target : e.source;
                    const otherNode = nodeMap.get(otherId);

                    return (
                      <div
                        key={idx}
                        className="rounded border border-surface-border bg-surface-inset/50 p-2 text-xs space-y-1"
                      >
                        <div className="flex items-center gap-1.5 font-medium text-indigo-300">
                          <span>{isOutgoing ? "➔ OUT:" : "⬅ IN:"}</span>
                          <span className="font-mono text-amber-300">{e.relationship}</span>
                        </div>
                        <div className="text-zinc-400 truncate">
                          {isOutgoing ? `To: ${otherNode?.label || otherId}` : `From: ${otherNode?.label || otherId}`}
                        </div>
                        {e.timestamp && (
                          <div className="text-[10px] text-zinc-500 font-mono">
                            {e.timestamp}
                          </div>
                        )}
                      </div>
                    );
                  })}
              </div>
            </div>

            {/* If node is an alert, option to jump to alert */}
            {Boolean(selectedNode.type === "Alert" && selectedNode.properties?.alert_id && onSelectAlert) ? (
              <button
                type="button"
                onClick={() => onSelectAlert && onSelectAlert(Number(selectedNode.properties?.alert_id))}
                className="w-full flex items-center justify-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-2 text-xs font-semibold text-white hover:bg-indigo-500"
              >
                Inspect Alert Details
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            ) : null}
          </div>
        )}
      </div>

      {/* Legend Footer */}
      <div className="flex flex-wrap items-center gap-3 border-t border-surface-border bg-surface-base px-4 py-2 text-xs text-zinc-400">
        <span className="font-semibold text-zinc-300">Telemetry Legend:</span>
        {Object.entries(TYPE_COLORS).map(([type, style]) => {
          const Icon = style.icon;
          return (
            <div key={type} className="flex items-center gap-1">
              <Icon className={`h-3 w-3 ${style.text}`} />
              <span>{type}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
