import { useEffect, useState } from "react";
import { Activity, ArrowRight, Eye, Play, Search, Shield, UploadCloud, X } from "lucide-react";

import { SeverityBadge, SourceBadge } from "../components/Badge";
import { EmptyState, LoadingState } from "../components/State";
import { fetchEvents, replayZeekTelemetry } from "../services/api";
import type { NormalizedEvent, Page, ZeekReplayResponse } from "../types";
import { formatDate } from "../utils/format";

export function EventsPage() {
  const [data, setData] = useState<Page<NormalizedEvent> | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<NormalizedEvent | null>(null);
  const [filters, setFilters] = useState({
    q: "",
    source_type: "",
    severity: "",
    event_type: "",
    source_ip: "",
    username: "",
    hostname: "",
  });
  const [showReplayModal, setShowReplayModal] = useState(false);
  const [replayResult, setReplayResult] = useState<ZeekReplayResponse | null>(null);

  const loadEvents = () => {
    setLoading(true);
    fetchEvents({ ...filters, page_size: 30 })
      .then(setData)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadEvents();
  }, [filters]);

  return (
    <div className="space-y-4">
      {/* Top action header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Telemetry & Events</h1>
          <p className="text-xs text-zinc-400">Multi-source event store (Web, Auth, Firewall, Zeek Network Telemetry)</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowReplayModal(true)}
            className="focus-ring inline-flex items-center gap-2 rounded-lg border border-purple-500/40 bg-purple-500/10 px-3 py-2 text-xs font-semibold text-purple-300 transition hover:bg-purple-500/20"
          >
            <Activity className="h-4 w-4" />
            Replay Zeek Network Telemetry
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
        <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7">
          <label className="relative col-span-2">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
            <input
              className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset py-2 pl-9 pr-3 text-sm text-zinc-100 placeholder-zinc-500"
              placeholder="Search event messages, IPs, hosts..."
              value={filters.q}
              onChange={(event) => setFilters((current) => ({ ...current, q: event.target.value }))}
            />
          </label>
          <FilterInput
            label="Source"
            value={filters.source_type}
            onChange={(value) => setFilters((current) => ({ ...current, source_type: value }))}
            options={["", "ZEEK", "WEB", "AUTH", "FIREWALL"]}
          />
          <FilterInput
            label="Severity"
            value={filters.severity}
            onChange={(value) => setFilters((current) => ({ ...current, severity: value }))}
            options={["", "critical", "high", "medium", "low"]}
          />
          <FilterInput
            label="Type"
            value={filters.event_type}
            onChange={(value) => setFilters((current) => ({ ...current, event_type: value }))}
            options={["", "network_connection", "dns_lookup", "web_request", "failed_login", "successful_login", "firewall_denied"]}
          />
          <TextFilter
            label="Source IP"
            value={filters.source_ip}
            onChange={(value) => setFilters((current) => ({ ...current, source_ip: value }))}
          />
          <TextFilter
            label="Username"
            value={filters.username}
            onChange={(value) => setFilters((current) => ({ ...current, username: value }))}
          />
        </div>
      </div>

      {/* Events Table */}
      {loading ? (
        <LoadingState label="Loading telemetry events" />
      ) : data && data.items.length > 0 ? (
        <EventsTable events={data.items} onSelect={setSelected} />
      ) : (
        <EmptyState title="No events found for current filters" />
      )}

      {/* Event Drawer */}
      {selected ? <EventDrawer event={selected} onClose={() => setSelected(null)} /> : null}

      {/* Zeek Replay Modal */}
      {showReplayModal ? (
        <ZeekReplayModal
          onClose={() => setShowReplayModal(false)}
          onSuccess={(res) => {
            setReplayResult(res);
            loadEvents();
          }}
          lastResult={replayResult}
        />
      ) : null}
    </div>
  );
}

function EventsTable({ events, onSelect }: { events: NormalizedEvent[]; onSelect: (event: NormalizedEvent) => void }) {
  return (
    <div className="overflow-hidden rounded-lg border border-surface-border bg-surface-raised">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1050px] text-left text-sm">
          <thead className="bg-surface-inset text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-3 py-3">Source</th>
              <th className="px-4 py-3">Event Type</th>
              <th className="px-3 py-3">Severity</th>
              <th className="px-4 py-3">Source & Port</th>
              <th className="px-4 py-3">Destination</th>
              <th className="px-4 py-3">Protocol / State</th>
              <th className="px-4 py-3">Message</th>
              <th className="px-3 py-3 text-right"></th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-t border-surface-border hover:bg-surface-inset/70">
                <td className="whitespace-nowrap px-4 py-3 text-zinc-400">{formatDate(event.timestamp)}</td>
                <td className="px-3 py-3">
                  <SourceBadge value={event.source_type} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-200">{event.event_type}</td>
                <td className="px-3 py-3">
                  <SeverityBadge value={event.severity} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">
                  {event.source_ip ?? "-"}
                  {event.source_port ? <span className="text-zinc-500">:{event.source_port}</span> : null}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">
                  {event.destination_ip ?? event.hostname ?? "-"}
                  {event.destination_port ? <span className="text-zinc-500">:{event.destination_port}</span> : null}
                </td>
                <td className="px-4 py-3 text-xs text-zinc-400">
                  {event.protocol ? <span className="font-mono text-zinc-300 uppercase">{event.protocol}</span> : null}
                  {event.connection_state ? (
                    <span className="ml-1 rounded bg-zinc-800 px-1 py-0.5 font-mono text-[10px] text-zinc-400">
                      {event.connection_state}
                    </span>
                  ) : null}
                  {!event.protocol && !event.connection_state && "-"}
                </td>
                <td className="max-w-xs truncate px-4 py-3 text-zinc-400">{event.message}</td>
                <td className="px-3 py-3 text-right">
                  <button
                    className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
                    onClick={() => onSelect(event)}
                    title="Inspect Event"
                  >
                    <Eye className="h-4 w-4" />
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

function EventDrawer({ event, onClose }: { event: NormalizedEvent; onClose: () => void }) {
  const isNetwork = event.source_type === "ZEEK" || Boolean(event.source_port || event.destination_port || event.dns_query);

  return (
    <div className="fixed inset-0 z-40 bg-black/70">
      <aside className="ml-auto flex h-full w-full max-w-2xl flex-col border-l border-surface-border bg-surface-base shadow-glow">
        <div className="flex items-center justify-between border-b border-surface-border px-5 py-4">
          <div className="flex items-center gap-3">
            <SourceBadge value={event.source_type} />
            <div>
              <h2 className="text-base font-semibold text-zinc-50">{event.event_type}</h2>
              <p className="text-xs text-zinc-500">{formatDate(event.timestamp)}</p>
            </div>
          </div>
          <button className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-surface-inset hover:text-zinc-100" onClick={onClose}>
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto p-5">
          {/* Message Banner */}
          <div>
            <div className="mb-2 text-xs uppercase text-zinc-500">Event Message</div>
            <p className="rounded-lg border border-surface-border bg-surface-raised p-3 text-sm text-zinc-200">{event.message}</p>
          </div>

          {/* Network Telemetry Card (Zeek / L4 / DNS) */}
          {isNetwork && (
            <div className="rounded-lg border border-purple-500/30 bg-purple-950/15 p-4">
              <div className="mb-3 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-purple-300">
                  <Activity className="h-4 w-4" />
                  Network & Zeek Connection Flow
                </div>
                {event.connection_state && (
                  <span className="rounded border border-purple-500/40 bg-purple-500/20 px-2 py-0.5 font-mono text-xs text-purple-200">
                    State: {event.connection_state}
                  </span>
                )}
              </div>

              <div className="grid gap-3 text-sm sm:grid-cols-2">
                <div className="rounded border border-purple-500/20 bg-purple-900/20 p-2.5">
                  <div className="text-[11px] text-purple-300">Flow Vector</div>
                  <div className="mt-1 font-mono text-xs text-zinc-200">
                    {event.source_ip}:{event.source_port ?? "?"}{" "}
                    <ArrowRight className="inline h-3 w-3 text-purple-400 mx-1" />{" "}
                    {event.destination_ip}:{event.destination_port ?? "?"}
                  </div>
                </div>

                <div className="rounded border border-purple-500/20 bg-purple-900/20 p-2.5">
                  <div className="text-[11px] text-purple-300">Protocol & UID</div>
                  <div className="mt-1 font-mono text-xs text-zinc-200">
                    <span className="uppercase text-purple-300 font-bold">{event.protocol ?? "N/A"}</span>
                    {event.raw_reference && (
                      <span className="ml-2 text-zinc-400" title="Zeek UID">
                        ({event.raw_reference})
                      </span>
                    )}
                  </div>
                </div>

                <div className="rounded border border-purple-500/20 bg-purple-900/20 p-2.5">
                  <div className="text-[11px] text-purple-300">Bytes Volume</div>
                  <div className="mt-1 font-mono text-xs text-zinc-200">
                    In: <span className="text-purple-300">{event.bytes_in ?? 0} B</span> | Out:{" "}
                    <span className="text-purple-300">{event.bytes_out ?? 0} B</span>
                  </div>
                </div>

                <div className="rounded border border-purple-500/20 bg-purple-900/20 p-2.5">
                  <div className="text-[11px] text-purple-300">Latency / Duration</div>
                  <div className="mt-1 font-mono text-xs text-zinc-200">
                    {event.response_time_ms !== null && event.response_time_ms !== undefined
                      ? `${event.response_time_ms} ms`
                      : "N/A"}
                  </div>
                </div>

                {event.dns_query && (
                  <div className="col-span-2 rounded border border-purple-500/20 bg-purple-900/20 p-2.5">
                    <div className="text-[11px] text-purple-300">DNS Resolution Telemetry</div>
                    <div className="mt-1 font-mono text-xs text-zinc-200">
                      Query: <span className="text-amber-300">{event.dns_query}</span>
                      {event.dns_response && (
                        <div className="mt-1 text-emerald-300">Answer: {event.dns_response}</div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Standard Event Fields Grid */}
          <div className="grid gap-2 sm:grid-cols-2">
            <FieldCard label="Event ID" value={event.event_id ?? event.id} />
            <FieldCard label="Source Type" value={event.source_type} />
            <FieldCard label="Severity" value={event.severity} />
            <FieldCard label="Category" value={event.event_category} />
            <FieldCard label="Source IP" value={event.source_ip} />
            <FieldCard label="Destination IP" value={event.destination_ip} />
            <FieldCard label="Username" value={event.username} />
            <FieldCard label="Hostname" value={event.hostname} />
            {event.request_path && <FieldCard label="Request Path" value={event.request_path} />}
            {event.http_method && <FieldCard label="HTTP Method" value={event.http_method} />}
            {event.status_code && <FieldCard label="HTTP Status" value={event.status_code} />}
            {event.user_agent && <FieldCard label="User Agent" value={event.user_agent} />}
          </div>

          {/* Raw Log Inspection */}
          <div>
            <div className="mb-2 text-xs uppercase text-zinc-500">Raw Telemetry Log</div>
            <pre className="max-h-64 overflow-auto rounded-lg border border-surface-border bg-black/60 p-3 text-xs font-mono text-zinc-300">
              {event.raw_log ?? "-"}
            </pre>
          </div>
        </div>
      </aside>
    </div>
  );
}

function FieldCard({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="rounded-lg border border-surface-border bg-surface-raised p-3">
      <div className="text-[11px] uppercase tracking-wider text-zinc-500">{label}</div>
      <div className="mt-1 break-words font-mono text-xs text-zinc-200">{String(value ?? "-")}</div>
    </div>
  );
}

function ZeekReplayModal({
  onClose,
  onSuccess,
  lastResult,
}: {
  onClose: () => void;
  onSuccess: (result: ZeekReplayResponse) => void;
  lastResult: ZeekReplayResponse | null;
}) {
  const [logType, setLogType] = useState<string>("auto");
  const [mode, setMode] = useState<string>("REPLAY");
  const [content, setContent] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const sampleConnTSV = `#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n1711929600.123456\tCReplay01\t10.0.0.45\t54321\t192.168.1.10\t443\ttcp\tssl\t1.24\t1520\t8420\tSF\n1711929605.654321\tCReplay02\t192.168.1.200\t59123\t10.0.0.1\t22\ttcp\tssh\t0.08\t450\t980\tSF`;

  const sampleHttpJSON = `{"ts":1711929610.123456,"uid":"HReplay01","id.orig_h":"10.0.0.50","id.orig_p":51234,"id.resp_h":"192.168.1.10","id.resp_p":80,"method":"POST","host":"api.internal.corp","uri":"/auth/login","user_agent":"Mozilla/5.0","status_code":401,"request_body_len":64,"response_body_len":128}\n{"ts":1711929612.987654,"uid":"HReplay02","id.orig_h":"10.0.0.50","id.orig_p":51236,"id.resp_h":"192.168.1.10","id.resp_p":80,"method":"GET","host":"api.internal.corp","uri":"/admin/export","user_agent":"sqlmap/1.7","status_code":200,"request_body_len":0,"response_body_len":4096}`;

  const sampleDnsJSON = `{"ts":1711929620.123456,"uid":"DReplay01","id.orig_h":"10.0.0.75","id.orig_p":61234,"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp","query":"malicious-c2.darknet.org","qtype_name":"A","rcode_name":"NOERROR","answers":["198.51.100.44"]}`;

  const handleSubmit = async () => {
    if (!content.trim()) {
      setError("Please select a sample fixture or paste Zeek raw telemetry log lines.");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await replayZeekTelemetry({
        raw_content: content,
        log_type: logType === "auto" ? undefined : logType,
        mode,
      });
      onSuccess(res);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? "Failed to replay telemetry.";
      setError(String(msg));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="w-full max-w-2xl rounded-xl border border-surface-border bg-surface-base p-6 shadow-2xl">
        <div className="flex items-center justify-between border-b border-surface-border pb-4">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-purple-400" />
            <h2 className="text-base font-semibold text-zinc-100">Zeek Telemetry Replay Engine</h2>
          </div>
          <button onClick={onClose} className="rounded p-1 text-zinc-400 hover:text-zinc-100">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="mt-4 space-y-4">
          <p className="text-xs text-zinc-400">
            Replay network connections, HTTP transactions, or DNS queries directly into the SOC telemetry store with microsecond throughput benchmarking.
          </p>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="text-xs uppercase tracking-wider text-zinc-500">Log Type Routing</label>
              <select
                value={logType}
                onChange={(e) => setLogType(e.target.value)}
                className="mt-1 w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-xs text-zinc-200"
              >
                <option value="auto">Auto-detect (from headers or JSON keys)</option>
                <option value="conn">conn.log (Connections)</option>
                <option value="http">http.log (HTTP requests)</option>
                <option value="dns">dns.log (DNS queries)</option>
              </select>
            </div>
            <div>
              <label className="text-xs uppercase tracking-wider text-zinc-500">Mode Classification</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                className="mt-1 w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-xs text-zinc-200"
              >
                <option value="REPLAY">REPLAY (Controlled experiment)</option>
                <option value="SIMULATED">SIMULATED (Synthetic network)</option>
                <option value="LIVE">LIVE (Real sensor telemetry)</option>
              </select>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-zinc-400 mb-1">
              <span>Quick Preset Fixtures:</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setContent(sampleConnTSV);
                    setLogType("conn");
                  }}
                  className="rounded bg-surface-inset px-2 py-0.5 text-[11px] text-purple-300 hover:bg-surface-border"
                >
                  conn.log (TSV)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setContent(sampleHttpJSON);
                    setLogType("http");
                  }}
                  className="rounded bg-surface-inset px-2 py-0.5 text-[11px] text-cyan-300 hover:bg-surface-border"
                >
                  http.log (JSON)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setContent(sampleDnsJSON);
                    setLogType("dns");
                  }}
                  className="rounded bg-surface-inset px-2 py-0.5 text-[11px] text-amber-300 hover:bg-surface-border"
                >
                  dns.log (JSON)
                </button>
              </div>
            </div>
            <textarea
              rows={6}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste Zeek TSV lines (with #fields header) or JSON streaming lines here..."
              className="w-full rounded-lg border border-surface-border bg-surface-inset p-3 font-mono text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-purple-500"
            />
          </div>

          {error && <div className="rounded bg-red-950/40 border border-red-500/30 p-2 text-xs text-red-300">{error}</div>}

          {lastResult && (
            <div className="rounded-lg border border-surface-border bg-surface-inset/80 p-3 text-xs">
              <div className="font-semibold text-emerald-400 mb-1">Latest Replay Benchmark Result:</div>
              <div className="grid grid-cols-2 gap-2 text-zinc-300 sm:grid-cols-4 font-mono text-[11px]">
                <div>Processed: <span className="text-zinc-100">{lastResult.events_processed}</span></div>
                <div>Accepted: <span className="text-emerald-300">{lastResult.events_accepted}</span></div>
                <div>Rejected: <span className="text-amber-300">{lastResult.events_rejected}</span></div>
                <div>Duplicated: <span className="text-blue-300">{lastResult.events_duplicated}</span></div>
                <div>Throughput: <span className="text-purple-300">{lastResult.throughput_eps} eps</span></div>
                <div>Avg Latency: <span className="text-zinc-100">{lastResult.average_latency_ms} ms</span></div>
                <div>Max Latency: <span className="text-zinc-100">{lastResult.maximum_latency_ms} ms</span></div>
                <div>Alerts: <span className="text-orange-300">{lastResult.alert_count}</span></div>
              </div>
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              onClick={onClose}
              className="rounded-lg border border-surface-border px-4 py-2 text-xs font-medium text-zinc-400 hover:bg-surface-inset"
            >
              Close
            </button>
            <button
              disabled={loading}
              onClick={handleSubmit}
              className="focus-ring inline-flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-purple-500 disabled:opacity-50"
            >
              {loading ? (
                "Ingesting & Benchmarking..."
              ) : (
                <>
                  <Play className="h-3.5 w-3.5" />
                  Execute Ingestion Replay
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function FilterInput({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <label>
      <span className="sr-only">{label}</span>
      <select className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm text-zinc-200" value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option || "all"} value={option}>
            {option ? `${label}: ${option}` : `All ${label}s`}
          </option>
        ))}
      </select>
    </label>
  );
}

function TextFilter({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <input
      className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm text-zinc-200 placeholder-zinc-500"
      placeholder={label}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

