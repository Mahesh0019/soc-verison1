import { useEffect, useState } from "react";
import { CheckCircle2, FileText, MessageSquarePlus, Search, X } from "lucide-react";

import { SeverityBadge, StatusBadge } from "../components/Badge";
import { EmptyState, LoadingState } from "../components/State";
import { useAuth } from "../components/AuthProvider";
import { useToast } from "../components/Toast";
import { addAlertNote, fetchAlert, fetchAlerts, updateAlertStatus } from "../services/api";
import type { Alert, AlertDetail, AlertStatus, Page } from "../types";
import { formatDate } from "../utils/format";

export function AlertsPage() {
  const [data, setData] = useState<Page<Alert> | null>(null);
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ q: "", severity: "", status: "", source_ip: "", username: "" });

  useEffect(() => {
    setLoading(true);
    fetchAlerts({ ...filters, page_size: 30 })
      .then(setData)
      .finally(() => setLoading(false));
  }, [filters]);

  async function openDetail(alert: Alert) {
    setDetail(await fetchAlert(alert.id));
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
        <div className="grid gap-3 md:grid-cols-[minmax(180px,1.5fr)_repeat(4,minmax(120px,1fr))]">
          <label className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
            <input
              className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset py-2 pl-9 pr-3 text-sm"
              placeholder="Search alerts"
              value={filters.q}
              onChange={(event) => setFilters((current) => ({ ...current, q: event.target.value }))}
            />
          </label>
          <Select value={filters.severity} onChange={(severity) => setFilters((current) => ({ ...current, severity }))} options={["", "critical", "high", "medium", "low"]} label="Severity" />
          <Select value={filters.status} onChange={(status) => setFilters((current) => ({ ...current, status }))} options={["", "open", "investigating", "resolved", "false_positive"]} label="Status" />
          <Text value={filters.source_ip} onChange={(source_ip) => setFilters((current) => ({ ...current, source_ip }))} label="Source IP" />
          <Text value={filters.username} onChange={(username) => setFilters((current) => ({ ...current, username }))} label="Username" />
        </div>
      </div>

      {loading ? <LoadingState label="Loading alerts" /> : data && data.items.length > 0 ? <AlertsTable alerts={data.items} onSelect={openDetail} /> : <EmptyState title="No alerts found" />}

      {detail ? <AlertDrawer detail={detail} onClose={() => setDetail(null)} onRefresh={async () => setDetail(await fetchAlert(detail.id))} /> : null}
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
                <td className="max-w-sm px-4 py-3 text-zinc-200">{alert.title}</td>
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
                  <button className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100" onClick={() => onSelect(alert)}>
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

function AlertDrawer({ detail, onClose, onRefresh }: { detail: AlertDetail; onClose: () => void; onRefresh: () => Promise<void> }) {
  const { can } = useAuth();
  const { notify } = useToast();
  const [note, setNote] = useState("");
  const canInvestigate = can("admin", "analyst");

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

  return (
    <div className="fixed inset-0 z-40 bg-black/70">
      <aside className="ml-auto flex h-full w-full max-w-3xl flex-col border-l border-surface-border bg-surface-base shadow-glow">
        <div className="flex items-start justify-between gap-4 border-b border-surface-border px-5 py-4">
          <div className="space-y-2">
            <h2 className="text-lg font-semibold text-zinc-50">{detail.title}</h2>
            <div className="flex flex-wrap gap-2">
              <SeverityBadge value={detail.severity} />
              <StatusBadge value={detail.status} />
            </div>
          </div>
          <button className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-surface-inset hover:text-zinc-100" onClick={onClose}>
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 space-y-6 overflow-y-auto p-5">
          <p className="rounded-lg border border-surface-border bg-surface-raised p-3 text-sm text-zinc-300">{detail.description}</p>

          {canInvestigate ? (
            <div className="flex flex-wrap gap-2">
              {(["open", "investigating", "resolved", "false_positive"] as AlertStatus[]).map((status) => (
                <button key={status} className="focus-ring rounded-lg border border-surface-border bg-surface-raised px-3 py-2 text-sm capitalize text-zinc-200 hover:bg-surface-inset" onClick={() => changeStatus(status)}>
                  {status.replace("_", " ")}
                </button>
              ))}
            </div>
          ) : null}

          <section>
            <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-100">
              <CheckCircle2 className="h-4 w-4 text-cyan-200" />
              Timeline
            </h3>
            <div className="space-y-3">
              {detail.related_events.slice(0, 12).map((event) => (
                <div key={event.id} className="rounded-lg border border-surface-border bg-surface-raised p-3">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                    <span>{formatDate(event.timestamp)}</span>
                    <span>{event.source_ip ?? "-"}</span>
                    <SeverityBadge value={event.severity} />
                  </div>
                  <p className="mt-2 text-sm text-zinc-200">{event.message}</p>
                </div>
              ))}
            </div>
          </section>

          <section>
            <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-100">
              <MessageSquarePlus className="h-4 w-4 text-emerald-200" />
              Analyst notes
            </h3>
            <div className="space-y-2">
              {detail.notes.map((item) => (
                <div key={item.id} className="rounded-lg border border-surface-border bg-surface-raised p-3 text-sm text-zinc-300">
                  <div className="mb-1 text-xs text-zinc-500">
                    {item.user?.username ?? "analyst"} - {formatDate(item.created_at)}
                  </div>
                  {item.note}
                </div>
              ))}
              {canInvestigate ? (
                <div className="flex gap-2">
                  <textarea className="focus-ring min-h-20 flex-1 rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" value={note} onChange={(event) => setNote(event.target.value)} />
                  <button className="focus-ring rounded-lg bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-950 hover:bg-white" onClick={submitNote}>
                    Add
                  </button>
                </div>
              ) : null}
            </div>
          </section>
        </div>
      </aside>
    </div>
  );
}

function Select({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <select className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" value={value} onChange={(event) => onChange(event.target.value)}>
      {options.map((option) => (
        <option key={option || "all"} value={option}>
          {option || label}
        </option>
      ))}
    </select>
  );
}

function Text({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <input className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder={label} value={value} onChange={(event) => onChange(event.target.value)} />;
}

