import { useEffect, useState } from "react";
import { Eye, Search, X } from "lucide-react";

import { SeverityBadge } from "../components/Badge";
import { EmptyState, LoadingState } from "../components/State";
import { fetchEvents } from "../services/api";
import type { NormalizedEvent, Page } from "../types";
import { formatDate } from "../utils/format";

export function EventsPage() {
  const [data, setData] = useState<Page<NormalizedEvent> | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<NormalizedEvent | null>(null);
  const [filters, setFilters] = useState({ q: "", severity: "", event_type: "", source_ip: "", username: "", hostname: "" });

  useEffect(() => {
    setLoading(true);
    fetchEvents({ ...filters, page_size: 30 })
      .then(setData)
      .finally(() => setLoading(false));
  }, [filters]);

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
        <div className="grid gap-3 md:grid-cols-[minmax(180px,1.5fr)_repeat(5,minmax(120px,1fr))]">
          <label className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
            <input
              className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset py-2 pl-9 pr-3 text-sm"
              placeholder="Search events"
              value={filters.q}
              onChange={(event) => setFilters((current) => ({ ...current, q: event.target.value }))}
            />
          </label>
          <FilterInput label="Severity" value={filters.severity} onChange={(value) => setFilters((current) => ({ ...current, severity: value }))} options={["", "critical", "high", "medium", "low"]} />
          <FilterInput label="Type" value={filters.event_type} onChange={(value) => setFilters((current) => ({ ...current, event_type: value }))} options={["", "failed_login", "successful_login", "web_request", "http_404", "firewall_denied"]} />
          <TextFilter label="Source IP" value={filters.source_ip} onChange={(value) => setFilters((current) => ({ ...current, source_ip: value }))} />
          <TextFilter label="Username" value={filters.username} onChange={(value) => setFilters((current) => ({ ...current, username: value }))} />
          <TextFilter label="Hostname" value={filters.hostname} onChange={(value) => setFilters((current) => ({ ...current, hostname: value }))} />
        </div>
      </div>

      {loading ? <LoadingState label="Loading events" /> : data && data.items.length > 0 ? <EventsTable events={data.items} onSelect={setSelected} /> : <EmptyState title="No events found" />}

      {selected ? <EventDrawer event={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

function EventsTable({ events, onSelect }: { events: NormalizedEvent[]; onSelect: (event: NormalizedEvent) => void }) {
  return (
    <div className="overflow-hidden rounded-lg border border-surface-border bg-surface-raised">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] text-left text-sm">
          <thead className="bg-surface-inset text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">User</th>
              <th className="px-4 py-3">Host</th>
              <th className="px-4 py-3">Message</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-t border-surface-border hover:bg-surface-inset/70">
                <td className="whitespace-nowrap px-4 py-3 text-zinc-400">{formatDate(event.timestamp)}</td>
                <td className="px-4 py-3 text-zinc-200">{event.event_type}</td>
                <td className="px-4 py-3">
                  <SeverityBadge value={event.severity} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">{event.source_ip ?? "-"}</td>
                <td className="px-4 py-3 text-zinc-300">{event.username ?? "-"}</td>
                <td className="px-4 py-3 text-zinc-300">{event.hostname ?? "-"}</td>
                <td className="max-w-sm truncate px-4 py-3 text-zinc-400">{event.message}</td>
                <td className="px-4 py-3 text-right">
                  <button className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100" onClick={() => onSelect(event)}>
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
  const fields = Object.entries(event).filter(([key]) => !["raw_log", "message"].includes(key));
  return (
    <div className="fixed inset-0 z-40 bg-black/70">
      <aside className="ml-auto flex h-full w-full max-w-2xl flex-col border-l border-surface-border bg-surface-base shadow-glow">
        <div className="flex items-center justify-between border-b border-surface-border px-5 py-4">
          <div>
            <h2 className="text-lg font-semibold text-zinc-50">{event.event_type}</h2>
            <p className="text-sm text-zinc-500">{formatDate(event.timestamp)}</p>
          </div>
          <button className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-surface-inset hover:text-zinc-100" onClick={onClose}>
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 space-y-5 overflow-y-auto p-5">
          <div>
            <div className="mb-2 text-xs uppercase text-zinc-500">Message</div>
            <p className="rounded-lg border border-surface-border bg-surface-raised p-3 text-sm text-zinc-200">{event.message}</p>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {fields.map(([key, value]) => (
              <div key={key} className="rounded-lg border border-surface-border bg-surface-raised p-3">
                <div className="text-xs uppercase text-zinc-500">{key}</div>
                <div className="mt-1 break-words text-sm text-zinc-200">{String(value ?? "-")}</div>
              </div>
            ))}
          </div>
          <div>
            <div className="mb-2 text-xs uppercase text-zinc-500">Raw log</div>
            <pre className="max-h-64 overflow-auto rounded-lg border border-surface-border bg-black/40 p-3 text-xs text-zinc-300">{event.raw_log ?? "-"}</pre>
          </div>
        </div>
      </aside>
    </div>
  );
}

function FilterInput({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <label>
      <span className="sr-only">{label}</span>
      <select className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option || "all"} value={option}>
            {option || label}
          </option>
        ))}
      </select>
    </label>
  );
}

function TextFilter({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <input
      className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm"
      placeholder={label}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

