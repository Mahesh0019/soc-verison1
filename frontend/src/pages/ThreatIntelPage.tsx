import { FormEvent, useCallback, useEffect, useState } from "react";
import { Plus, Search, Trash2 } from "lucide-react";

import { SeverityBadge } from "../components/Badge";
import { EmptyState, LoadingState } from "../components/State";
import { useAuth } from "../components/AuthProvider";
import { useToast } from "../components/Toast";
import { createIndicator, deleteIndicator, fetchIndicators } from "../services/api";
import type { Page, Severity, ThreatIndicator } from "../types";

export function ThreatIntelPage() {
  const [data, setData] = useState<Page<ThreatIndicator> | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const { can } = useAuth();
  const { notify } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    fetchIndicators({ q: query, page_size: 50 })
      .then(setData)
      .finally(() => setLoading(false));
  }, [query]);

  useEffect(() => {
    load();
  }, [load]);

  async function remove(id: number) {
    await deleteIndicator(id);
    notify("Indicator deleted", "success");
    await load();
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
      <section className="rounded-lg border border-surface-border bg-surface-raised">
        <div className="border-b border-surface-border p-4">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
            <input className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset py-2 pl-9 pr-3 text-sm" placeholder="Search indicators" value={query} onChange={(event) => setQuery(event.target.value)} />
          </div>
        </div>
        {loading ? <LoadingState label="Loading indicators" /> : data && data.items.length ? <IndicatorTable indicators={data.items} canEdit={can("admin")} onDelete={remove} /> : <EmptyState title="No indicators found" />}
      </section>
      {can("admin") ? <IndicatorForm onCreated={load} /> : null}
    </div>
  );
}

function IndicatorTable({ indicators, canEdit, onDelete }: { indicators: ThreatIndicator[]; canEdit: boolean; onDelete: (id: number) => void }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="bg-surface-inset text-xs uppercase text-zinc-500">
          <tr>
            <th className="px-4 py-3">Type</th>
            <th className="px-4 py-3">Value</th>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Description</th>
            <th className="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          {indicators.map((indicator) => (
            <tr key={indicator.id} className="border-t border-surface-border hover:bg-surface-inset/70">
              <td className="px-4 py-3 capitalize text-zinc-300">{indicator.type}</td>
              <td className="px-4 py-3 font-mono text-xs text-zinc-100">{indicator.value}</td>
              <td className="px-4 py-3">
                <SeverityBadge value={indicator.severity} />
              </td>
              <td className="max-w-md px-4 py-3 text-zinc-400">{indicator.description ?? "-"}</td>
              <td className="px-4 py-3 text-right">
                <button className="focus-ring rounded-lg p-2 text-zinc-400 hover:bg-red-500/10 hover:text-red-200" disabled={!canEdit} onClick={() => onDelete(indicator.id)}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IndicatorForm({ onCreated }: { onCreated: () => Promise<void> }) {
  const { notify } = useToast();
  const [form, setForm] = useState({ type: "ip" as ThreatIndicator["type"], value: "", description: "", severity: "medium" as Severity });

  async function submit(event: FormEvent) {
    event.preventDefault();
    await createIndicator(form);
    notify("Indicator added", "success");
    setForm({ type: "ip", value: "", description: "", severity: "medium" });
    await onCreated();
  }

  return (
    <form onSubmit={submit} className="rounded-lg border border-surface-border bg-surface-raised p-4">
      <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-zinc-100">
        <Plus className="h-4 w-4 text-cyan-200" />
        Add indicator
      </h2>
      <div className="space-y-3">
        <select className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" value={form.type} onChange={(event) => setForm((current) => ({ ...current, type: event.target.value as ThreatIndicator["type"] }))}>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="username">Username</option>
        </select>
        <input required className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder="Value" value={form.value} onChange={(event) => setForm((current) => ({ ...current, value: event.target.value }))} />
        <input className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder="Description" value={form.description} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} />
        <select className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" value={form.severity} onChange={(event) => setForm((current) => ({ ...current, severity: event.target.value as Severity }))}>
          {["low", "medium", "high", "critical"].map((severity) => (
            <option key={severity}>{severity}</option>
          ))}
        </select>
        <button className="focus-ring flex w-full items-center justify-center gap-2 rounded-lg bg-zinc-100 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-white">
          <Plus className="h-4 w-4" />
          Add indicator
        </button>
      </div>
    </form>
  );
}
