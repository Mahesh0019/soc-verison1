import { FormEvent, useCallback, useEffect, useState } from "react";
import { Plus, Search, ToggleLeft, ToggleRight } from "lucide-react";

import { SeverityBadge } from "../components/Badge";
import { EmptyState, LoadingState } from "../components/State";
import { useAuth } from "../components/AuthProvider";
import { useToast } from "../components/Toast";
import { createRule, fetchRules, toggleRule } from "../services/api";
import type { DetectionRule, Page, Severity } from "../types";

export function RulesPage() {
  const [data, setData] = useState<Page<DetectionRule> | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const { can } = useAuth();
  const { notify } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    fetchRules({ q: query, page_size: 100 })
      .then(setData)
      .finally(() => setLoading(false));
  }, [query]);

  useEffect(() => {
    load();
  }, [load]);

  async function onToggle(rule: DetectionRule) {
    await toggleRule(rule.id, !rule.enabled);
    notify(`Rule ${!rule.enabled ? "enabled" : "disabled"}`, "success");
    await load();
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <section className="rounded-lg border border-surface-border bg-surface-raised">
          <div className="flex items-center gap-3 border-b border-surface-border p-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
              <input className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset py-2 pl-9 pr-3 text-sm" placeholder="Search rules" value={query} onChange={(event) => setQuery(event.target.value)} />
            </div>
          </div>
          {loading ? <LoadingState label="Loading rules" /> : data && data.items.length ? <RuleList rules={data.items} canEdit={can("admin")} onToggle={onToggle} /> : <EmptyState title="No rules found" />}
        </section>
        {can("admin") ? <CustomRuleForm onCreated={load} /> : null}
      </div>
    </div>
  );
}

function RuleList({ rules, canEdit, onToggle }: { rules: DetectionRule[]; canEdit: boolean; onToggle: (rule: DetectionRule) => void }) {
  return (
    <div className="divide-y divide-surface-border">
      {rules.map((rule) => (
        <article key={rule.id} className="p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-semibold text-zinc-100">{rule.name}</h2>
                <SeverityBadge value={rule.severity} />
              </div>
              <p className="mt-2 text-sm text-zinc-400">{rule.description}</p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs text-zinc-500">
                <span className="rounded-md bg-surface-inset px-2 py-1">threshold {rule.threshold}</span>
                <span className="rounded-md bg-surface-inset px-2 py-1">{rule.time_window_minutes} min</span>
              </div>
            </div>
            <button className="focus-ring flex items-center gap-2 rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm text-zinc-200" disabled={!canEdit} onClick={() => onToggle(rule)}>
              {rule.enabled ? <ToggleRight className="h-5 w-5 text-emerald-300" /> : <ToggleLeft className="h-5 w-5 text-zinc-500" />}
              {rule.enabled ? "Enabled" : "Disabled"}
            </button>
          </div>
        </article>
      ))}
    </div>
  );
}

function CustomRuleForm({ onCreated }: { onCreated: () => Promise<void> }) {
  const { notify } = useToast();
  const [form, setForm] = useState({ name: "", description: "", severity: "medium" as Severity, eventType: "failed_login", threshold: 3, window: 10 });

  async function submit(event: FormEvent) {
    event.preventDefault();
    await createRule({
      name: form.name,
      description: form.description,
      severity: form.severity,
      enabled: true,
      threshold: form.threshold,
      time_window_minutes: form.window,
      conditions_json: { type: "threshold", filters: { event_type: form.eventType }, group_by: ["source_ip"] },
    });
    notify("Custom rule created", "success");
    setForm({ name: "", description: "", severity: "medium", eventType: "failed_login", threshold: 3, window: 10 });
    await onCreated();
  }

  return (
    <form onSubmit={submit} className="rounded-lg border border-surface-border bg-surface-raised p-4">
      <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-zinc-100">
        <Plus className="h-4 w-4 text-cyan-200" />
        Custom rule
      </h2>
      <div className="space-y-3">
        <Input label="Name" value={form.name} onChange={(name) => setForm((current) => ({ ...current, name }))} />
        <Input label="Description" value={form.description} onChange={(description) => setForm((current) => ({ ...current, description }))} />
        <Input label="Event type" value={form.eventType} onChange={(eventType) => setForm((current) => ({ ...current, eventType }))} />
        <select className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" value={form.severity} onChange={(event) => setForm((current) => ({ ...current, severity: event.target.value as Severity }))}>
          {["low", "medium", "high", "critical"].map((severity) => (
            <option key={severity}>{severity}</option>
          ))}
        </select>
        <div className="grid grid-cols-2 gap-3">
          <NumberInput label="Threshold" value={form.threshold} onChange={(threshold) => setForm((current) => ({ ...current, threshold }))} />
          <NumberInput label="Minutes" value={form.window} onChange={(window) => setForm((current) => ({ ...current, window }))} />
        </div>
        <button className="focus-ring flex w-full items-center justify-center gap-2 rounded-lg bg-zinc-100 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-white">
          <Plus className="h-4 w-4" />
          Create rule
        </button>
      </div>
    </form>
  );
}

function Input({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <input required className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder={label} value={value} onChange={(event) => onChange(event.target.value)} />;
}

function NumberInput({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return <input required min={1} className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder={label} type="number" value={value} onChange={(event) => onChange(Number(event.target.value))} />;
}
