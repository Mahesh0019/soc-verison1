import { useState } from "react";
import { Download, FileJson, FileText, UploadCloud } from "lucide-react";

import { SeverityBadge } from "../components/Badge";
import { EmptyState } from "../components/State";
import { useToast } from "../components/Toast";
import { uploadLogs } from "../services/api";
import type { IngestResponse } from "../types";

const samples = [
  { label: "SSH auth", href: "/sample_logs/ssh_auth.log" },
  { label: "Web access", href: "/sample_logs/web_access.log" },
  { label: "Firewall", href: "/sample_logs/firewall.log" },
  { label: "JSON app", href: "/sample_logs/application_logins.jsonl" },
];

export function UploadLogsPage() {
  const { notify } = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<IngestResponse | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit() {
    if (!file) return;
    setLoading(true);
    setProgress(0);
    try {
      const response = await uploadLogs(file, setProgress);
      setResult(response);
      notify(`Parsed ${response.parsed_count} events and touched ${response.alert_count} alerts`, "success");
    } catch {
      notify("Upload failed", "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
      <section className="rounded-lg border border-surface-border bg-surface-raised p-5">
        <label className="flex min-h-64 cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-zinc-700 bg-surface-inset p-6 text-center hover:border-cyan-400/50">
          <UploadCloud className="mb-4 h-10 w-10 text-cyan-200" />
          <span className="text-sm font-medium text-zinc-100">{file ? file.name : "Select JSON, CSV, TXT, or LOG"}</span>
          <span className="mt-1 text-xs text-zinc-500">2 MB maximum</span>
          <input className="hidden" type="file" accept=".json,.csv,.txt,.log" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
        </label>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button className="focus-ring flex items-center gap-2 rounded-lg bg-zinc-100 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-white" disabled={!file || loading} onClick={submit}>
            <UploadCloud className="h-4 w-4" />
            {loading ? "Uploading" : "Upload logs"}
          </button>
          <div className="h-2 min-w-48 flex-1 overflow-hidden rounded-full bg-surface-inset">
            <div className="h-full bg-cyan-300 transition-all" style={{ width: `${progress}%` }} />
          </div>
        </div>

        <div className="mt-6">
          <h2 className="mb-3 text-sm font-semibold text-zinc-100">Parsed preview</h2>
          {result?.preview.length ? (
            <div className="overflow-x-auto rounded-lg border border-surface-border">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="bg-surface-inset text-xs uppercase text-zinc-500">
                  <tr>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Source</th>
                    <th className="px-4 py-3">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {result.preview.map((event) => (
                    <tr key={event.id} className="border-t border-surface-border">
                      <td className="px-4 py-3 text-zinc-200">{event.event_type}</td>
                      <td className="px-4 py-3">
                        <SeverityBadge value={event.severity} />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-zinc-300">{event.source_ip ?? "-"}</td>
                      <td className="max-w-md truncate px-4 py-3 text-zinc-400">{event.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No preview yet" />
          )}
        </div>
      </section>

      <aside className="space-y-4">
        <section className="rounded-lg border border-surface-border bg-surface-raised p-4">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-100">
            <Download className="h-4 w-4 text-emerald-200" />
            Sample logs
          </h2>
          <div className="space-y-2">
            {samples.map((sample) => (
              <a key={sample.href} className="focus-ring flex items-center justify-between rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800" href={sample.href} download>
                <span className="flex items-center gap-2">
                  {sample.href.endsWith(".jsonl") ? <FileJson className="h-4 w-4 text-cyan-200" /> : <FileText className="h-4 w-4 text-amber-100" />}
                  {sample.label}
                </span>
                <Download className="h-4 w-4 text-zinc-500" />
              </a>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-surface-border bg-surface-raised p-4">
          <h2 className="mb-3 text-sm font-semibold text-zinc-100">Invalid lines</h2>
          {result?.errors.length ? (
            <div className="max-h-64 space-y-2 overflow-auto">
              {result.errors.map((error, index) => (
                <div key={index} className="rounded-md border border-amber-400/20 bg-amber-400/10 p-2 text-xs text-amber-100">
                  {error}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-surface-border bg-surface-inset p-3 text-sm text-zinc-500">None</div>
          )}
        </section>
      </aside>
    </div>
  );
}

