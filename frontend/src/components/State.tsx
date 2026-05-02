import { Loader2, SearchX } from "lucide-react";

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex min-h-40 items-center justify-center gap-3 rounded-lg border border-surface-border bg-surface-raised text-sm text-zinc-300">
      <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title = "No results" }: { title?: string }) {
  return (
    <div className="flex min-h-40 flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-surface-border bg-surface-raised text-sm text-zinc-400">
      <SearchX className="h-5 w-5 text-zinc-500" />
      <span>{title}</span>
    </div>
  );
}

