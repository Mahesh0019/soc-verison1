import type { LucideIcon } from "lucide-react";

import { shortNumber } from "../utils/format";

export function MetricCard({ title, value, icon: Icon, tone = "cyan" }: { title: string; value: number; icon: LucideIcon; tone?: "cyan" | "emerald" | "amber" | "red" }) {
  const tones = {
    cyan: "border-cyan-400/20 bg-cyan-400/10 text-cyan-200",
    emerald: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
    amber: "border-amber-400/20 bg-amber-400/10 text-amber-100",
    red: "border-red-400/20 bg-red-400/10 text-red-200",
  };
  return (
    <div className="rounded-lg border border-surface-border bg-surface-raised p-4 shadow-glow">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm text-zinc-400">{title}</p>
          <p className="mt-2 text-2xl font-semibold text-zinc-50">{shortNumber(value)}</p>
        </div>
        <div className={`rounded-lg border p-3 ${tones[tone]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}

