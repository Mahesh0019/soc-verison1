import clsx from "clsx";

export function formatDate(value?: string | null) {
  if (!value) return "-";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function shortNumber(value: number) {
  return new Intl.NumberFormat(undefined, { notation: value > 9999 ? "compact" : "standard" }).format(value);
}

export function severityClass(severity?: string) {
  return clsx(
    "border",
    severity === "critical" && "border-red-400/40 bg-red-500/15 text-red-200",
    severity === "high" && "border-orange-400/40 bg-orange-500/15 text-orange-200",
    severity === "medium" && "border-amber-400/40 bg-amber-500/15 text-amber-100",
    severity === "low" && "border-emerald-400/40 bg-emerald-500/15 text-emerald-100",
    !severity && "border-zinc-600 bg-zinc-800 text-zinc-200",
  );
}

export function statusClass(status?: string) {
  return clsx(
    "border",
    status === "open" && "border-red-400/40 bg-red-500/15 text-red-200",
    status === "investigating" && "border-cyan-400/40 bg-cyan-500/15 text-cyan-100",
    status === "resolved" && "border-emerald-400/40 bg-emerald-500/15 text-emerald-100",
    status === "false_positive" && "border-zinc-500/40 bg-zinc-700/40 text-zinc-200",
    !status && "border-zinc-600 bg-zinc-800 text-zinc-200",
  );
}

