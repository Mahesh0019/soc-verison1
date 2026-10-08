import clsx from "clsx";

import { severityClass, statusClass } from "../utils/format";

export function SeverityBadge({ value }: { value?: string }) {
  return <span className={clsx("inline-flex items-center rounded-md px-2 py-1 text-xs font-medium capitalize", severityClass(value))}>{value ?? "unknown"}</span>;
}

export function StatusBadge({ value }: { value?: string }) {
  return <span className={clsx("inline-flex items-center rounded-md px-2 py-1 text-xs font-medium capitalize", statusClass(value))}>{value?.replace("_", " ") ?? "unknown"}</span>;
}

export function SourceBadge({ value }: { value?: string }) {
  const v = (value || "WEB").toUpperCase();
  const cls = clsx(
    "inline-flex items-center border px-2 py-0.5 text-xs font-mono rounded font-medium",
    v === "ZEEK" && "border-purple-500/30 bg-purple-500/15 text-purple-300",
    v === "WEB" && "border-cyan-500/30 bg-cyan-500/15 text-cyan-300",
    v === "AUTH" && "border-emerald-500/30 bg-emerald-500/15 text-emerald-300",
    v === "FIREWALL" && "border-amber-500/30 bg-amber-500/15 text-amber-300",
    v === "SYSMON" && "border-blue-500/30 bg-blue-500/15 text-blue-300",
    v === "THREAT_INTEL" && "border-rose-500/30 bg-rose-500/15 text-rose-300",
    !["ZEEK", "WEB", "AUTH", "FIREWALL", "SYSMON", "THREAT_INTEL"].includes(v) && "border-zinc-700 bg-zinc-800 text-zinc-300",
  );
  return <span className={cls}>{v}</span>;
}

