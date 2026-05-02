import clsx from "clsx";

import { severityClass, statusClass } from "../utils/format";

export function SeverityBadge({ value }: { value?: string }) {
  return <span className={clsx("inline-flex items-center rounded-md px-2 py-1 text-xs font-medium capitalize", severityClass(value))}>{value ?? "unknown"}</span>;
}

export function StatusBadge({ value }: { value?: string }) {
  return <span className={clsx("inline-flex items-center rounded-md px-2 py-1 text-xs font-medium capitalize", statusClass(value))}>{value?.replace("_", " ") ?? "unknown"}</span>;
}

