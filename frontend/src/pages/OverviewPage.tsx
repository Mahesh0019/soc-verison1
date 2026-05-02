import { useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, Bell, Database, ShieldAlert } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { SeverityBadge, StatusBadge } from "../components/Badge";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, LoadingState } from "../components/State";
import { fetchDashboard } from "../services/api";
import type { DashboardSummary, SeriesPoint } from "../types";
import { formatDate } from "../utils/format";

const palette = ["#22d3ee", "#34d399", "#fbbf24", "#fb7185", "#a78bfa", "#f97316"];

export function OverviewPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboard()
      .then(setSummary)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState label="Loading dashboard" />;
  if (!summary) return <EmptyState title="Dashboard unavailable" />;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard title="Total events" value={summary.total_events} icon={Database} tone="cyan" />
        <MetricCard title="Total alerts" value={summary.total_alerts} icon={Bell} tone="amber" />
        <MetricCard title="Open critical alerts" value={summary.open_critical_alerts} icon={ShieldAlert} tone="red" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(360px,1fr)]">
        <ChartPanel title="Events over time">
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={summary.events_over_time}>
              <defs>
                <linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#27272a" vertical={false} />
              <XAxis dataKey="label" stroke="#a1a1aa" fontSize={12} />
              <YAxis stroke="#a1a1aa" fontSize={12} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8 }} />
              <Area type="monotone" dataKey="value" stroke="#22d3ee" fill="url(#eventFill)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </ChartPanel>

        <ChartPanel title="Alerts by severity">
          <Donut data={summary.alerts_by_severity} />
        </ChartPanel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <ChartPanel title="Top source IPs">
          <HorizontalBars data={summary.top_source_ips} />
        </ChartPanel>
        <ChartPanel title="Top usernames">
          <HorizontalBars data={summary.top_usernames} />
        </ChartPanel>
        <ChartPanel title="Top event types">
          <HorizontalBars data={summary.top_event_types} />
        </ChartPanel>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <ChartPanel title="Failed vs successful logins">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={summary.login_trends}>
              <CartesianGrid stroke="#27272a" vertical={false} />
              <XAxis dataKey="label" stroke="#a1a1aa" fontSize={12} />
              <YAxis stroke="#a1a1aa" fontSize={12} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8 }} />
              <Legend />
              <Bar dataKey="failed" fill="#fb7185" radius={[4, 4, 0, 0]} />
              <Bar dataKey="successful" fill="#34d399" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>

        <div className="rounded-lg border border-surface-border bg-surface-raised">
          <div className="flex items-center gap-2 border-b border-surface-border px-4 py-3">
            <AlertTriangle className="h-4 w-4 text-amber-200" />
            <h2 className="text-sm font-semibold text-zinc-100">Recent alerts</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead className="text-xs uppercase text-zinc-500">
                <tr>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {summary.recent_alerts.map((alert) => (
                  <tr key={alert.id} className="border-t border-surface-border">
                    <td className="max-w-xs px-4 py-3 text-zinc-200">{alert.title}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge value={alert.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge value={alert.status} />
                    </td>
                    <td className="px-4 py-3 text-zinc-400">{formatDate(alert.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function ChartPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-surface-border bg-surface-raised p-4 shadow-glow">
      <h2 className="mb-4 text-sm font-semibold text-zinc-100">{title}</h2>
      {children}
    </section>
  );
}

function HorizontalBars({ data }: { data: SeriesPoint[] }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} layout="vertical" margin={{ left: 18, right: 12 }}>
        <CartesianGrid stroke="#27272a" horizontal={false} />
        <XAxis type="number" stroke="#a1a1aa" fontSize={12} allowDecimals={false} />
        <YAxis dataKey="label" type="category" width={96} stroke="#a1a1aa" fontSize={12} />
        <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8 }} />
        <Bar dataKey="value" fill="#34d399" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function Donut({ data }: { data: SeriesPoint[] }) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="label" innerRadius={72} outerRadius={104} paddingAngle={3}>
          {data.map((_, index) => (
            <Cell key={index} fill={palette[index % palette.length]} />
          ))}
        </Pie>
        <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8 }} />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}
