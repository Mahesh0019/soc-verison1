import {
  Activity,
  Bell,
  Crosshair,
  Database,
  FileUp,
  FlaskConical,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Users,
  X,
} from "lucide-react";
import { useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "./AuthProvider";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/events", label: "Events", icon: Activity },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/threat-hunting", label: "Threat Hunting", icon: Crosshair },
  { to: "/research", label: "Research & Benchmarks", icon: FlaskConical },
  { to: "/detection-lab", label: "Detection & ML Lab", icon: Sparkles },
  { to: "/rules", label: "Rules", icon: SlidersHorizontal },
  { to: "/upload", label: "Upload Logs", icon: FileUp },
  { to: "/threat-intel", label: "Threat Intel", icon: Radar },
  { to: "/admin", label: "Admin", icon: Users, adminOnly: true },
];

export function Layout() {
  const [open, setOpen] = useState(false);
  const { user, logout } = useAuth();
  const location = useLocation();
  const title = nav.find((item) => item.to === location.pathname)?.label ?? "Mini SIEM";

  const sidebar = (
    <aside className="flex h-full w-72 flex-col border-r border-surface-border bg-surface-base/95 px-4 py-5">
      <Link to="/" className="focus-ring flex items-center gap-3 rounded-lg px-2 py-2" onClick={() => setOpen(false)}>
        <div className="rounded-lg border border-cyan-400/30 bg-cyan-400/10 p-2 text-cyan-200">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <div className="text-sm font-semibold text-zinc-50">Mini SIEM</div>
          <div className="text-xs text-zinc-500">SOC portfolio lab</div>
        </div>
      </Link>

      <nav className="mt-8 flex flex-1 flex-col gap-1">
        {nav
          .filter((item) => !item.adminOnly || user?.role === "admin")
          .map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                onClick={() => setOpen(false)}
                className={({ isActive }) =>
                  `focus-ring flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
                    isActive ? "bg-zinc-100 text-zinc-950" : "text-zinc-400 hover:bg-surface-inset hover:text-zinc-100"
                  }`
                }
              >
                <Icon className="h-4 w-4" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
      </nav>

      <div className="border-t border-surface-border pt-4">
        <div className="mb-3 rounded-lg bg-surface-raised p-3">
          <div className="text-sm font-medium text-zinc-100">{user?.username}</div>
          <div className="text-xs capitalize text-zinc-500">{user?.role}</div>
        </div>
        <button className="focus-ring flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 hover:bg-surface-inset hover:text-zinc-100" onClick={logout}>
          <LogOut className="h-4 w-4" />
          Sign out
        </button>
      </div>
    </aside>
  );

  return (
    <div className="min-h-screen bg-surface-base text-zinc-100">
      <div className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:block">{sidebar}</div>
      {open ? (
        <div className="fixed inset-0 z-40 bg-black/70 lg:hidden">
          <div className="h-full">{sidebar}</div>
          <button className="focus-ring absolute right-4 top-4 rounded-lg bg-surface-raised p-2 text-zinc-100" onClick={() => setOpen(false)}>
            <X className="h-5 w-5" />
          </button>
        </div>
      ) : null}

      <main className="lg:pl-72">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-surface-border bg-surface-base/90 px-4 backdrop-blur md:px-6">
          <div className="flex items-center gap-3">
            <button className="focus-ring rounded-lg p-2 text-zinc-300 hover:bg-surface-inset lg:hidden" onClick={() => setOpen(true)}>
              <Menu className="h-5 w-5" />
            </button>
            <div>
              <h1 className="text-lg font-semibold text-zinc-50">{title}</h1>
              <p className="text-xs text-zinc-500">Live defensive telemetry lab</p>
            </div>
          </div>
          <div className="hidden items-center gap-2 rounded-lg border border-surface-border bg-surface-raised px-3 py-2 text-xs text-zinc-400 sm:flex">
            <Database className="h-4 w-4 text-emerald-300" />
            API connected
          </div>
        </header>
        <div className="mx-auto w-full max-w-7xl px-4 py-6 md:px-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

