import { FormEvent, useCallback, useEffect, useState } from "react";
import { DatabaseZap, Plus, RotateCcw, Trash2, Users } from "lucide-react";

import { EmptyState, LoadingState } from "../components/State";
import { useToast } from "../components/Toast";
import { clearDemo, createUser, fetchAdminStats, fetchUsers, seedDemo } from "../services/api";
import type { Page, Role, User } from "../types";

export function AdminPage() {
  const { notify } = useToast();
  const [stats, setStats] = useState<Record<string, number> | null>(null);
  const [users, setUsers] = useState<Page<User> | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    const [statsResult, usersResult] = await Promise.all([fetchAdminStats(), fetchUsers({ page_size: 50 })]);
    setStats(statsResult);
    setUsers(usersResult);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function seed() {
    await seedDemo();
    notify("Demo data seeded", "success");
    await load();
  }

  async function clear() {
    await clearDemo();
    notify("Demo data cleared", "success");
    await load();
  }

  if (loading) return <LoadingState label="Loading admin" />;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        {stats
          ? Object.entries(stats).map(([key, value]) => (
              <div key={key} className="rounded-lg border border-surface-border bg-surface-raised p-4">
                <div className="text-xs uppercase text-zinc-500">{key.replace("_", " ")}</div>
                <div className="mt-2 text-2xl font-semibold text-zinc-50">{value}</div>
              </div>
            ))
          : null}
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="rounded-lg border border-surface-border bg-surface-raised">
          <div className="flex items-center gap-2 border-b border-surface-border px-4 py-3">
            <Users className="h-4 w-4 text-cyan-200" />
            <h2 className="text-sm font-semibold text-zinc-100">Users</h2>
          </div>
          {users?.items.length ? <UsersTable users={users.items} /> : <EmptyState title="No users found" />}
        </section>

        <aside className="space-y-4">
          <UserForm onCreated={load} />
          <section className="rounded-lg border border-surface-border bg-surface-raised p-4">
            <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-100">
              <DatabaseZap className="h-4 w-4 text-emerald-200" />
              Demo data
            </h2>
            <div className="grid gap-2">
              <button className="focus-ring flex items-center justify-center gap-2 rounded-lg bg-zinc-100 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-white" onClick={seed}>
                <RotateCcw className="h-4 w-4" />
                Seed demo data
              </button>
              <button className="focus-ring flex items-center justify-center gap-2 rounded-lg border border-red-400/30 bg-red-500/10 px-4 py-2.5 text-sm font-medium text-red-100 hover:bg-red-500/20" onClick={clear}>
                <Trash2 className="h-4 w-4" />
                Clear demo data
              </button>
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

function UsersTable({ users }: { users: User[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead className="bg-surface-inset text-xs uppercase text-zinc-500">
          <tr>
            <th className="px-4 py-3">Username</th>
            <th className="px-4 py-3">Email</th>
            <th className="px-4 py-3">Role</th>
            <th className="px-4 py-3">Created</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id} className="border-t border-surface-border">
              <td className="px-4 py-3 text-zinc-100">{user.username}</td>
              <td className="px-4 py-3 text-zinc-300">{user.email}</td>
              <td className="px-4 py-3 capitalize text-zinc-300">{user.role}</td>
              <td className="px-4 py-3 text-zinc-500">{new Date(user.created_at).toLocaleDateString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UserForm({ onCreated }: { onCreated: () => Promise<void> }) {
  const { notify } = useToast();
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "viewer" as Role });

  async function submit(event: FormEvent) {
    event.preventDefault();
    await createUser(form);
    notify("User created", "success");
    setForm({ username: "", email: "", password: "", role: "viewer" });
    await onCreated();
  }

  return (
    <form onSubmit={submit} className="rounded-lg border border-surface-border bg-surface-raised p-4">
      <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-zinc-100">
        <Plus className="h-4 w-4 text-cyan-200" />
        New user
      </h2>
      <div className="space-y-3">
        <input required className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder="Username" value={form.username} onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))} />
        <input required className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder="Email" value={form.email} onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))} />
        <input required className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" placeholder="Password" type="password" value={form.password} onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))} />
        <select className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-sm" value={form.role} onChange={(event) => setForm((current) => ({ ...current, role: event.target.value as Role }))}>
          <option value="viewer">Viewer</option>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
        <button className="focus-ring flex w-full items-center justify-center gap-2 rounded-lg bg-zinc-100 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-white">
          <Plus className="h-4 w-4" />
          Create user
        </button>
      </div>
    </form>
  );
}
