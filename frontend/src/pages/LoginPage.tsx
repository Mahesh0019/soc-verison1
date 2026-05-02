import { FormEvent, useState } from "react";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { Navigate, useNavigate } from "react-router-dom";

import { useAuth } from "../components/AuthProvider";
import { useToast } from "../components/Toast";

export function LoginPage() {
  const { login, token } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("AdminPass123!");
  const [loading, setLoading] = useState(false);

  if (token) return <Navigate to="/" replace />;

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    try {
      await login(username, password);
      navigate("/");
    } catch {
      notify("Invalid username or password", "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-base px-4">
      <form onSubmit={onSubmit} className="w-full max-w-md rounded-lg border border-surface-border bg-surface-raised p-6 shadow-glow">
        <div className="mb-8 flex items-center gap-3">
          <div className="rounded-lg border border-cyan-400/30 bg-cyan-400/10 p-3 text-cyan-200">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-zinc-50">Mini SIEM</h1>
            <p className="text-sm text-zinc-500">Security operations dashboard</p>
          </div>
        </div>

        <label className="mb-4 block text-sm">
          <span className="mb-2 block text-zinc-300">Username</span>
          <input className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-zinc-100" value={username} onChange={(event) => setUsername(event.target.value)} />
        </label>

        <label className="mb-6 block text-sm">
          <span className="mb-2 block text-zinc-300">Password</span>
          <input
            className="focus-ring w-full rounded-lg border border-surface-border bg-surface-inset px-3 py-2 text-zinc-100"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>

        <button className="focus-ring flex w-full items-center justify-center gap-2 rounded-lg bg-zinc-100 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-white" disabled={loading}>
          <LockKeyhole className="h-4 w-4" />
          {loading ? "Signing in" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

