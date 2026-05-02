import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

import { login as loginRequest } from "../services/api";
import type { Role, User } from "../types";

interface AuthContextValue {
  user: User | null;
  token: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  can: (...roles: Role[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("mini-siem-token"));
  const [user, setUser] = useState<User | null>(() => {
    const stored = localStorage.getItem("mini-siem-user");
    return stored ? (JSON.parse(stored) as User) : null;
  });

  const handleLogin = useCallback(async (username: string, password: string) => {
    const result = await loginRequest(username, password);
    localStorage.setItem("mini-siem-token", result.access_token);
    localStorage.setItem("mini-siem-user", JSON.stringify(result.user));
    setToken(result.access_token);
    setUser(result.user);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("mini-siem-token");
    localStorage.removeItem("mini-siem-user");
    setToken(null);
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({
      user,
      token,
      login: handleLogin,
      logout,
      can: (...roles: Role[]) => Boolean(user && roles.includes(user.role)),
    }),
    [handleLogin, logout, token, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
