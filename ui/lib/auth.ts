import type { User } from "./types";

const TOKEN_KEY = "hsm_auth_token";
const USER_KEY = "hsm_auth_user";

export function getAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setAuthToken(token: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;
  const userJson = localStorage.getItem(USER_KEY);
  if (!userJson) return null;
  try {
    return JSON.parse(userJson) as User;
  } catch {
    return null;
  }
}

export function setStoredUser(user: User): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function isAuthenticated(): boolean {
  return !!getAuthToken();
}

export function hasRole(user: User | null, role: string): boolean {
  if (!user) return false;
  const lowerRole = role.toLowerCase();
  const lowerRoles = user.roles.map(r => r.toLowerCase());
  return lowerRoles.includes(lowerRole) || lowerRoles.includes("admin");
}

export function hasNamespaceAccess(user: User | null, namespace: string): boolean {
  if (!user) return false;
  if (user.roles.includes("admin") || user.roles.includes("Admin")) return true;
  return user.namespace === namespace || user.namespace === "*";
}
