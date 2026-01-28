"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  getAuthToken,
  setAuthToken,
  clearAuthToken,
  getStoredUser,
  setStoredUser,
} from "@/lib/auth";
import { hsmApi } from "@/lib/api";
import type { User, LoginRequest } from "@/lib/types";

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginRequest) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const initAuth = async () => {
      const token = getAuthToken();
      if (token) {
        const storedUser = getStoredUser();
        if (storedUser) {
          setUser(storedUser);
        }
        // Verify token is still valid
        const response = await hsmApi.me();
        if (response.data?.user) {
          setUser(response.data.user);
          setStoredUser(response.data.user);
        } else {
          // Token invalid, clear auth
          clearAuthToken();
          setUser(null);
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (credentials: LoginRequest) => {
    setIsLoading(true);
    try {
      const response = await hsmApi.login(credentials);
      if (response.data) {
        setAuthToken(response.data.token);
        setStoredUser(response.data.user);
        setUser(response.data.user);
        return { success: true };
      } else {
        return {
          success: false,
          error: response.error?.message || "Login failed",
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Login failed",
      };
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      await hsmApi.logout();
    } finally {
      clearAuthToken();
      setUser(null);
      setIsLoading(false);
      router.push("/login");
    }
  };

  const refreshUser = async () => {
    const response = await hsmApi.me();
    if (response.data?.user) {
      setUser(response.data.user);
      setStoredUser(response.data.user);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
