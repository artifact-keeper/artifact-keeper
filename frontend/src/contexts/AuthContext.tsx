import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { authApi } from '../api';
import apiClient from '../api/client';
import type { User, LoginResponse } from '../types';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  mustChangePassword: boolean;
  login: (username: string, password: string) => Promise<boolean>; // returns true if must change password
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  clearMustChangePassword: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [mustChangePassword, setMustChangePassword] = useState(false);

  const isAuthenticated = !!user;

  function storeTokens(response: LoginResponse): void {
    localStorage.setItem('access_token', response.access_token);
    localStorage.setItem('refresh_token', response.refresh_token);
  }

  function clearTokens(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }

  const refreshUser = useCallback(async () => {
    try {
      const userData = await authApi.getCurrentUser();
      setUser(userData);
    } catch {
      setUser(null);
      clearTokens();
    }
  }, []);

  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    const response = await authApi.login({ username, password });
    storeTokens(response);
    await refreshUser();

    if (response.must_change_password) {
      setMustChangePassword(true);
      return true;
    }
    return false;
  }, [refreshUser]);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      // Ignore logout errors
    } finally {
      clearTokens();
      setUser(null);
      setMustChangePassword(false);
    }
  }, []);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    if (!user) throw new Error('Not authenticated');

    await apiClient.post(`/api/v1/users/${user.id}/password`, {
      current_password: currentPassword,
      new_password: newPassword,
    });

    setMustChangePassword(false);
  }, [user]);

  const clearMustChangePassword = useCallback(() => {
    setMustChangePassword(false);
  }, []);

  // Check for existing token on mount, auto-login in demo mode
  useEffect(() => {
    async function initAuth(): Promise<void> {
      const token = localStorage.getItem('access_token');
      if (token) {
        await refreshUser();
        setIsLoading(false);
        return;
      }

      // In demo mode, auto-login as admin so visitors see the full UI
      await attemptDemoAutoLogin();
      setIsLoading(false);
    }

    async function attemptDemoAutoLogin(): Promise<void> {
      try {
        const healthRes = await fetch('/health');
        const health = await healthRes.json();
        if (health.demo_mode !== true) return;

        const loginRes = await authApi.login({ username: 'admin', password: 'demo' });
        storeTokens(loginRes);
        await refreshUser();
      } catch {
        // Health check or demo auto-login failed, continue as anonymous
      }
    }

    initAuth();
  }, [refreshUser]);

  return (
    <AuthContext.Provider value={{
      user,
      isAuthenticated,
      isLoading,
      mustChangePassword,
      login,
      logout,
      refreshUser,
      changePassword,
      clearMustChangePassword,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
