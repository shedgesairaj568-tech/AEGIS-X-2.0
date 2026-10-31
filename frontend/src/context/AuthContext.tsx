import React, { createContext, useContext, useState, useEffect } from 'react';
import type { User } from '../types';
import { api } from '../services/api';
import { soundFX } from '../services/soundEffects';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, pass: string) => Promise<boolean>;
  register: (email: string, fullName: string, pass: string) => Promise<boolean>;
  logout: () => void;
  quickLogin: (role: 'analyst' | 'admin') => Promise<void>;
  isBackendConnected: boolean;
  refreshHealth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);

  const refreshHealth = async () => {
    const health = await api.checkHealth();
    setIsBackendConnected(health.status === 'ok');
  };

  useEffect(() => {
    const initAuth = async () => {
      setIsLoading(true);
      await refreshHealth();
      try {
        const me = await api.getMe();
        if (me) {
          setUser(me);
        }
      } catch (e) {
        console.warn('Could not restore user session', e);
      } finally {
        setIsLoading(false);
      }
    };
    initAuth();
  }, []);

  const login = async (email: string, pass: string): Promise<boolean> => {
    try {
      await api.login(email, pass);
      const me = await api.getMe();
      setUser(me);
      soundFX.playSuccess();
      return true;
    } catch (e) {
      console.error('Login error', e);
      return false;
    }
  };

  const register = async (email: string, fullName: string, pass: string): Promise<boolean> => {
    try {
      await api.register(email, fullName, pass);
      return await login(email, pass);
    } catch (e) {
      console.error('Register error', e);
      return false;
    }
  };

  const logout = () => {
    api.clearTokens();
    setUser(null);
    soundFX.playClick();
  };

  const quickLogin = async (role: 'analyst' | 'admin') => {
    const email = role === 'admin' ? 'admin@aegis-x.io' : 'analyst@aegis-x.io';
    await login(email, 'changeme123');
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        quickLogin,
        isBackendConnected,
        refreshHealth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
};
