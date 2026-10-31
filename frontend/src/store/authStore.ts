import { create } from "zustand";
import type { User } from "../types/api";
import { authService } from "../services/authService";
import { getApiErrorMessage } from "../services/apiClient";

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isInitialized: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  initialize: () => Promise<void>;
  clearError: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isLoading: false,
  isInitialized: false,
  error: null,

  login: async (email, password) => {
    set({ isLoading: true, error: null });
    try {
      await authService.login({ email, password });
      const user = await authService.getCurrentUser();
      set({ user, isLoading: false });
    } catch (err) {
      set({ error: getApiErrorMessage(err), isLoading: false });
      throw err;
    }
  },

  logout: () => {
    authService.logout();
    set({ user: null });
  },

  initialize: async () => {
    if (!authService.isAuthenticated()) {
      set({ isInitialized: true });
      return;
    }
    try {
      const user = await authService.getCurrentUser();
      set({ user, isInitialized: true });
    } catch {
      authService.logout();
      set({ user: null, isInitialized: true });
    }
  },

  clearError: () => set({ error: null }),
}));
