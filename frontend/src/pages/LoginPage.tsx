import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/authStore";

export function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { login, isLoading, error, clearError } = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    clearError();
    try {
      await login(email, password);
      navigate("/");
    } catch {
      // error is already surfaced via the store's `error` state
    }
  };

  return (
    <div className="relative flex h-screen items-center justify-center overflow-hidden bg-base">
      {/* Restrained radar-sweep background — a slow rotating gradient wedge, low opacity. */}
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <div className="radar-sweep h-[140vmax] w-[140vmax] opacity-[0.07]" />
      </div>
      <div className="pointer-events-none absolute inset-0 [background:radial-gradient(circle_at_center,transparent_0%,#0B1120_70%)]" />

      <div className="relative z-10 w-full max-w-sm px-4">
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
              <path d="M12 2 4 5v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V5l-8-3Z" />
            </svg>
          </div>
          <div className="text-center">
            <h1 className="text-lg font-semibold tracking-wide">AEGIS-X</h1>
            <p className="text-xs text-text-muted font-mono">AUTONOMOUS ENTERPRISE GUARDIAN INTELLIGENCE SYSTEM</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-lg border border-border bg-surface/90 p-6 shadow-2xl shadow-black/40 backdrop-blur-sm"
        >
          <div className="mb-4">
            <label htmlFor="email" className="mb-1.5 block text-xs font-medium text-text-secondary">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border border-border bg-base px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-accent"
              placeholder="analyst@yourcompany.io"
            />
          </div>

          <div className="mb-5">
            <label htmlFor="password" className="mb-1.5 block text-xs font-medium text-text-secondary">
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-border bg-base px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-accent"
              placeholder="••••••••"
            />
          </div>

          {error && (
            <div className="mb-4 rounded-md border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-base transition-colors hover:bg-accent-bright disabled:opacity-50"
          >
            {isLoading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-text-muted">
          No account?{" "}
          <a href="/register" className="text-accent hover:underline">
            Register
          </a>
        </p>
      </div>

      <style>{`
        .radar-sweep {
          border-radius: 9999px;
          background: conic-gradient(from 0deg, transparent 0deg, #FFB454 8deg, transparent 40deg, transparent 360deg);
          animation: radar-spin 8s linear infinite;
        }
        @keyframes radar-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @media (prefers-reduced-motion: reduce) {
          .radar-sweep { animation: none; }
        }
      `}</style>
    </div>
  );
}
