import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { authService } from "../services/authService";
import { getApiErrorMessage } from "../services/apiClient";
import { useAuthStore } from "../store/authStore";

export function RegisterPage() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const login = useAuthStore((s) => s.login);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await authService.register({ email, full_name: fullName, password });
      await login(email, password);
      navigate("/");
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex h-screen items-center justify-center bg-base px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <h1 className="text-lg font-semibold tracking-wide">Create Account</h1>
          <p className="mt-1 text-xs text-text-muted">Register a new SOC analyst account</p>
        </div>

        <form onSubmit={handleSubmit} className="rounded-lg border border-border bg-surface p-6">
          <div className="mb-4">
            <label htmlFor="full_name" className="mb-1.5 block text-xs font-medium text-text-secondary">
              Full Name
            </label>
            <input
              id="full_name"
              required
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full rounded-md border border-border bg-base px-3 py-2 text-sm placeholder:text-text-muted focus:border-accent"
              placeholder="Jordan Analyst"
            />
          </div>
          <div className="mb-4">
            <label htmlFor="email" className="mb-1.5 block text-xs font-medium text-text-secondary">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border border-border bg-base px-3 py-2 text-sm placeholder:text-text-muted focus:border-accent"
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
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-border bg-base px-3 py-2 text-sm placeholder:text-text-muted focus:border-accent"
              placeholder="At least 8 characters"
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
            className="w-full rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-base hover:bg-accent-bright disabled:opacity-50"
          >
            {isLoading ? "Creating account..." : "Create Account"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-text-muted">
          Already have an account?{" "}
          <a href="/login" className="text-accent hover:underline">
            Sign in
          </a>
        </p>
      </div>
    </div>
  );
}
