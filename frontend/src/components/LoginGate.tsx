import React, { useState } from 'react';
import { Lock, ShieldCheck, AlertCircle, Loader2, Eye, EyeOff, UserPlus, CheckCircle2 } from 'lucide-react';

export interface LoginGateProps {
  onLoginSuccess: (token: string) => void;
}

export const LoginGate: React.FC<LoginGateProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);
    setIsLoading(true);

    try {
      if (isRegisterMode) {
        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            username,
            password,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          setError(errorData.detail || 'Username already registered');
          return;
        }

        setSuccessMessage('Account created successfully! You can now log in.');
        setPassword('');
        setIsRegisterMode(false);
      } else {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            username,
            password,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          setError(errorData.detail || 'Invalid username or password');
          return;
        }

        const data = await response.json();
        const token = data.access_token || data.token;
        if (token) {
          sessionStorage.setItem('auth_token', token);
          onLoginSuccess(token);
        } else {
          setError('Authentication response did not contain an access token.');
        }
      }
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during authentication.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-[80vh] items-center justify-center p-4">
      <div className="w-full max-w-md rounded-2xl border border-white/[0.08] bg-slate-900/80 p-8 shadow-2xl backdrop-blur-xl transition-all">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400 shadow-inner">
            {isRegisterMode ? <UserPlus className="h-7 w-7" /> : <Lock className="h-7 w-7" />}
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-white">
            {isRegisterMode ? 'Register SOC Account' : 'Security Operations Login'}
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            {isRegisterMode
              ? 'ArcSight Rule Migration Suite • Create New Analyst Account'
              : 'ArcSight Rule Migration Suite • Authenticated Vault Access'}
          </p>
        </div>

        {successMessage && (
          <div
            role="status"
            className="mb-5 flex items-start gap-2.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3.5 text-xs text-emerald-300"
          >
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
            <span className="leading-relaxed">{successMessage}</span>
          </div>
        )}

        {error && (
          <div
            role="alert"
            className="mb-5 flex items-start gap-2.5 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-300"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            <span className="leading-relaxed">{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="username"
              className="block text-xs font-medium uppercase tracking-wider text-slate-300"
            >
              Username
            </label>
            <div className="mt-1.5">
              <input
                id="username"
                name="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                disabled={isLoading}
                placeholder="Enter SOC username"
                className="w-full rounded-xl border border-white/[0.1] bg-slate-800/60 px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 shadow-inner outline-none transition focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 disabled:opacity-50"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-xs font-medium uppercase tracking-wider text-slate-300"
            >
              Password
            </label>
            <div className="relative mt-1.5">
              <input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={isRegisterMode ? 'new-password' : 'current-password'}
                required
                disabled={isLoading}
                placeholder={isRegisterMode ? 'Create strong password' : 'Enter password'}
                className="w-full rounded-xl border border-white/[0.1] bg-slate-800/60 px-3.5 py-2.5 pr-10 text-sm text-slate-100 placeholder-slate-500 shadow-inner outline-none transition focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 disabled:opacity-50"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 flex items-center pr-3 text-slate-400 hover:text-slate-200"
                tabIndex={-1}
                aria-label={showPassword ? 'Hide secret' : 'Show secret'}
                title={showPassword ? 'Hide secret' : 'Show secret'}
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={isLoading}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition hover:from-cyan-400 hover:to-blue-500 active:scale-[0.99] disabled:pointer-events-none disabled:opacity-60"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>{isRegisterMode ? 'Registering...' : 'Authenticating...'}</span>
                </>
              ) : isRegisterMode ? (
                <>
                  <UserPlus className="h-4 w-4" />
                  <span>Register Securely</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="h-4 w-4" />
                  <span>Secure Login</span>
                </>
              )}
            </button>
          </div>

          <div className="pt-1 text-center">
            <button
              type="button"
              disabled={isLoading}
              onClick={() => {
                setIsRegisterMode(!isRegisterMode);
                setError(null);
                setSuccessMessage(null);
              }}
              className="text-xs font-medium text-slate-400 transition hover:text-cyan-400 underline-offset-4 hover:underline disabled:opacity-50"
            >
              {isRegisterMode ? 'Already have an account? Back to Login' : 'Create Account'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
