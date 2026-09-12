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
    <div className="login-studio">
      <div className="login-orbit"><span /><span /><span /></div>
      <div className="login-brand"><span className="brand-mark"><ShieldCheck size={16} /></span><span><strong>arc<span>/</span>shift</strong><small>migration studio</small></span></div>
      <div className="login-layout">
        <div className="login-manifest">
          <div className="eyebrow">Detection engineering / 01</div>
          <h1>Move old logic<br /><em>forward.</em></h1>
          <p>A quiet workspace for turning ArcSight rules into reviewed, deployable detections.</p>
          <div className="login-manifest-line"><span>01</span> parse intent <i /> <span>02</span> translate <i /> <span>03</span> ship safely</div>
        </div>
        <div className="login-sheet">
          <div className="login-sheet-icon">{isRegisterMode ? <UserPlus size={18} /> : <Lock size={18} />}</div>
          <div className="eyebrow">{isRegisterMode ? 'Create analyst access' : 'Secure workspace access'}</div>
          <h2>{isRegisterMode ? 'Register SOC Account' : 'Security Operations Login'}</h2>
          <p className="login-sheet-copy">{isRegisterMode ? 'Create an account for your migration workspace.' : 'Sign in to open your protected migration studio.'}</p>

        {successMessage && (
          <div
            role="status"
            className="login-alert success"
          >
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
            <span className="leading-relaxed">{successMessage}</span>
          </div>
        )}

        {error && (
          <div
            role="alert"
            className="login-alert error"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            <span className="leading-relaxed">{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          <div>
            <label
              htmlFor="username"
              className="login-label"
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
                className="login-input"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="password"
              className="login-label"
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
                className="login-input password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="login-toggle"
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

          <div>
            <button
              type="submit"
              disabled={isLoading}
              className="login-submit"
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

          <div className="login-switch">
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
    </div>
  );
};
