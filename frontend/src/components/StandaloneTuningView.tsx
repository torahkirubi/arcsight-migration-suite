import React, { useState } from 'react';
import {
  Activity,
  Layers,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Sparkles,
  Code2,
  Copy,
  Check,
} from 'lucide-react';
import { TelemetryTuneResponse } from '../api/client';
import { TelemetryTunerCard } from './TelemetryTunerCard';

export interface TuneResponse extends TelemetryTuneResponse {
  tuned_kql?: string | null;
}

export interface StandaloneTuningViewProps {
  initialKql?: string;
  initialThreshold?: number;
}

export const StandaloneTuningView: React.FC<StandaloneTuningViewProps> = ({
  initialKql = '',
  initialThreshold = 1,
}) => {
  const [rawKql, setRawKql] = useState(initialKql);
  const [currentThreshold, setCurrentThreshold] = useState<number | string>(initialThreshold);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [tuningResult, setTuningResult] = useState<TuneResponse | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const token = sessionStorage.getItem('auth_token') || sessionStorage.getItem('token');
      const response = await fetch('/api/telemetry/tune', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          raw_kql: rawKql,
          current_threshold: Number(currentThreshold) || 1,
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Telemetry tuning failed with status ${response.status}`);
      }

      const data: TuneResponse = await response.json();
      setTuningResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze telemetry');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyTunedKql = () => {
    if (tuningResult?.tuned_kql && navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(tuningResult.tuned_kql);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Configuration & Input Card */}
      <div className="rounded-2xl border border-white/[0.08] bg-slate-900/80 p-6 shadow-2xl backdrop-blur-xl">
        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400 shadow-inner">
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold tracking-tight text-white">
                Historical Telemetry Baselining & Tuning
              </h2>
              <p className="text-xs text-slate-400">
                Execute live Log Analytics queries to evaluate false positive baseline noise
              </p>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-300">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="raw_kql"
              className="block text-xs font-medium uppercase tracking-wider text-slate-300"
            >
              Raw KQL Query
            </label>
            <div className="mt-1.5">
              <textarea
                id="raw_kql"
                name="raw_kql"
                rows={6}
                value={rawKql}
                onChange={(e) => setRawKql(e.target.value)}
                required
                disabled={isLoading}
                placeholder="// Enter raw Microsoft Sentinel / Defender KQL query here..."
                className="w-full rounded-xl border border-white/[0.1] bg-slate-950/70 p-4 font-mono text-xs text-cyan-200 placeholder-slate-600 shadow-inner outline-none transition focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 disabled:opacity-50"
              />
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pt-1">
            <div className="w-full sm:w-48">
              <label
                htmlFor="current_threshold"
                className="block text-xs font-medium uppercase tracking-wider text-slate-300"
              >
                Current Threshold
              </label>
              <div className="mt-1.5">
                <input
                  id="current_threshold"
                  name="current_threshold"
                  type="number"
                  min="1"
                  value={currentThreshold}
                  onChange={(e) => setCurrentThreshold(e.target.value)}
                  disabled={isLoading}
                  className="w-full rounded-xl border border-white/[0.1] bg-slate-800/60 px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 shadow-inner outline-none transition focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 disabled:opacity-50"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading || !rawKql.trim()}
              className="flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-2.5 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition hover:from-cyan-400 hover:to-blue-500 active:scale-[0.99] disabled:pointer-events-none disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <Sparkles className="h-4 w-4" />
                  <span>Analyze Telemetry</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Baselined Telemetry Tuning Recommendation Card */}
      {tuningResult && (
        <div className="space-y-6 animate-fadeIn">
          <TelemetryTunerCard tuning_recommendation={tuningResult} />

          {/* AI Noise Diagnostics Section */}
          {tuningResult.noise_diagnostics && (
            <div className="rounded-2xl border border-white/[0.08] bg-slate-900/80 p-6 shadow-2xl backdrop-blur-xl">
              <div className="mb-4 flex items-center justify-between border-b border-white/[0.06] pb-3">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-purple-500/30 bg-purple-500/10 text-purple-400">
                    <Sparkles className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">AI Noise Diagnostics</h3>
                    <p className="text-[11px] text-slate-400">
                      Gemini telemetry pattern classification and exclusion guidance
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 rounded-full border border-purple-500/20 bg-purple-500/10 px-2.5 py-1 text-[11px] font-medium text-purple-300">
                  <Layers className="h-3 w-3" />
                  <span>Automated Root Cause</span>
                </div>
              </div>

              <div className="space-y-4 text-xs">
                {/* Noise Source */}
                <div>
                  <span className="block text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Noise Source
                  </span>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="inline-flex items-center rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 font-medium text-amber-300">
                      {tuningResult.noise_diagnostics.noise_source}
                    </span>
                  </div>
                </div>

                {/* Affected Entities */}
                <div>
                  <span className="block text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Affected Entities
                  </span>
                  <ul className="mt-1.5 list-disc space-y-1 pl-4 text-slate-200">
                    {tuningResult.noise_diagnostics.affected_entities.map((entity, idx) => (
                      <li key={idx} className="font-mono text-[11px] text-cyan-300">
                        {entity}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Mitigation Steps */}
                <div>
                  <span className="block text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Mitigation Steps
                  </span>
                  <div className="mt-1.5 space-y-2">
                    {tuningResult.noise_diagnostics.mitigation_steps.map((step, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-2.5 rounded-xl border border-emerald-500/20 bg-emerald-500/[0.04] p-3 text-emerald-200"
                      >
                        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                        <span className="leading-relaxed">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Auto-Mitigated Query Section */}
          {tuningResult.tuned_kql && (
            <div className="rounded-2xl border border-white/[0.08] bg-slate-900/80 p-6 shadow-2xl backdrop-blur-xl">
              <div className="mb-4 flex items-center justify-between border-b border-white/[0.06] pb-3">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
                    <Code2 className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">Auto-Mitigated Query</h3>
                    <p className="text-[11px] text-slate-400">
                      Optimized KQL query with noise exclusions injected prior to aggregations
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleCopyTunedKql}
                  className="flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-slate-800/60 px-2.5 py-1.5 text-xs text-slate-300 transition hover:bg-slate-700/60 hover:text-white"
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      <span className="text-emerald-300">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5 text-slate-400" />
                      <span>Copy KQL</span>
                    </>
                  )}
                </button>
              </div>

              <div className="relative">
                <pre className="overflow-x-auto rounded-lg border border-white/[0.08] bg-slate-900/50 p-4 font-mono text-xs text-cyan-100 shadow-inner">
                  <code>{tuningResult.tuned_kql}</code>
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

