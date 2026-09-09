import React, { useState } from 'react';
import { testLiveSplunk, LiveSplunkTestResponse } from '../api/client';
import { Database, Play, X, CheckCircle, AlertTriangle } from 'lucide-react';

interface SplunkTestModalProps {
  isOpen: boolean;
  onClose: () => void;
  splQuery: string;
}

export const SplunkTestModal: React.FC<SplunkTestModalProps> = ({ isOpen, onClose, splQuery }) => {
  const [query, setQuery] = useState(splQuery);
  const [earliest, setEarliest] = useState('-24h');
  const [latest, setLatest] = useState('now');
  const [maxEvents, setMaxEvents] = useState(25);
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<LiveSplunkTestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  React.useEffect(() => {
    setQuery(splQuery);
  }, [splQuery]);

  if (!isOpen) return null;

  const handleRunSearch = async () => {
    setIsRunning(true);
    setError(null);
    setResult(null);
    try {
      const res = await testLiveSplunk(query, earliest, latest, maxEvents);
      setResult(res);
      if (!res.success && res.error) {
        setError(res.error);
      }
    } catch (err: any) {
      setError(err.message || 'Splunk search failed');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/75 backdrop-blur-md animate-fadeIn">
      <div className="w-full max-w-3xl rounded-2xl border border-white/[0.1] bg-[#0c0d14]/95 p-6 sm:p-8 shadow-2xl space-y-5 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
          <div className="flex items-center gap-2.5 text-emerald-400">
            <Database className="w-5 h-5 stroke-[1.75]" />
            <h3 className="text-sm font-semibold text-white tracking-tight">Live Splunk Validation (Read-Only)</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/[0.05] transition-colors"
            title="Close modal"
          >
            <X className="w-4 h-4 stroke-[2]" />
          </button>
        </div>

        <p className="text-xs text-zinc-400 font-light leading-relaxed">
          Executes a bounded <code className="text-cyan-300 font-mono bg-white/[0.04] px-1.5 py-0.5 rounded border border-white/[0.08]">oneshot</code> search via Splunk REST API (port 8089). Strictly read-only; never alters server configuration.
        </p>

        <div className="space-y-4 text-xs overflow-y-auto pr-1">
          {/* Query Editor */}
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300">SPL Query</label>
            <textarea
              rows={4}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl p-4 font-mono text-xs leading-relaxed text-zinc-200 focus:outline-none focus:border-cyan-400/50 transition-colors"
            />
          </div>

          {/* Search Bounds */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="space-y-1">
              <label className="block text-xs font-medium text-zinc-400">Earliest Time</label>
              <input
                type="text"
                value={earliest}
                onChange={(e) => setEarliest(e.target.value)}
                placeholder="-24h"
                className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl px-3.5 py-2 font-mono text-xs text-zinc-200 focus:outline-none focus:border-cyan-400/50"
              />
            </div>
            <div className="space-y-1">
              <label className="block text-xs font-medium text-zinc-400">Latest Time</label>
              <input
                type="text"
                value={latest}
                onChange={(e) => setLatest(e.target.value)}
                placeholder="now"
                className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl px-3.5 py-2 font-mono text-xs text-zinc-200 focus:outline-none focus:border-cyan-400/50"
              />
            </div>
            <div className="space-y-1">
              <label className="block text-xs font-medium text-zinc-400">Max Events</label>
              <input
                type="number"
                value={maxEvents}
                onChange={(e) => setMaxEvents(parseInt(e.target.value) || 25)}
                min={1}
                max={100}
                className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl px-3.5 py-2 font-mono text-xs text-zinc-200 focus:outline-none focus:border-cyan-400/50"
              />
            </div>
          </div>

          {/* Run Action */}
          <div className="flex justify-end pt-1">
            <button
              onClick={handleRunSearch}
              disabled={isRunning || !query.trim()}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-400 hover:bg-emerald-300 disabled:opacity-40 text-[#07080b] font-semibold text-xs transition-all shadow-[0_0_15px_rgba(52,211,153,0.2)]"
            >
              <Play className={`w-3.5 h-3.5 stroke-[2] ${isRunning ? 'animate-spin' : ''}`} />
              <span>{isRunning ? 'Executing Search...' : 'Execute Live Search'}</span>
            </button>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-500/[0.06] text-rose-300 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 stroke-[2] shrink-0 mt-0.5 text-rose-400" />
              <div>
                <span className="font-semibold text-rose-200">Splunk Query Error:</span>
                <p className="mt-1 font-mono text-xs leading-relaxed text-zinc-400">{error}</p>
              </div>
            </div>
          )}

          {/* Results Display */}
          {result && (
            <div className="space-y-3 border-t border-white/[0.06] pt-3.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-emerald-400 font-medium">
                  <CheckCircle className="w-4 h-4 stroke-[2]" />
                  <span className="text-xs">Execution Successful</span>
                </div>
                <span className="px-2.5 py-1 rounded-full border border-white/[0.08] bg-white/[0.03] font-mono text-xs text-zinc-300">
                  Hit Count: <strong className="text-emerald-300 font-semibold">{result.hit_count}</strong> events
                </span>
              </div>

              {result.sample_events && result.sample_events.length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-zinc-400 font-medium text-xs">Sample Event Payload:</span>
                  <div className="bg-[#07080b] rounded-xl border border-white/[0.06] p-4 max-h-48 overflow-y-auto font-mono text-xs leading-relaxed text-zinc-300 space-y-2">
                    {result.sample_events.map((ev, i) => (
                      <pre key={i} className="whitespace-pre-wrap border-b border-white/[0.04] pb-2 last:border-0 last:pb-0">
                        {JSON.stringify(ev, null, 2)}
                      </pre>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
