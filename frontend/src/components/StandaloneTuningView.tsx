import React, { useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Copy, Loader2, Sparkles } from 'lucide-react';
import { apiFetch, LLMConfig, TelemetryTuneResponse } from '../api/client';
import { TelemetryTunerCard } from './TelemetryTunerCard';

export interface TuneResponse extends TelemetryTuneResponse {
  tuned_kql?: string | null;
}
export interface StandaloneTuningViewProps { initialKql?: string; initialThreshold?: number; llmConfig?: LLMConfig; }

export const StandaloneTuningView: React.FC<StandaloneTuningViewProps> = ({ initialKql = '', initialThreshold = 1, llmConfig }) => {
  const [rawKql, setRawKql] = useState(initialKql);
  const [currentThreshold, setCurrentThreshold] = useState<number | string>(initialThreshold);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [tuningResult, setTuningResult] = useState<TuneResponse | null>(null);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      const response = await apiFetch('/telemetry/tune', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_kql: rawKql,
          current_threshold: Number(currentThreshold) || 1,
          ...(llmConfig ? { llm_config: llmConfig } : {}),
        }),
      });
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Telemetry tuning failed with status ${response.status}`);
      }
      setTuningResult(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze telemetry');
    } finally {
      setIsLoading(false);
    }
  };

  const copyTunedQuery = async () => {
    if (!tuningResult?.tuned_kql) return;
    await navigator.clipboard?.writeText(tuningResult.tuned_kql);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="telemetry-lab">
      <div className="telemetry-lab-intro">
        <div><span className="eyebrow">Signal instrument / live</span><h2>Find the quietest useful threshold.</h2><p>Give the lab a KQL signal and its current threshold. Sentinel history will show where noise becomes meaningful.</p></div>
        <div className="telemetry-badge"><Activity size={14} /> connected to Log Analytics</div>
      </div>
      <form onSubmit={handleSubmit} className="telemetry-console">
        <div className="telemetry-console-head"><span className="source-index">T</span><div><strong>Telemetry probe</strong><small>Read-only analysis · 7-day historical window</small></div></div>
        <label htmlFor="raw_kql" className="telemetry-label">Raw KQL Query</label>
        <textarea id="raw_kql" name="raw_kql" value={rawKql} onChange={(event) => setRawKql(event.target.value)} required disabled={isLoading} placeholder="// Enter raw Microsoft Sentinel / Defender KQL query here..." className="telemetry-query" />
        <div className="telemetry-controls">
          <label htmlFor="current_threshold" className="telemetry-threshold"><span>Current Threshold</span><input id="current_threshold" name="current_threshold" type="number" min="1" value={currentThreshold} onChange={(event) => setCurrentThreshold(event.target.value)} disabled={isLoading} /></label>
          <button type="submit" aria-label="Analyze Telemetry" className="studio-button primary" disabled={isLoading || !rawKql.trim()}>{isLoading ? <Loader2 className="animate-spin" size={15} /> : <Sparkles size={15} />}{isLoading ? 'Reading signal…' : 'Run the probe'}</button>
        </div>
      </form>
      {error && <div className="lab-error"><AlertTriangle size={15} />{error}</div>}
      {tuningResult && <div className="telemetry-results"><TelemetryTunerCard tuning_recommendation={tuningResult} />{tuningResult.tuned_kql && <div className="tuned-query"><div><span className="eyebrow">Suggested expression</span><h3>Apply the tuned KQL</h3><span className="sr-only">Auto-Mitigated Query</span></div><button className="round-action" onClick={copyTunedQuery} title="Copy tuned KQL" aria-label="Copy tuned KQL">{copied ? <CheckCircle2 size={15} /> : <Copy size={15} />}</button><pre>{tuningResult.tuned_kql}</pre></div>}{tuningResult.noise_diagnostics && <div className="diagnostic-strip"><span className="eyebrow">Pattern found</span><span className="sr-only">Noise Source</span><strong>{tuningResult.noise_diagnostics.noise_source}</strong><span className="sr-only">Affected Entities</span><div className="diagnostic-entities">{tuningResult.noise_diagnostics.affected_entities.map((entity) => <span key={entity}>{entity}</span>)}</div><span className="sr-only">Mitigation Steps</span><div className="diagnostic-steps">{tuningResult.noise_diagnostics.mitigation_steps.map((step) => <p key={step}>{step}</p>)}</div></div>}</div>}
    </div>
  );
};
