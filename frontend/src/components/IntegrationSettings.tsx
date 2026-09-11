import React, { useState } from 'react';
import { Shield, CheckCircle2, AlertCircle, Loader2, Eye, EyeOff, Sliders } from 'lucide-react';
import { apiFetch } from '../api/client';

export interface IntegrationSettingsProps {
  onClose?: () => void;
  onSaved?: () => void;
}

export const IntegrationSettings: React.FC<IntegrationSettingsProps> = ({
  onClose,
  onSaved,
}) => {
  const [tenantId, setTenantId] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [workspaceId, setWorkspaceId] = useState('');
  const [showSecret, setShowSecret] = useState(false);

  const [isTesting, setIsTesting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [saveMessage, setSaveMessage] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  const handleTestConnection = async () => {
    setIsTesting(true);
    setStatusMessage(null);
    try {
      const res = await apiFetch('/settings/sentinel/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant_id: tenantId,
          client_id: clientId,
          client_secret: clientSecret,
          workspace_id: workspaceId,
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setStatusMessage({
          type: 'success',
          message: data.message || 'Connection Successful',
        });
      } else {
        setStatusMessage({
          type: 'error',
          message: data.error || 'Connection Failed',
        });
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        message: err.message || 'Connection Failed: Network or Server Error',
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSaveConfiguration = async () => {
    setIsSaving(true);
    setSaveMessage(null);
    try {
      const res = await apiFetch('/settings/sentinel', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant_id: tenantId,
          client_id: clientId,
          client_secret: clientSecret,
          workspace_id: workspaceId,
        }),
      });
      const data = await res.json();
      if (res.ok && (data.success || data.status === 'success')) {
        setSaveMessage({
          type: 'success',
          message: data.message || 'Configuration Saved Successfully',
        });
        if (onSaved) {
          onSaved();
        }
      } else {
        setSaveMessage({
          type: 'error',
          message: data.error || data.detail || 'Failed to save configuration',
        });
      }
    } catch (err: any) {
      setSaveMessage({
        type: 'error',
        message: err.message || 'Failed to save configuration',
      });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="w-full max-w-xl rounded-2xl border border-white/[0.08] bg-[#0c0d14]/95 p-6 sm:p-8 space-y-6 shadow-2xl backdrop-blur-md">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
        <div className="flex items-center gap-2.5 text-cyan-400">
          <Sliders className="w-5 h-5 stroke-[1.75]" />
          <div>
            <h3 className="text-base font-semibold text-white tracking-tight">
              Microsoft Sentinel Integration
            </h3>
            <p className="text-xs text-zinc-400 font-light mt-0.5">
              Configure Azure tenant and Log Analytics credentials for live ASIM schema querying and baseline telemetry.
            </p>
          </div>
        </div>
      </div>

      {/* Form Fields */}
      <div className="space-y-4">
        {/* Tenant ID */}
        <div className="space-y-1.5">
          <label htmlFor="tenant-id" className="block text-xs font-medium text-zinc-300">
            Tenant ID
          </label>
          <input
            id="tenant-id"
            type="text"
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="e.g. 00000000-0000-0000-0000-000000000000"
            className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-cyan-400/50 rounded-xl px-4 py-2.5 text-xs sm:text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none transition-all"
          />
        </div>

        {/* Client ID */}
        <div className="space-y-1.5">
          <label htmlFor="client-id" className="block text-xs font-medium text-zinc-300">
            Client ID
          </label>
          <input
            id="client-id"
            type="text"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            placeholder="e.g. 00000000-0000-0000-0000-000000000000"
            className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-cyan-400/50 rounded-xl px-4 py-2.5 text-xs sm:text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none transition-all"
          />
        </div>

        {/* Client Secret */}
        <div className="space-y-1.5">
          <label htmlFor="client-secret" className="block text-xs font-medium text-zinc-300">
            Client Secret
          </label>
          <div className="relative">
            <input
              id="client-secret"
              type={showSecret ? 'text' : 'password'}
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder="••••••••••••••••••••••••"
              className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-cyan-400/50 rounded-xl px-4 py-2.5 pr-10 text-xs sm:text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none transition-all font-mono"
            />
            <button
              type="button"
              onClick={() => setShowSecret(!showSecret)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 transition-colors"
              title={showSecret ? 'Hide secret' : 'Show secret'}
            >
              {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Workspace ID */}
        <div className="space-y-1.5">
          <label htmlFor="workspace-id" className="block text-xs font-medium text-zinc-300">
            Workspace ID
          </label>
          <input
            id="workspace-id"
            type="text"
            value={workspaceId}
            onChange={(e) => setWorkspaceId(e.target.value)}
            placeholder="e.g. 00000000-0000-0000-0000-000000000000"
            className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-cyan-400/50 rounded-xl px-4 py-2.5 text-xs sm:text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none transition-all"
          />
        </div>
      </div>

      {/* Feedback Messages */}
      {statusMessage && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-start gap-2.5 animate-fadeIn ${
            statusMessage.type === 'success'
              ? 'border-emerald-500/30 bg-emerald-500/[0.08] text-emerald-300'
              : 'border-rose-500/30 bg-rose-500/[0.08] text-rose-300'
          }`}
        >
          {statusMessage.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          )}
          <span className="font-medium">{statusMessage.message}</span>
        </div>
      )}

      {saveMessage && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-start gap-2.5 animate-fadeIn ${
            saveMessage.type === 'success'
              ? 'border-cyan-500/30 bg-cyan-500/[0.08] text-cyan-300'
              : 'border-rose-500/30 bg-rose-500/[0.08] text-rose-300'
          }`}
        >
          {saveMessage.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          ) : (
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          )}
          <span className="font-medium">{saveMessage.message}</span>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex flex-col sm:flex-row items-center justify-end gap-3 pt-2">
        <button
          type="button"
          onClick={handleTestConnection}
          disabled={isTesting}
          className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.1] text-xs font-medium text-zinc-200 hover:text-white transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
        >
          {isTesting ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
              <span>Testing Connection...</span>
            </>
          ) : (
            <>
              <Shield className="w-4 h-4 text-cyan-400" />
              <span>Test Connection</span>
            </>
          )}
        </button>

        <button
          type="button"
          onClick={handleSaveConfiguration}
          disabled={isSaving}
          className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-semibold text-xs transition-all shadow-[0_0_15px_rgba(6,182,212,0.25)] hover:shadow-[0_0_20px_rgba(6,182,212,0.4)] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
        >
          {isSaving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Saving...</span>
            </>
          ) : (
            <>
              <CheckCircle2 className="w-4 h-4" />
              <span>Save Configuration</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
