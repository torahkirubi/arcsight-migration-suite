import React, { useState } from 'react';
import { LLMConfig, saveLLMSettings } from '../api/client';
import { Cpu, Server, Key, X, Check, Lock, Loader2, AlertCircle } from 'lucide-react';

interface ModelSelectorProps {
  isOpen: boolean;
  onClose: () => void;
  config: LLMConfig;
  onChange: (updated: LLMConfig) => void;
}

export const ModelSelector: React.FC<ModelSelectorProps> = ({
  isOpen,
  onClose,
  config,
  onChange,
}) => {
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSaveKey = async () => {
    if (!config.api_key || !config.api_key.trim()) {
      setSaveStatus('error');
      setSaveMessage('Please enter an API key first');
      return;
    }

    setSaveStatus('saving');
    setSaveMessage(null);

    try {
      const res = await saveLLMSettings(
        config.provider,
        config.api_key.trim(),
        config.model_name?.trim() || undefined
      );
      setSaveStatus('success');
      setSaveMessage(res.message || 'Key saved to Vault');
      setTimeout(() => {
        setSaveStatus('idle');
        setSaveMessage(null);
      }, 4000);
    } catch (err: any) {
      setSaveStatus('error');
      setSaveMessage(err.message || 'Failed to save key to Vault');
    }
  };

  const handleApply = async () => {
    if (config.provider !== 'lm_studio' && config.api_key && config.api_key.trim() && saveStatus === 'idle') {
      try {
        await saveLLMSettings(
          config.provider,
          config.api_key.trim(),
          config.model_name?.trim() || undefined
        );
      } catch (err) {
        console.warn('Auto-save key to vault on apply warning:', err);
      }
    }
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/75 backdrop-blur-md animate-fadeIn">
      <div className="w-full max-w-xl rounded-2xl border border-white/[0.1] bg-[#0c0d14]/95 p-6 sm:p-8 shadow-2xl space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
          <div className="flex items-center gap-2.5 text-cyan-400">
            <Cpu className="w-5 h-5 stroke-[1.75]" />
            <h3 className="text-sm font-semibold text-white tracking-tight">Dual-Model Routing Engine</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/[0.05] transition-colors"
            title="Close modal"
          >
            <X className="w-4 h-4 stroke-[2]" />
          </button>
        </div>

        <div className="space-y-4 text-xs sm:text-sm">
          {/* Provider Selection */}
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300">Routing Provider</label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <button
                type="button"
                onClick={() =>
                  onChange({
                    ...config,
                    provider: 'lm_studio',
                    custom_base_url: 'http://localhost:1234/v1',
                    model_name: 'qwen2.5-coder-7b-instruct',
                  })
                }
                className={`p-3.5 rounded-xl border text-left flex flex-col gap-1 transition-all ${
                  config.provider === 'lm_studio'
                    ? 'border-cyan-400/40 bg-cyan-400/[0.06] text-cyan-200'
                    : 'border-white/[0.08] bg-white/[0.02] text-zinc-400 hover:bg-white/[0.04]'
                }`}
              >
                <span className="font-semibold text-white flex items-center justify-between text-xs">
                  LM Studio
                  {config.provider === 'lm_studio' && <Check className="w-4 h-4 text-cyan-400 stroke-[2.5]" />}
                </span>
                <span className="text-[11px] text-zinc-400 font-light leading-relaxed">
                  Local offline inference with zero telemetry leaks.
                </span>
              </button>

              <button
                type="button"
                onClick={() =>
                  onChange({
                    ...config,
                    provider: 'gemini',
                    custom_base_url: 'https://generativelanguage.googleapis.com/v1beta/openai',
                    model_name: 'gemini-2.5-flash',
                  })
                }
                className={`p-3.5 rounded-xl border text-left flex flex-col gap-1 transition-all ${
                  config.provider === 'gemini'
                    ? 'border-cyan-400/40 bg-cyan-400/[0.06] text-cyan-200'
                    : 'border-white/[0.08] bg-white/[0.02] text-zinc-400 hover:bg-white/[0.04]'
                }`}
              >
                <span className="font-semibold text-white flex items-center justify-between text-xs">
                  Google Gemini
                  {config.provider === 'gemini' && <Check className="w-4 h-4 text-cyan-400 stroke-[2.5]" />}
                </span>
                <span className="text-[11px] text-zinc-400 font-light leading-relaxed">
                  High-speed reasoning via Gemini 2.5 Flash API.
                </span>
              </button>

              <button
                type="button"
                onClick={() =>
                  onChange({
                    ...config,
                    provider: 'cloud_openai',
                    custom_base_url: 'https://api.openai.com/v1',
                    model_name: 'gpt-4o',
                  })
                }
                className={`p-3.5 rounded-xl border text-left flex flex-col gap-1 transition-all ${
                  config.provider === 'cloud_openai'
                    ? 'border-cyan-400/40 bg-cyan-400/[0.06] text-cyan-200'
                    : 'border-white/[0.08] bg-white/[0.02] text-zinc-400 hover:bg-white/[0.04]'
                }`}
              >
                <span className="font-semibold text-white flex items-center justify-between text-xs">
                  Cloud OpenAI
                  {config.provider === 'cloud_openai' && <Check className="w-4 h-4 text-cyan-400 stroke-[2.5]" />}
                </span>
                <span className="text-[11px] text-zinc-400 font-light leading-relaxed">
                  GPT-4o or OpenAI-compatible endpoint.
                </span>
              </button>
            </div>
          </div>

          {/* Base URL */}
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300">
              API Base URL (OpenAI-compatible)
            </label>
            <div className="relative">
              <Server className="w-3.5 h-3.5 text-zinc-500 absolute left-3.5 top-3" />
              <input
                type="text"
                value={config.custom_base_url || ''}
                onChange={(e) => onChange({ ...config, custom_base_url: e.target.value })}
                placeholder="http://localhost:1234/v1"
                className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl pl-9 pr-4 py-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-400/50 transition-colors"
              />
            </div>
            {config.provider === 'lm_studio' && (
              <p className="text-[11px] text-zinc-500 font-light">
                Inside Docker, use <code className="font-mono text-zinc-400">http://host.docker.internal:1234/v1</code>
              </p>
            )}
          </div>

          {/* Model Identifier */}
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300">Model Identifier</label>
            <input
              type="text"
              value={config.model_name || ''}
              onChange={(e) => onChange({ ...config, model_name: e.target.value })}
              placeholder="e.g. qwen2.5-coder-7b-instruct or gpt-4o"
              className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl px-4 py-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-400/50 transition-colors"
            />
          </div>

          {/* API Key */}
          {config.provider !== 'lm_studio' && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-medium text-zinc-300">API Key</label>
                {saveStatus === 'success' && (
                  <span className="text-[11px] text-emerald-400 flex items-center gap-1 font-medium animate-fadeIn">
                    <Check className="w-3.5 h-3.5 stroke-[2.5]" /> Key saved to Vault
                  </span>
                )}
                {saveStatus === 'error' && (
                  <span className="text-[11px] text-rose-400 flex items-center gap-1 font-medium">
                    <AlertCircle className="w-3.5 h-3.5" /> {saveMessage || 'Failed to save key'}
                  </span>
                )}
              </div>
              <div className="flex gap-2 items-center">
                <div className="relative flex-1">
                  <Key className="w-3.5 h-3.5 text-zinc-500 absolute left-3.5 top-3" />
                  <input
                    type="password"
                    value={config.api_key || ''}
                    onChange={(e) => {
                      onChange({ ...config, api_key: e.target.value });
                      if (saveStatus !== 'idle') {
                        setSaveStatus('idle');
                        setSaveMessage(null);
                      }
                    }}
                    placeholder={config.provider === 'gemini' ? 'AIzaSy...' : 'sk-...'}
                    className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl pl-9 pr-4 py-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-400/50 transition-colors"
                  />
                </div>
                <button
                  type="button"
                  onClick={handleSaveKey}
                  disabled={saveStatus === 'saving' || !config.api_key?.trim()}
                  className="px-3.5 py-2.5 rounded-xl border border-white/[0.1] bg-white/[0.04] hover:bg-white/[0.08] disabled:opacity-50 disabled:cursor-not-allowed text-xs font-medium text-zinc-200 hover:text-white flex items-center gap-1.5 transition-all whitespace-nowrap shadow-sm cursor-pointer"
                  title="Persist API key to SQLite vault"
                >
                  {saveStatus === 'saving' ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                      <span>Saving...</span>
                    </>
                  ) : saveStatus === 'success' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400 stroke-[2.5]" />
                      <span className="text-emerald-300">Saved</span>
                    </>
                  ) : (
                    <>
                      <Lock className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Save Key</span>
                    </>
                  )}
                </button>
              </div>
              <p className="text-[11px] text-zinc-500 font-light">
                Encrypted and persisted to backend SQLite Vault (<code className="font-mono text-zinc-400">vault.db</code>).
              </p>
            </div>
          )}
        </div>

        {/* Action Button */}
        <div className="flex justify-end pt-3 border-t border-white/[0.06]">
          <button
            onClick={handleApply}
            className="px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#07080b] font-semibold text-xs sm:text-sm shadow-[0_0_15px_rgba(34,211,238,0.2)] transition-all cursor-pointer"
          >
            Apply Configuration
          </button>
        </div>
      </div>
    </div>
  );
};
