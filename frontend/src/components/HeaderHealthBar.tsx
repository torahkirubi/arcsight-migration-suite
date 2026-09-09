import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchHealth, LLMConfig } from '../api/client';
import { Shield, Server, Cpu, Database, RefreshCw, History, SlidersHorizontal, Settings } from 'lucide-react';

interface HeaderHealthBarProps {
  llmConfig: LLMConfig;
  onOpenSettings: () => void;
  onOpenAuditLog: () => void;
  activeTab?: 'translate' | 'settings';
  onSelectTab?: (tab: 'translate' | 'settings') => void;
}

export const HeaderHealthBar: React.FC<HeaderHealthBarProps> = ({
  llmConfig,
  onOpenSettings,
  onOpenAuditLog,
  activeTab = 'translate',
  onSelectTab,
}) => {
  const [showTooltip, setShowTooltip] = useState<string | null>(null);

  // Background health poll every 30 seconds
  const { data, refetch, isFetching } = useQuery({
    queryKey: ['system-health', llmConfig.provider, llmConfig.custom_base_url, llmConfig.api_key],
    queryFn: () => fetchHealth(llmConfig.provider, llmConfig.custom_base_url, llmConfig.api_key),
    refetchInterval: 30000,
    refetchIntervalInBackground: true,
    staleTime: 15000,
    retry: 1,
  });

  const getStatusColor = (status?: string) => {
    switch (status) {
      case 'online':
      case 'connected':
        return 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]';
      case 'degraded':
      case 'unauthorized':
        return 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)]';
      case 'unreachable':
      default:
        return 'bg-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.5)]';
    }
  };

  const getStatusBadgeClass = (status?: string) => {
    switch (status) {
      case 'online':
      case 'connected':
        return 'border-emerald-500/20 bg-emerald-500/[0.04] text-emerald-300/90';
      case 'degraded':
      case 'unauthorized':
        return 'border-amber-500/20 bg-amber-500/[0.04] text-amber-300/90';
      case 'unreachable':
      default:
        return 'border-rose-500/20 bg-rose-500/[0.04] text-rose-300/90';
    }
  };

  const apiStatus = data?.services?.fastapi;
  const llmStatus = data?.services?.llm;
  const splunkStatus = data?.services?.splunk;

  return (
    <header className="border-b border-white/[0.06] bg-[#07080b]/80 backdrop-blur-xl sticky top-0 z-40 px-4 sm:px-6 lg:px-8 py-3.5 transition-all">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 max-w-7xl mx-auto">
        {/* Brand & Suite Identification */}
        <div
          onClick={() => onSelectTab?.('translate')}
          className="flex items-center gap-3.5 cursor-pointer select-none group"
        >
          <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.08] group-hover:border-cyan-400/30 flex items-center justify-center text-cyan-400/90 shadow-sm transition-colors">
            <Shield className="w-4 h-4 stroke-[1.75]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-sm font-semibold tracking-tight text-white group-hover:text-cyan-200 transition-colors">
                ArcSight Migration
              </span>
              <span className="px-2 py-0.5 text-[10px] font-medium tracking-wider uppercase rounded-full bg-cyan-400/10 text-cyan-300/90 border border-cyan-400/20">
                Direct Path
              </span>
            </div>
            <p className="text-xs text-zinc-400 font-light">
              Deterministic parsing to Microsoft Defender &amp; Splunk
            </p>
          </div>
        </div>

        {/* Telemetry Status & Controls */}
        <div className="flex items-center flex-wrap gap-2 sm:gap-2.5">
          {/* Badge: FastAPI */}
          <div
            className="relative"
            onMouseEnter={() => setShowTooltip('fastapi')}
            onMouseLeave={() => setShowTooltip(null)}
          >
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium cursor-help transition-all duration-200 ${getStatusBadgeClass(
                apiStatus?.status
              )}`}
            >
              <Server className="w-3.5 h-3.5 stroke-[1.75]" />
              <span>API :8001</span>
              <span
                className={`w-1.5 h-1.5 rounded-full ${getStatusColor(apiStatus?.status)}`}
              />
            </div>
            {showTooltip === 'fastapi' && (
              <div className="absolute top-full mt-2 left-0 w-60 p-3.5 bg-[#0e1017] border border-white/[0.1] rounded-xl shadow-2xl text-xs z-50 space-y-1.5 backdrop-blur-md">
                <div className="font-medium text-white">FastAPI Backend Status</div>
                <div className="text-zinc-400">Status: {apiStatus?.status || 'Probing...'}</div>
                {apiStatus?.uptime_seconds && (
                  <div className="text-zinc-400">Uptime: {apiStatus.uptime_seconds}s</div>
                )}
                <div className="text-zinc-400">Storage: {apiStatus?.database || 'sqlite'}</div>
              </div>
            )}
          </div>

          {/* Badge: LLM */}
          <div
            className="relative"
            onMouseEnter={() => setShowTooltip('llm')}
            onMouseLeave={() => setShowTooltip(null)}
          >
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium cursor-help transition-all duration-200 ${getStatusBadgeClass(
                llmStatus?.status
              )}`}
            >
              <Cpu className="w-3.5 h-3.5 stroke-[1.75]" />
              <span className="truncate max-w-[130px] sm:max-w-[160px]">
                {llmStatus?.provider === 'lm_studio' ? 'LM Studio' : 'Cloud LLM'}:{' '}
                {llmStatus?.active_model ? llmStatus.active_model : 'Ready'}
              </span>
              <span
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${getStatusColor(llmStatus?.status)}`}
              />
            </div>
            {showTooltip === 'llm' && (
              <div className="absolute top-full mt-2 left-0 w-64 p-3.5 bg-[#0e1017] border border-white/[0.1] rounded-xl shadow-2xl text-xs z-50 space-y-1.5 backdrop-blur-md">
                <div className="font-medium text-white">LLM Engine Telemetry</div>
                <div className="text-zinc-400">Provider: {llmStatus?.provider}</div>
                <div className="text-zinc-400 truncate">Endpoint: {llmStatus?.base_url}</div>
                <div className="text-zinc-400">Model: {llmStatus?.active_model || 'N/A'}</div>
                {llmStatus?.latency_ms !== undefined && (
                  <div className="text-zinc-400">Latency: {llmStatus.latency_ms} ms</div>
                )}
                {llmStatus?.error && (
                  <div className="text-rose-400 mt-1 break-words">
                    {llmStatus.error}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Badge: Splunk */}
          <div
            className="relative"
            onMouseEnter={() => setShowTooltip('splunk')}
            onMouseLeave={() => setShowTooltip(null)}
          >
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium cursor-help transition-all duration-200 ${getStatusBadgeClass(
                splunkStatus?.status
              )}`}
            >
              <Database className="w-3.5 h-3.5 stroke-[1.75]" />
              <span>Splunk</span>
              <span
                className={`w-1.5 h-1.5 rounded-full ${getStatusColor(splunkStatus?.status)}`}
              />
            </div>
            {showTooltip === 'splunk' && (
              <div className="absolute top-full mt-2 right-0 w-64 p-3.5 bg-[#0e1017] border border-white/[0.1] rounded-xl shadow-2xl text-xs z-50 space-y-1.5 backdrop-blur-md">
                <div className="font-medium text-white">Splunk Server Telemetry</div>
                <div className="text-zinc-400">Status: {splunkStatus?.status || 'Unknown'}</div>
                {splunkStatus?.server_name && (
                  <div className="text-zinc-400">Host: {splunkStatus.server_name}</div>
                )}
                {splunkStatus?.version && (
                  <div className="text-zinc-400">Version: {splunkStatus.version}</div>
                )}
                {splunkStatus?.error && (
                  <div className="text-rose-400 mt-1 break-words">
                    {splunkStatus.error}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Subtle Divider */}
          <div className="hidden sm:block w-[1px] h-5 bg-white/[0.08] mx-0.5" />

          {/* Precision Controls */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 rounded-xl border border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.06] text-zinc-400 hover:text-white transition-all duration-150 disabled:opacity-40"
            title="Refresh System Health"
          >
            <RefreshCw className={`w-3.5 h-3.5 stroke-[1.75] ${isFetching ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={onOpenAuditLog}
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.06] text-zinc-300 hover:text-white text-xs font-medium transition-all duration-150"
          >
            <History className="w-3.5 h-3.5 stroke-[1.75]" />
            <span className="hidden sm:inline">Audit Log</span>
          </button>

          <button
            onClick={onOpenSettings}
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.06] text-zinc-300 hover:text-white text-xs font-medium transition-all duration-150"
            title="Configure LLM & Routing"
          >
            <SlidersHorizontal className="w-3.5 h-3.5 stroke-[1.75]" />
            <span className="hidden sm:inline">Model Engine</span>
          </button>

          {/* Sentinel Settings Gear Button */}
          <button
            onClick={() => onSelectTab?.(activeTab === 'settings' ? 'translate' : 'settings')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-medium transition-all duration-150 cursor-pointer ${
              activeTab === 'settings'
                ? 'border-cyan-400/40 bg-cyan-400/[0.12] text-cyan-200 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                : 'border-cyan-400/20 bg-cyan-400/[0.05] hover:bg-cyan-400/[0.1] text-cyan-300 hover:text-cyan-200'
            }`}
            title={activeTab === 'settings' ? 'Return to Detection Workspace' : 'Configure Microsoft Sentinel'}
          >
            <Settings className="w-3.5 h-3.5 stroke-[1.75]" />
            <span>{activeTab === 'settings' ? 'Workspace' : 'Sentinel Settings'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
