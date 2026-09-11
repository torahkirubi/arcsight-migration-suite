import React, { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  Activity,
  BarChart3,
  BookOpen,
  FileCode2,
  History,
  LogOut,
  Menu,
  Settings2,
  Shield,
  SlidersHorizontal,
  X,
} from 'lucide-react';
import { LLMConfig } from './api/client';
import { DirectTranslateView } from './components/DirectTranslateView';
import { IntegrationSettings } from './components/IntegrationSettings';
import { StandaloneTuningView } from './components/StandaloneTuningView';
import { ModelSelector } from './components/ModelSelector';
import { AuditLogModal } from './components/AuditLogModal';
import { LoginGate } from './components/LoginGate';

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false } },
});

export type AppSection = 'translate' | 'tuning' | 'settings' | 'history';

const navItems: Array<{ id: AppSection; label: string; caption: string; icon: React.ElementType }> = [
  { id: 'translate', label: 'Translate', caption: 'Migration workspace · validate rules', icon: FileCode2 },
  { id: 'tuning', label: 'Live Tuning', caption: 'Sentinel telemetry thresholds', icon: SlidersHorizontal },
  { id: 'settings', label: 'Settings', caption: 'Connect LLM and Sentinel', icon: Settings2 },
  { id: 'history', label: 'Audit', caption: 'Review migration activity', icon: History },
];

export const AppContent: React.FC = () => {
  const [token, setToken] = useState<string | null>(
    sessionStorage.getItem('auth_token') || localStorage.getItem('auth_token'),
  );
  const [section, setSection] = useState<AppSection>('translate');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [modelOpen, setModelOpen] = useState(false);
  const [auditOpen, setAuditOpen] = useState(false);
  const [llmConfig, setLlmConfig] = useState<LLMConfig>({
    provider: 'lm_studio',
    model_name: 'qwen2.5-coder-7b-instruct',
    custom_base_url: 'http://localhost:1234/v1',
  });

  const logout = () => {
    sessionStorage.removeItem('auth_token');
    localStorage.removeItem('auth_token');
    setToken(null);
  };

  if (!token) return <LoginGate onLoginSuccess={setToken} />;

  const selectSection = (next: AppSection) => {
    setSection(next);
    setMobileNavOpen(false);
  };

  return (
    <div className="min-h-screen bg-[#080a0d] text-slate-200">
      <header className="sticky top-0 z-40 border-b border-[#202832] bg-[#0b0f13]">
        <div className="mx-auto flex h-16 max-w-[1680px] items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <button
              className="inline-flex h-9 w-9 items-center justify-center border border-[#29323d] text-slate-300 lg:hidden"
              onClick={() => setMobileNavOpen((open) => !open)}
              aria-label="Toggle navigation"
            >
              {mobileNavOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
            <button className="flex items-center gap-3 text-left" onClick={() => selectSection('translate')}>
              <span className="flex h-9 w-9 items-center justify-center bg-cyan-400 text-slate-950">
                <Shield size={18} />
              </span>
              <span>
                <span className="block text-sm font-semibold tracking-wide text-white">ArcSight Migration</span>
                <span className="hidden text-[10px] uppercase tracking-[0.16em] text-slate-500 sm:block">
                  Detection engineering workspace
                </span>
              </span>
            </button>
          </div>

          <div className="hidden items-center gap-2 md:flex">
            <ServiceChip label="API" state="online" />
            <ServiceChip label="LLM" state={llmConfig.provider === 'lm_studio' ? 'local' : 'cloud'} />
            <button className="icon-button" title="Model route" aria-label="Model route" onClick={() => setModelOpen(true)}>
              <Activity size={16} />
            </button>
            <button className="icon-button" title="Sign out" onClick={logout} aria-label="Logout">
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto flex max-w-[1680px]">
        <aside
          className={`fixed inset-y-16 left-0 z-30 w-72 border-r border-[#202832] bg-[#0b0f13] p-3 transition-transform lg:sticky lg:top-16 lg:block lg:h-[calc(100vh-4rem)] lg:translate-x-0 ${
            mobileNavOpen ? 'translate-x-0' : '-translate-x-full'
          }`}
        >
          <div className="mb-4 px-3 pt-2">
            <div className="eyebrow">Workspace</div>
            <p className="mt-1 text-xs leading-5 text-slate-500">Move from source rule to reviewed, exportable detection.</p>
          </div>
          <nav className="space-y-1" aria-label="Primary navigation">
            {navItems.map(({ id, label, caption, icon: Icon }) => (
              <button
                key={id}
                className={`nav-item ${section === id ? 'nav-item-active' : ''}`}
                onClick={() => selectSection(id)}
                aria-current={section === id ? 'page' : undefined}
              >
                <Icon size={17} />
                <span className="min-w-0 text-left">
                  <span className="block truncate text-sm font-medium">{label}</span>
                  <span aria-hidden="true" className="mt-0.5 block truncate text-[11px] text-slate-500">{caption}</span>
                </span>
              </button>
            ))}
          </nav>

        </aside>

        <main className="min-w-0 flex-1 px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
          {section === 'translate' && <DirectTranslateView llmConfig={llmConfig} />}
          {section === 'tuning' && <StandaloneTuningView />}
          {section === 'settings' && (
            <SettingsSection
              llmConfig={llmConfig}
              onModel={() => setModelOpen(true)}
              onSaved={() => selectSection('translate')}
            />
          )}
          {section === 'history' && (
            <HistorySection onOpen={() => setAuditOpen(true)} />
          )}
        </main>
      </div>

      <ModelSelector isOpen={modelOpen} onClose={() => setModelOpen(false)} config={llmConfig} onChange={setLlmConfig} />
      <AuditLogModal isOpen={auditOpen} onClose={() => setAuditOpen(false)} />
    </div>
  );
};

const ServiceChip: React.FC<{ label: string; state: string }> = ({ label, state }) => (
  <span className="status-chip">
    <span className={`status-dot ${state === 'online' || state === 'local' ? 'status-dot-good' : 'status-dot-warn'}`} />
    {label} <span className="text-slate-500">{state}</span>
  </span>
);

const SettingsSection: React.FC<{
  llmConfig: LLMConfig;
  onModel: () => void;
  onSaved: () => void;
}> = ({ llmConfig, onModel, onSaved }) => (
  <PageIntro
    eyebrow="Integrations"
    title="Connect the services behind the migration pipeline"
    description="Credentials are stored by the backend vault. Configure the Sentinel workspace separately from the model route."
    icon={<Settings2 size={18} />}
  >
    <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
      <div className="workbench-panel p-5">
        <IntegrationSettings onSaved={onSaved} />
      </div>
      <div className="workbench-panel h-fit p-5">
        <div className="eyebrow">Active model route</div>
        <h2 className="mt-2 text-base font-semibold text-white">{llmConfig.model_name || 'No model selected'}</h2>
        <p className="mt-1 text-xs leading-5 text-slate-500">{llmConfig.provider} · {llmConfig.custom_base_url}</p>
        <button className="button-secondary mt-5 w-full" onClick={onModel}>
          <Activity size={15} /> Configure model
        </button>
      </div>
    </div>
  </PageIntro>
);

const HistorySection: React.FC<{ onOpen: () => void }> = ({ onOpen }) => (
  <PageIntro
    eyebrow="Audit history"
    title="Trace every migration decision"
    description="Review translation outcomes, validation coverage, provider usage, and export activity."
    icon={<BarChart3 size={18} />}
  >
    <div className="workbench-panel flex min-h-64 flex-col items-center justify-center p-8 text-center">
      <History className="text-cyan-300" size={28} />
      <h2 className="mt-4 text-base font-semibold text-white">Migration activity log</h2>
      <p className="mt-2 max-w-md text-sm leading-6 text-slate-500">Open the protected audit trail to inspect recent translations and their validation outcomes.</p>
      <button className="button-primary mt-5" onClick={onOpen}><History size={15} /> Open audit history</button>
    </div>
  </PageIntro>
);

const PageIntro: React.FC<{
  eyebrow: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}> = ({ eyebrow, title, description, icon, children }) => (
  <div className="space-y-6">
    <div className="flex items-start gap-3 border-b border-[#202832] pb-5">
      <span className="section-icon">{icon}</span>
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1 className="mt-1 text-xl font-semibold tracking-tight text-white sm:text-2xl">{title}</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">{description}</p>
      </div>
    </div>
    {children}
  </div>
);

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
