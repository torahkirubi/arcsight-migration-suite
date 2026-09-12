import React, { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  ArrowUpRight,
  Bot,
  FileCode2,
  History,
  LogOut,
  Settings2,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
} from 'lucide-react';
import { LLMConfig } from './api/client';
import { DirectTranslateView } from './components/DirectTranslateView';
import { IntegrationSettings } from './components/IntegrationSettings';
import { StandaloneTuningView } from './components/StandaloneTuningView';
import { ModelSelector } from './components/ModelSelector';
import { AuditLogModal } from './components/AuditLogModal';
import { LoginGate } from './components/LoginGate';

const queryClient = new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: false } } });
export type AppSection = 'translate' | 'tuning' | 'settings' | 'history';

const sections: Array<{ id: AppSection; label: string; icon: React.ElementType }> = [
  { id: 'translate', label: 'Studio', icon: FileCode2 },
  { id: 'tuning', label: 'Telemetry', icon: SlidersHorizontal },
  { id: 'settings', label: 'Connections', icon: Settings2 },
  { id: 'history', label: 'Archive', icon: History },
];

export const AppContent: React.FC = () => {
  const [token, setToken] = useState<string | null>(sessionStorage.getItem('auth_token') || localStorage.getItem('auth_token'));
  const [section, setSection] = useState<AppSection>('translate');
  const [modelOpen, setModelOpen] = useState(false);
  const [auditOpen, setAuditOpen] = useState(false);
  const [llmConfig, setLlmConfig] = useState<LLMConfig>({
    provider: 'lm_studio',
    model_name: 'qwen2.5-coder-7b-instruct',
    custom_base_url: 'http://localhost:1234/v1',
  });

  React.useEffect(() => {
    const handleAuthExpired = () => setToken(null);
    window.addEventListener('auth:expired', handleAuthExpired);
    return () => window.removeEventListener('auth:expired', handleAuthExpired);
  }, []);

  if (!token) return <LoginGate onLoginSuccess={setToken} />;

  const logout = () => {
    sessionStorage.removeItem('auth_token');
    localStorage.removeItem('auth_token');
    setToken(null);
  };
  const selectSection = (next: AppSection) => setSection(next);

  return (
    <div className="studio-app">
      <header className="studio-topbar">
        <button className="studio-brand" onClick={() => selectSection('translate')}>
          <span className="brand-mark"><Sparkles size={16} /></span>
          <span><strong>arc<span>/</span>shift</strong><small>migration studio</small></span>
        </button>
        <nav className="studio-nav" aria-label="Primary navigation">
          {sections.map(({ id, label, icon: Icon }) => (
            <button key={id} aria-label={id === 'translate' ? 'Translate' : id === 'tuning' ? 'Live Tuning' : id === 'settings' ? 'Settings' : 'Audit'} className={section === id ? 'studio-nav-item active' : 'studio-nav-item'} onClick={() => selectSection(id)}>
              <Icon size={14} /> {label}
            </button>
          ))}
        </nav>
        <div className="studio-actions">
          <button className="model-pill" onClick={() => setModelOpen(true)} aria-label="Model route">
            <span className="pulse-dot" /><Bot size={14} /> <span className="model-pill-name">{llmConfig.model_name}</span>
          </button>
          <button className="round-action" title="Logout" aria-label="Logout" onClick={logout}><LogOut size={15} /></button>
        </div>
      </header>

      <div className="studio-subbar">
        <div className="studio-breadcrumb"><span>Workspace</span><ArrowUpRight size={13} /><strong>{sections.find((item) => item.id === section)?.label}</strong></div>
        <div className="studio-shortcuts"><span><kbd>⌘</kbd>K</span> command menu <span className="shortcut-separator" /><span className="live-indicator">●</span> API ready</div>
      </div>

      <main className="studio-main">
        {section === 'translate' && <DirectTranslateView llmConfig={llmConfig} />}
        {section === 'tuning' && <div className="studio-page"><PageHeading eyebrow="Telemetry lab" title="Tune the signal, not the rule" description="Explore live Sentinel telemetry and find a threshold your analysts can trust." icon={<TerminalSquare size={18} />} /><StandaloneTuningView llmConfig={llmConfig} /></div>}
        {section === 'settings' && <div className="studio-page"><PageHeading eyebrow="Connections" title="Your tools, in one place" description="Keep service credentials and model routing separate from the migration canvas." icon={<Settings2 size={18} />} /><div className="studio-settings-grid"><div className="studio-sheet"><IntegrationSettings onSaved={() => setSection('translate')} /></div><div className="studio-note"><div className="eyebrow">Active route</div><h2>{llmConfig.model_name}</h2><p>{llmConfig.provider} · local route</p><button className="studio-button secondary" onClick={() => setModelOpen(true)}><Bot size={14} /> Change model</button></div></div></div>}
        {section === 'history' && <div className="studio-page"><PageHeading eyebrow="Archive" title="A trail of every decision" description="Open the audit log when you need to explain what changed, why it changed, and who reviewed it." icon={<History size={18} />} /><div className="archive-empty"><History size={25} /><h2>No context lost</h2><p>Migration history is protected behind the audit viewer, keeping the studio calm until you need it.</p><button className="studio-button primary" onClick={() => setAuditOpen(true)}>Open archive <ArrowUpRight size={14} /></button></div></div>}
      </main>

      <ModelSelector isOpen={modelOpen} onClose={() => setModelOpen(false)} config={llmConfig} onChange={setLlmConfig} />
      <AuditLogModal isOpen={auditOpen} onClose={() => setAuditOpen(false)} />
    </div>
  );
};

const PageHeading: React.FC<{ eyebrow: string; title: string; description: string; icon: React.ReactNode }> = ({ eyebrow, title, description, icon }) => (
  <div className="studio-heading"><span className="heading-icon">{icon}</span><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div></div>
);

export default function App() {
  return <QueryClientProvider client={queryClient}><AppContent /></QueryClientProvider>;
}
