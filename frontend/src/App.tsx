import React, { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { LLMConfig } from './api/client';
import { HeaderHealthBar } from './components/HeaderHealthBar';
import { DirectTranslateView } from './components/DirectTranslateView';
import { ModelSelector } from './components/ModelSelector';
import { AuditLogModal } from './components/AuditLogModal';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
    },
  },
});

export const AppContent: React.FC = () => {
  const [llmConfig, setLlmConfig] = useState<LLMConfig>({
    provider: 'lm_studio',
    model_name: 'qwen2.5-coder-7b-instruct',
    custom_base_url: 'http://localhost:1234/v1',
  });

  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#07080b] bg-[radial-gradient(ellipse_80%_60%_at_50%_-10%,rgba(56,189,248,0.04),transparent)] text-slate-200 flex flex-col font-sans antialiased selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Precision Header & Telemetry Bar */}
      <HeaderHealthBar
        llmConfig={llmConfig}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenAuditLog={() => setIsAuditLogOpen(true)}
      />

      {/* Main Workspace */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 md:py-10">
        <DirectTranslateView llmConfig={llmConfig} />
      </main>

      {/* Minimalist Footnote */}
      <footer className="border-t border-white/[0.05] bg-[#07080b]/50 backdrop-blur-sm py-6 px-4 text-center text-xs text-zinc-500 tracking-wide">
        <div className="flex flex-wrap items-center justify-center gap-2">
          <span>ArcSight Detection Migration</span>
          <span className="text-zinc-700">•</span>
          <span>Deterministic Parsing Engine</span>
          <span className="text-zinc-700">•</span>
          <span>Dual Model Architecture</span>
          <span className="text-zinc-700">•</span>
          <span>Strict Human MDE Boundary</span>
        </div>
      </footer>

      {/* Modals */}
      <ModelSelector
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        config={llmConfig}
        onChange={setLlmConfig}
      />

      <AuditLogModal
        isOpen={isAuditLogOpen}
        onClose={() => setIsAuditLogOpen(false)}
      />
    </div>
  );
};

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
