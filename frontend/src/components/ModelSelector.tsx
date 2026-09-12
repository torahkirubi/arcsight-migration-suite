import React, { useState } from 'react';
import { Check, Cpu, KeyRound, Loader2, Save, Server, X } from 'lucide-react';
import { LLMConfig, saveLLMSettings } from '../api/client';

interface ModelSelectorProps { isOpen: boolean; onClose: () => void; config: LLMConfig; onChange: (updated: LLMConfig) => void; }
export const ModelSelector: React.FC<ModelSelectorProps> = ({ isOpen, onClose, config, onChange }) => {
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  if (!isOpen) return null;
  const choose = (provider: LLMConfig['provider'], base: string, model: string) => onChange({ ...config, provider, custom_base_url: base, model_name: model });
  const saveKey = async () => {
    if (!config.api_key?.trim()) { setSaveStatus('error'); setSaveMessage('Enter an API key before saving.'); return; }
    setSaveStatus('saving'); setSaveMessage(null);
    try { const response = await saveLLMSettings(config.provider, config.api_key.trim(), config.model_name?.trim() || undefined); setSaveStatus('success'); setSaveMessage(response.message || 'Key saved to vault'); }
    catch (error) { setSaveStatus('error'); setSaveMessage(error instanceof Error ? error.message : 'Failed to save key'); }
  };
  return <div className="model-studio-backdrop"><section className="model-studio" aria-label="Model routing studio">
    <header className="model-studio-head"><div><span className="eyebrow">Routing atelier / 02</span><h2>Choose the mind behind the migration.</h2><span className="sr-only">Dual-Model Routing Engine</span><p>Route parsing and threat analysis through a local or cloud model without changing the pipeline.</p></div><button className="round-action" onClick={onClose} aria-label="Close model settings"><X size={16} /></button></header>
    <div className="model-studio-body">
      <div className="provider-orbit">
        <span className="eyebrow">Available routes</span>
        <Provider name="LM Studio" note="Private · local inference" active={config.provider === 'lm_studio'} onClick={() => choose('lm_studio', 'http://localhost:1234/v1', 'qwen2.5-coder-7b-instruct')} />
        <Provider name="Google Gemini" note="Fast · hosted reasoning" active={config.provider === 'gemini'} onClick={() => choose('gemini', 'https://generativelanguage.googleapis.com/v1beta/openai', 'gemini-3.6-flash')} />
        <Provider name="Cloud OpenAI" note="General · hosted reasoning" active={config.provider === 'cloud_openai'} onClick={() => choose('cloud_openai', 'https://api.openai.com/v1', 'gpt-4o')} />
        <Provider name="Custom / Claude / Kimi" note="Any OpenAI-compatible gateway" active={config.provider === 'custom'} onClick={() => choose('custom', 'https://your-provider.example/v1', '')} />
      </div>
      <div className="model-config-sheet">
        <div className="model-config-title"><Cpu size={16} /><span>Route details</span><span className="route-live">active</span></div>
        <label>Model identifier<input value={config.model_name || ''} onChange={(event) => onChange({ ...config, model_name: event.target.value })} placeholder="Enter the exact model ID from your provider" /></label>
        <label><span className="label-with-icon"><Server size={13} /> OpenAI-compatible base URL</span><input className="mono-input" value={config.custom_base_url || ''} onChange={(event) => onChange({ ...config, custom_base_url: event.target.value })} placeholder="https://api.example.com/v1" /></label>
        {config.provider !== 'lm_studio' && <label><span className="label-with-icon"><KeyRound size={13} /> API key</span><input className="mono-input" type="password" value={config.api_key || ''} onChange={(event) => onChange({ ...config, api_key: event.target.value })} placeholder="sk-..." /></label>}
        {saveMessage && <div className={`model-message ${saveStatus}`}>{saveStatus === 'success' ? <Check size={14} /> : null}{saveMessage}{saveStatus === 'success' && <span className="sr-only">Key saved to Vault</span>}</div>}
        <div className="model-studio-actions">{config.provider !== 'lm_studio' && <button className="studio-button secondary" onClick={saveKey} disabled={saveStatus === 'saving'}>{saveStatus === 'saving' ? <Loader2 className="animate-spin" size={14} /> : <Save size={14} />} Save key</button>}<button className="studio-button primary" onClick={onClose}>Use this route <Check size={14} /></button></div>
      </div>
    </div>
  </section></div>;
};
const Provider: React.FC<{ name: string; note: string; active: boolean; onClick: () => void }> = ({ name, note, active, onClick }) => <button className={active ? 'provider-row active' : 'provider-row'} onClick={onClick}><span className="provider-orb" /><span><strong>{name}</strong><small>{note}</small></span>{active && <Check size={15} />}</button>;
