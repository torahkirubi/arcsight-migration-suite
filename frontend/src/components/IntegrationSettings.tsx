import React, { useState } from 'react';
import { AlertCircle, CheckCircle2, Eye, EyeOff, Loader2, Radio, Save, Wifi } from 'lucide-react';
import { apiFetch } from '../api/client';

export interface IntegrationSettingsProps { onClose?: () => void; onSaved?: () => void; }
export const IntegrationSettings: React.FC<IntegrationSettingsProps> = ({ onSaved }) => {
  const [tenantId, setTenantId] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [workspaceId, setWorkspaceId] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const payload = { tenant_id: tenantId, client_id: clientId, client_secret: clientSecret, workspace_id: workspaceId };

  const testConnection = async () => {
    setIsTesting(true); setStatusMessage(null);
    try {
      const response = await apiFetch('/settings/sentinel/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await response.json();
      setStatusMessage({ type: response.ok && data.success ? 'success' : 'error', message: response.ok && data.success ? data.message || 'Connection verified' : data.error || 'Connection failed' });
    } catch (error) { setStatusMessage({ type: 'error', message: error instanceof Error ? error.message : 'Connection failed' }); }
    finally { setIsTesting(false); }
  };

  const saveConfiguration = async () => {
    setIsSaving(true); setSaveMessage(null);
    try {
      const response = await apiFetch('/settings/sentinel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await response.json();
      if (!response.ok || !(data.success || data.status === 'success')) throw new Error(data.error || data.detail || 'Failed to save configuration');
      setSaveMessage({ type: 'success', message: data.message || 'Configuration saved' }); onSaved?.();
    } catch (error) { setSaveMessage({ type: 'error', message: error instanceof Error ? error.message : 'Failed to save configuration' }); }
    finally { setIsSaving(false); }
  };

  return <div className="connection-console">
    <div className="connection-console-head"><div><span className="eyebrow">Connection / sentinel</span><h2>Give the studio a window into your telemetry.</h2><span className="sr-only">Microsoft Sentinel Integration</span><p>These credentials stay in the backend vault and are used only for bounded schema and baseline queries.</p></div><div className="connection-glyph"><Radio size={19} /></div></div>
    <div className="connection-map"><div className="connection-node active"><span>01</span><strong>Azure tenant</strong><small>identity</small></div><i /><div className="connection-node"><span>02</span><strong>Application</strong><small>client credentials</small></div><i /><div className="connection-node"><span>03</span><strong>Workspace</strong><small>log analytics</small></div></div>
    <div className="connection-fields">
      <Field id="tenant-id" label="Tenant ID" value={tenantId} onChange={setTenantId} placeholder="00000000-0000-0000-0000-000000000000" />
      <Field id="client-id" label="Client ID" value={clientId} onChange={setClientId} placeholder="00000000-0000-0000-0000-000000000000" />
      <div className="connection-field"><label htmlFor="client-secret">Client Secret</label><div className="secret-field"><input id="client-secret" type={showSecret ? 'text' : 'password'} value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} placeholder="••••••••••••••••" /><button type="button" onClick={() => setShowSecret(!showSecret)} aria-label={showSecret ? 'Hide secret' : 'Show secret'}>{showSecret ? <EyeOff size={15} /> : <Eye size={15} />}</button></div></div>
      <Field id="workspace-id" label="Workspace ID" value={workspaceId} onChange={setWorkspaceId} placeholder="00000000-0000-0000-0000-000000000000" />
    </div>
    {statusMessage && <div className={`connection-message ${statusMessage.type}`}>{statusMessage.type === 'success' ? <CheckCircle2 size={15} /> : <AlertCircle size={15} />}{statusMessage.message}</div>}
    {saveMessage && <div className={`connection-message ${saveMessage.type}`}>{saveMessage.type === 'success' ? <CheckCircle2 size={15} /> : <AlertCircle size={15} />}{saveMessage.message}</div>}
    <div className="connection-actions"><button className="studio-button secondary" onClick={testConnection} disabled={isTesting}>{isTesting ? <Loader2 className="animate-spin" size={14} /> : <Wifi size={14} />}{isTesting ? 'Checking…' : 'Test connection'}</button><button aria-label="Save Configuration" className="studio-button primary" onClick={saveConfiguration} disabled={isSaving}>{isSaving ? <Loader2 className="animate-spin" size={14} /> : <Save size={14} />}{isSaving ? 'Saving…' : 'Save to vault'}</button></div>
  </div>;
};

const Field: React.FC<{ id: string; label: string; value: string; onChange: (value: string) => void; placeholder: string }> = ({ id, label, value, onChange, placeholder }) => <div className="connection-field"><label htmlFor={id}>{label}</label><input id={id} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} /></div>;
