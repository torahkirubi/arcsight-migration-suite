import React, { useState } from 'react';
import { ShieldCheck, AlertCircle, Pencil, Check } from 'lucide-react';

interface MitreBadgeProps {
  tactic: string | null;
  source: 'extracted from rule' | 'missing' | string;
  rawUri: string | null;
  onTacticChange?: (newTactic: string) => void;
}

const COMMON_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export const MitreBadge: React.FC<MitreBadgeProps> = ({
  tactic,
  source,
  rawUri,
  onTacticChange,
}) => {
  const isExtracted = source === 'extracted from rule';
  const [isEditing, setIsEditing] = useState(false);
  const [customTactic, setCustomTactic] = useState(tactic || '');

  const handleSave = () => {
    setIsEditing(false);
    if (onTacticChange) {
      onTacticChange(customTactic);
    }
  };

  if (isExtracted) {
    return (
      <div className="flex flex-col gap-1.5">
        <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">
          MITRE ATT&CK Tactic
        </span>
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/[0.05] text-emerald-300 text-xs font-medium w-fit">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 stroke-[2] shrink-0" />
          <span className="font-semibold">{tactic || 'Unknown'}</span>
          <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase font-medium">
            Verified
          </span>
        </div>
        {rawUri && (
          <span className="text-[11px] text-zinc-500 font-mono truncate max-w-sm" title={rawUri}>
            {rawUri}
          </span>
        )}
      </div>
    );
  }

  // Unverified/Missing scenario
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">
        MITRE ATT&CK Tactic
      </span>
      <div className="flex flex-col sm:flex-row sm:items-center gap-2">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-amber-500/30 bg-amber-500/[0.05] text-amber-300 text-xs font-medium w-fit">
          <AlertCircle className="w-3.5 h-3.5 text-amber-400 stroke-[2] shrink-0" />
          <span className="font-semibold">{customTactic || 'Missing from Rule'}</span>
          <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 uppercase font-medium">
            Unverified
          </span>
        </div>

        {!isEditing ? (
          <button
            onClick={() => setIsEditing(true)}
            className="flex items-center gap-1 text-xs text-amber-400/90 hover:text-amber-300 underline font-medium transition-colors"
          >
            <Pencil className="w-3 h-3 stroke-[2]" />
            <span>Assign</span>
          </button>
        ) : (
          <div className="flex items-center gap-1.5">
            <select
              value={customTactic}
              onChange={(e) => setCustomTactic(e.target.value)}
              className="bg-[#0e1017] border border-white/[0.1] rounded-lg px-2.5 py-1 text-xs text-zinc-200 focus:outline-none focus:border-amber-400/50"
            >
              <option value="">Select Tactic...</option>
              {COMMON_TACTICS.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <button
              onClick={handleSave}
              className="p-1 rounded-md bg-amber-400 text-black hover:bg-amber-300 transition-colors"
              title="Confirm Tactic"
            >
              <Check className="w-3.5 h-3.5 stroke-[2.5]" />
            </button>
          </div>
        )}
      </div>
      <span className="text-[11px] text-zinc-500">
        eventAnnotationStage missing in export. Manual confirmation required.
      </span>
    </div>
  );
};
