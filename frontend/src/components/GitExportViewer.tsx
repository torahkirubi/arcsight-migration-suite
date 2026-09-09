import React, { useState } from 'react';
import { FileText, Copy, Check, Download, X } from 'lucide-react';
import { SaveRunbookResponse } from '../api/client';

interface GitExportViewerProps {
  isOpen: boolean;
  onClose: () => void;
  result: SaveRunbookResponse | null;
}

export const GitExportViewer: React.FC<GitExportViewerProps> = ({ isOpen, onClose, result }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !result) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(result.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([result.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = result.filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/75 backdrop-blur-md animate-fadeIn">
      <div className="w-full max-w-4xl rounded-2xl border border-white/[0.1] bg-[#0c0d14]/95 p-6 sm:p-8 shadow-2xl space-y-5 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
          <div className="flex items-center gap-2.5 text-cyan-400">
            <FileText className="w-5 h-5 stroke-[1.75]" />
            <div>
              <h3 className="text-sm font-semibold text-white tracking-tight">Git-Ready Output Specification</h3>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">{result.filename}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/[0.05] transition-colors"
            title="Close modal"
          >
            <X className="w-4 h-4 stroke-[2]" />
          </button>
        </div>

        {/* Action Controls Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#07080b] p-3.5 rounded-xl border border-white/[0.06]">
          <div className="text-xs text-zinc-400 truncate">
            Repository Target:{' '}
            <code className="text-cyan-300 font-mono bg-white/[0.04] px-2 py-0.5 rounded border border-white/[0.08]">
              {result.file_path || result.filename}
            </code>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl border border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.06] text-zinc-300 hover:text-white font-medium text-xs transition-all"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400 stroke-[2]" /> : <Copy className="w-3.5 h-3.5 stroke-[1.75]" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#07080b] font-semibold text-xs transition-all shadow-[0_0_15px_rgba(34,211,238,0.2)]"
            >
              <Download className="w-3.5 h-3.5 stroke-[2]" />
              <span>Download .txt</span>
            </button>
          </div>
        </div>

        {/* File Preview */}
        <div className="flex-1 overflow-y-auto rounded-xl border border-white/[0.06] bg-[#07080b] p-5 font-mono text-xs text-zinc-200 leading-relaxed whitespace-pre-wrap select-all">
          {result.content}
        </div>
      </div>
    </div>
  );
};
