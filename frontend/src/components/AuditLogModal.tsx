import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchAuditLog, AuditLogItem } from '../api/client';
import { History, X, CheckCircle2, XCircle, Search, RefreshCw } from 'lucide-react';

interface AuditLogModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AuditLogModal: React.FC<AuditLogModalProps> = ({ isOpen, onClose }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedItem, setSelectedItem] = useState<AuditLogItem | null>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['audit-log', searchTerm],
    queryFn: () => fetchAuditLog(50, 0, searchTerm || undefined),
    enabled: isOpen,
  });

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/75 backdrop-blur-md animate-fadeIn">
      <div className="w-full max-w-5xl rounded-2xl border border-white/[0.1] bg-[#0c0d14]/95 p-6 sm:p-8 shadow-2xl space-y-5 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
          <div className="flex items-center gap-2.5 text-cyan-400">
            <History className="w-5 h-5 stroke-[1.75]" />
            <h3 className="text-sm font-semibold text-white tracking-tight">Migration Audit Trail (SQLite)</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/[0.05] transition-colors"
            title="Close modal"
          >
            <X className="w-4 h-4 stroke-[2]" />
          </button>
        </div>

        {/* Metrics Strip */}
        {data?.stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 rounded-xl border border-white/[0.06] bg-white/[0.02]">
              <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Total Runs</div>
              <div className="text-xl font-semibold text-white mt-1 font-mono">
                {data.stats.total_events}
              </div>
            </div>
            <div className="p-4 rounded-xl border border-white/[0.06] bg-white/[0.02]">
              <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Passed</div>
              <div className="text-xl font-semibold text-emerald-400 mt-1 font-mono">
                {data.stats.passed_count}
              </div>
            </div>
            <div className="p-4 rounded-xl border border-white/[0.06] bg-white/[0.02]">
              <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Warnings / Fails</div>
              <div className="text-xl font-semibold text-rose-400 mt-1 font-mono">
                {data.stats.failed_count}
              </div>
            </div>
            <div className="p-4 rounded-xl border border-white/[0.06] bg-white/[0.02]">
              <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Avg Coverage</div>
              <div className="text-xl font-semibold text-cyan-400 mt-1 font-mono">
                {data.stats.average_coverage_pct}%
              </div>
            </div>
          </div>
        )}

        {/* Filter Bar */}
        <div className="flex items-center gap-2.5">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3.5 top-3" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by rule name..."
              className="w-full bg-[#07080b] border border-white/[0.08] rounded-xl pl-9 pr-4 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-400/50 transition-colors"
            />
          </div>
          <button
            onClick={() => refetch()}
            className="p-2 rounded-xl border border-white/[0.08] hover:bg-white/[0.05] text-zinc-400 hover:text-white transition-colors"
            title="Refresh audit history"
          >
            <RefreshCw className="w-3.5 h-3.5 stroke-[1.75]" />
          </button>
        </div>

        {/* Audit Table */}
        <div className="flex-1 overflow-y-auto rounded-xl border border-white/[0.06] bg-[#07080b] text-xs">
          <table className="w-full text-left">
            <thead className="border-b border-white/[0.06] bg-white/[0.02] text-zinc-400 font-medium sticky top-0 backdrop-blur-sm">
              <tr>
                <th className="px-4 py-3">Time (UTC)</th>
                <th className="px-4 py-3">Rule Name</th>
                <th className="px-4 py-3">Endpoint</th>
                <th className="px-4 py-3">Model</th>
                <th className="px-4 py-3">Coverage</th>
                <th className="px-4 py-3">Outcome</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-zinc-500">
                    Loading audit trail from database...
                  </td>
                </tr>
              ) : !data?.history || data.history.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-zinc-500">
                    No migration records found.
                  </td>
                </tr>
              ) : (
                data.history.map((item) => (
                  <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 text-zinc-500 font-mono whitespace-nowrap">
                      {item.timestamp ? item.timestamp.replace('T', ' ').slice(0, 19) : ''}
                    </td>
                    <td className="px-4 py-3 font-medium text-zinc-200 truncate max-w-[200px]">
                      {item.rule_name}
                    </td>
                    <td className="px-4 py-3 font-mono text-zinc-400">{item.endpoint}</td>
                    <td className="px-4 py-3 text-zinc-400">{item.model || item.provider || '-'}</td>
                    <td className="px-4 py-3 font-mono font-medium">
                      {item.coverage_pct !== null && item.coverage_pct !== undefined
                        ? `${item.coverage_pct}%`
                        : '-'}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium uppercase border ${
                          item.outcome === 'passed' || item.outcome === 'success'
                            ? 'bg-emerald-500/[0.08] text-emerald-300 border-emerald-500/30'
                            : 'bg-rose-500/[0.08] text-rose-300 border-rose-500/30'
                        }`}
                      >
                        {item.outcome === 'passed' || item.outcome === 'success' ? (
                          <CheckCircle2 className="w-3 h-3 stroke-[2]" />
                        ) : (
                          <XCircle className="w-3 h-3 stroke-[2]" />
                        )}
                        {item.outcome}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedItem(item)}
                        className="text-cyan-400 hover:text-cyan-300 underline font-medium transition-colors"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Selected Event Details Sub-Modal */}
        {selectedItem && (
          <div className="fixed inset-0 z-60 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div className="w-full max-w-2xl rounded-2xl border border-white/[0.1] bg-[#0c0d14] p-6 space-y-4 shadow-2xl">
              <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-white">
                  Audit Event #{selectedItem.id} Details
                </h4>
                <button
                  onClick={() => setSelectedItem(null)}
                  className="p-1 text-zinc-400 hover:text-white transition-colors"
                  title="Close"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <pre className="bg-[#07080b] p-4 rounded-xl max-h-80 overflow-y-auto text-xs font-mono text-zinc-300 leading-relaxed border border-white/[0.06]">
                {JSON.stringify(selectedItem.details, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
