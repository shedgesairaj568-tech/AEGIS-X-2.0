import React, { useState, useEffect } from 'react';
import { Search, RefreshCw, Lock } from 'lucide-react';
import { api } from '../services/api';
import type { AuditLog } from '../types';
import { soundFX } from '../services/soundEffects';

export const AuditLogsView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const res = await api.listAuditLogs();
      setLogs(res.items || []);
    } catch (e) {
      console.error('Audit logs error', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter((l) =>
    l.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (l.actor_email ? l.actor_email.toLowerCase().includes(searchQuery.toLowerCase()) : false) ||
    (l.details ? JSON.stringify(l.details).toLowerCase().includes(searchQuery.toLowerCase()) : false)
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600 mb-1">
            <Lock className="w-4 h-4" />
            <span>COMPLIANCE & TRACEABILITY</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Immutable SOC Audit Trail ({filteredLogs.length})
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Cryptographically sealed system activities, triage actions, and analyst interventions.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="relative w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search audit trail..."
              className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-900 focus:outline-none focus:border-indigo-500 focus:bg-white"
            />
          </div>

          <button
            onClick={() => {
              soundFX.playClick();
              fetchLogs();
            }}
            className="p-2.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 transition-all shadow-xs"
            title="Refresh Audit Logs"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[10px] font-semibold tracking-wider">
              <tr>
                <th className="p-3.5">Timestamp</th>
                <th className="p-3.5">Actor / Entity</th>
                <th className="p-3.5">Action Executed</th>
                <th className="p-3.5">Resource Target</th>
                <th className="p-3.5">Details & Metadata</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {isLoading ? (
                <tr>
                  <td colSpan={5} className="p-12 text-center text-slate-400">
                    Loading compliance audit trail...
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-12 text-center text-slate-400">
                    No audit logs matching query.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="p-3.5 font-mono text-slate-500 text-[11px] whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <div className="font-semibold text-slate-900">{log.actor_email || 'system'}</div>
                      <div className="text-[10px] text-indigo-600 font-mono">{log.ip_address || '127.0.0.1'}</div>
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2.5 py-0.5 rounded-full bg-indigo-50 text-indigo-700 font-semibold font-mono text-[10px]">
                        {log.action}
                      </span>
                    </td>
                    <td className="p-3.5 text-slate-600 font-mono text-[11px]">
                      {log.resource_type ? `${log.resource_type}:${log.resource_id?.slice(0, 8) || ''}` : '—'}
                    </td>
                    <td className="p-3.5 text-slate-600 text-[11px]">
                      {log.details ? (
                        <span className="font-mono bg-slate-50 px-2 py-0.5 rounded border border-slate-200 text-slate-700">
                          {JSON.stringify(log.details)}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
