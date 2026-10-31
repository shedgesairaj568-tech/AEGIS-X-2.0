import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Download, 
  RefreshCw, 
  ChevronLeft, 
  ChevronRight, 
  Flame, 
  ArrowUpDown
} from 'lucide-react';
import { useThreatFeed } from '../context/ThreatFeedContext';
import type { Alert } from '../types';
import { soundFX } from '../services/soundEffects';

interface AlertsViewProps {
  onSelectAlert: (alert: Alert) => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({ onSelectAlert }) => {
  const { alerts, fetchAlerts, triggerSimulationEvent } = useThreatFeed();

  // Filters state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'detected_at' | 'risk_score' | 'anomaly_score'>('detected_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Multi-select state
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 15;

  const handleRefresh = async () => {
    soundFX.playClick();
    await fetchAlerts();
  };

  const filteredAlerts = useMemo(() => {
    return alerts
      .filter((a) => {
        if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
        if (statusFilter !== 'all' && a.status !== statusFilter) return false;
        if (attackTypeFilter !== 'all' && a.attack_type !== attackTypeFilter) return false;
        if (sourceFilter !== 'all' && a.source !== sourceFilter) return false;
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchTitle = a.title.toLowerCase().includes(q);
          const matchSrc = a.source_ip?.toLowerCase().includes(q);
          const matchDst = a.destination_ip?.toLowerCase().includes(q);
          const matchMitre = a.mitre_technique_id?.toLowerCase().includes(q);
          if (!matchTitle && !matchSrc && !matchDst && !matchMitre) return false;
        }
        return true;
      })
      .sort((a, b) => {
        let valA = a[sortBy] ?? 0;
        let valB = b[sortBy] ?? 0;
        if (sortBy === 'detected_at') {
          valA = new Date(a.detected_at).getTime();
          valB = new Date(b.detected_at).getTime();
        }
        if (sortOrder === 'desc') {
          return valA > valB ? -1 : 1;
        }
        return valA > valB ? 1 : -1;
      });
  }, [alerts, severityFilter, statusFilter, attackTypeFilter, sourceFilter, searchQuery, sortBy, sortOrder]);

  const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / pageSize));
  const paginatedAlerts = filteredAlerts.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const toggleSelectAll = () => {
    if (selectedIds.length === paginatedAlerts.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(paginatedAlerts.map((a) => a.id));
    }
  };

  const toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleExportCSV = () => {
    soundFX.playClick();
    const headers = ['ID', 'Title', 'Severity', 'Status', 'Attack Type', 'Source IP', 'Target IP', 'Risk Score', 'Anomaly Score', 'Detected At'];
    const rows = filteredAlerts.map((a) => [
      a.id,
      `"${a.title.replace(/"/g, '""')}"`,
      a.severity,
      a.status,
      a.attack_type,
      a.source_ip || '',
      a.destination_ip || '',
      a.risk_score || '',
      a.anomaly_score || '',
      a.detected_at,
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `aegis_x_alerts_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      default:
        return 'badge-low';
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600 mb-1">
            <ShieldAlert className="w-4 h-4" />
            <span>INCIDENT QUEUE</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Security Incidents & Telemetry Alerts ({filteredAlerts.length})
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Browse and triage anomalous telemetry events detected across the enterprise network.
          </p>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={() => triggerSimulationEvent()}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-rose-50 hover:bg-rose-100 border border-rose-200 text-rose-700 text-xs font-semibold transition-all shadow-xs"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Simulate Anomaly</span>
          </button>

          <button
            onClick={handleExportCSV}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold transition-all shadow-xs"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={handleRefresh}
            className="p-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-600 transition-all shadow-xs"
            title="Refresh Alert Stream"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-white p-4 rounded-2xl border border-slate-200 shadow-xs space-y-3 text-xs">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {/* Search Bar */}
          <div className="lg:col-span-2 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Search title, IP address, MITRE technique..."
              className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:bg-white transition-colors"
            />
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(1);
              }}
              aria-label="Filter by Severity"
              className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs text-slate-700 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="all">Severity: All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Attack Type Filter */}
          <div>
            <select
              value={attackTypeFilter}
              onChange={(e) => {
                setAttackTypeFilter(e.target.value);
                setCurrentPage(1);
              }}
              aria-label="Filter by Attack Type"
              className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs text-slate-700 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="all">Attack Type: All</option>
              <option value="ddos">DDoS</option>
              <option value="brute_force">Brute Force</option>
              <option value="port_scan">Port Scan</option>
              <option value="sql_injection">SQL Injection</option>
              <option value="botnet">Botnet</option>
              <option value="web_attack">Web Attack</option>
              <option value="normal">Normal</option>
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setCurrentPage(1);
              }}
              aria-label="Filter by Status"
              className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs text-slate-700 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="all">Status: All</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          {/* Source Filter */}
          <div>
            <select
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setCurrentPage(1);
              }}
              aria-label="Filter by Source"
              className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs text-slate-700 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="all">Source: All</option>
              <option value="network_flow">Network Flow</option>
              <option value="auth_log">Auth Log</option>
              <option value="firewall">Firewall</option>
              <option value="ids_ips">IDS/IPS</option>
              <option value="endpoint">Endpoint</option>
            </select>
          </div>
        </div>

        {/* Sorting & Summary Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-100 text-xs text-slate-500">
          <div className="flex items-center space-x-3">
            <span>Showing {filteredAlerts.length} incidents</span>
            {selectedIds.length > 0 && (
              <span className="text-indigo-600 font-semibold">({selectedIds.length} selected)</span>
            )}
          </div>

          <div className="flex items-center space-x-3">
            <span className="flex items-center space-x-1 text-slate-400">
              <ArrowUpDown className="w-3 h-3 text-slate-500" />
              <span>Sort:</span>
            </span>
            <button
              onClick={() => {
                setSortBy('detected_at');
                setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
              }}
              className={`hover:text-indigo-600 font-medium ${sortBy === 'detected_at' ? 'text-indigo-600 font-bold' : ''}`}
            >
              Time {sortBy === 'detected_at' && (sortOrder === 'asc' ? '↑' : '↓')}
            </button>
            <button
              onClick={() => {
                setSortBy('risk_score');
                setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
              }}
              className={`hover:text-indigo-600 font-medium ${sortBy === 'risk_score' ? 'text-indigo-600 font-bold' : ''}`}
            >
              Risk {sortBy === 'risk_score' && (sortOrder === 'asc' ? '↑' : '↓')}
            </button>
            <button
              onClick={() => {
                setSortBy('anomaly_score');
                setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
              }}
              className={`hover:text-indigo-600 font-medium ${sortBy === 'anomaly_score' ? 'text-indigo-600 font-bold' : ''}`}
            >
              Anomaly {sortBy === 'anomaly_score' && (sortOrder === 'asc' ? '↑' : '↓')}
            </button>
          </div>
        </div>
      </div>

      {/* Incidents Data Table */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[10px] font-semibold tracking-wider">
              <tr>
                <th className="p-3.5 w-10 text-center">
                  <input
                    type="checkbox"
                    checked={selectedIds.length === paginatedAlerts.length && paginatedAlerts.length > 0}
                    onChange={toggleSelectAll}
                    aria-label="Select all alerts on page"
                    className="rounded border-slate-300 text-indigo-600 focus:ring-0 cursor-pointer"
                  />
                </th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Incident Title & Category</th>
                <th className="p-3.5">Source / Target IP</th>
                <th className="p-3.5">MITRE Technique</th>
                <th className="p-3.5 text-center">Risk</th>
                <th className="p-3.5 text-center">Anomaly</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center text-slate-400">
                    No security alerts found matching the selected filters.
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map((alt) => (
                  <tr
                    key={alt.id}
                    onClick={() => onSelectAlert(alt)}
                    className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                  >
                    <td className="p-3.5 text-center" onClick={(e) => toggleSelect(alt.id, e)}>
                      <input
                        type="checkbox"
                        checked={selectedIds.includes(alt.id)}
                        onChange={() => {}}
                        aria-label={`Select alert ${alt.title}`}
                        className="rounded border-slate-300 text-indigo-600 focus:ring-0 cursor-pointer"
                      />
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(alt.severity)}`}>
                        {alt.severity}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <div className="font-semibold text-slate-900 group-hover:text-indigo-600 transition-colors text-xs">
                        {alt.title}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 uppercase">
                        {alt.attack_type.replace('_', ' ')} • {alt.source.replace('_', ' ')}
                      </div>
                    </td>
                    <td className="p-3.5 whitespace-nowrap font-mono text-[11px]">
                      <div><span className="text-slate-400">Src:</span> <strong className="text-slate-800 font-semibold">{alt.source_ip || '—'}</strong></div>
                      <div><span className="text-slate-400">Dst:</span> <strong className="text-indigo-600 font-semibold">{alt.destination_ip || '—'}</strong></div>
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      {alt.mitre_technique_id ? (
                        <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-700 font-medium text-[11px]">
                          {alt.mitre_technique_id}
                        </span>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="p-3.5 text-center font-bold">
                      <span className="text-rose-600">{alt.risk_score?.toFixed(0) || '80'}</span>
                      <span className="text-slate-400 text-[10px]">/100</span>
                    </td>
                    <td className="p-3.5 text-center font-mono">
                      <span className="text-slate-700 font-semibold">{alt.anomaly_score?.toFixed(2) || '0.85'}</span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                        alt.status === 'open'
                          ? 'bg-rose-50 text-rose-700 border border-rose-200'
                          : alt.status === 'investigating'
                          ? 'bg-amber-50 text-amber-700 border border-amber-200'
                          : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}>
                        {alt.status}
                      </span>
                    </td>
                    <td className="p-3.5 text-right whitespace-nowrap text-slate-500 font-mono text-[11px]">
                      {new Date(alt.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="p-4 bg-slate-50/70 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
          <div>
            Page {currentPage} of {totalPages} ({filteredAlerts.length} total entries)
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1.5 rounded-lg bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1.5 rounded-lg bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 disabled:opacity-40"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
