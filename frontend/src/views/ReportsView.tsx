import React, { useState } from 'react';
import { 
  FileText, 
  Search, 
  ShieldCheck, 
  Printer 
} from 'lucide-react';
import { INITIAL_REPORTS } from '../services/mockData';
import type { Report } from '../types';
import { soundFX } from '../services/soundEffects';

export const ReportsView: React.FC = () => {
  const [reportsList] = useState<Report[]>(() => {
    const list: Report[] = [];
    Object.values(INITIAL_REPORTS).forEach((reps: Report[]) => list.push(...reps));
    
    // Add extra sample reports for realism
    list.push(
      {
        id: 'r2',
        alert_id: 'a1000000-0000-0000-0000-000000000002',
        title: 'Executive Incident Briefing: High-Frequency SSH Brute Force Surge',
        summary: 'AEGIS-X Auth Log monitor flagged 88 failed password attempts within 3 minutes targeting port 22 on host 192.168.1.10 originating from 91.240.118.172.',
        root_cause: 'Automated adversary bot running MITRE T1110 (Brute Force) dictionary attack targeting default administrative usernames (root, admin, deploy).',
        mitigation: '1. Dynamically blocked source IP 91.240.118.172 via iptables drop rule.\n2. Enforced SSH key-only authentication on 192.168.1.10.\n3. Verified zero successful credential authentications occurred.',
        generated_by: 'AEGIS-X Response Agent',
        created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
      },
      {
        id: 'r3',
        alert_id: 'a1000000-0000-0000-0000-000000000004',
        title: 'Automated Threat Report: SQL Injection Probe on Public API',
        summary: 'Web Application Firewall telemetry intercepted boolean-based and union-based SQL injection payloads targeting /api/v1/auth/login endpoint.',
        root_cause: 'Malicious actor scanned endpoint with automated sqlmap tool trying to extract schema metadata.',
        mitigation: '1. Perimeter WAF rate limiting applied.\n2. Parameterized SQL queries verified in backend ORM.\n3. Source IP placed on 24-hour quarantine watchlist.',
        generated_by: 'AEGIS-X Knowledge & Response Agent',
        created_at: new Date(Date.now() - 3600000 * 6).toISOString(),
      }
    );
    return list;
  });

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedReport, setSelectedReport] = useState<Report>(reportsList[0]);

  const filteredReports = reportsList.filter((r) =>
    r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    r.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
    r.generated_by.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600 mb-1">
            <FileText className="w-4 h-4" />
            <span>INCIDENT BRIEFINGS</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Security Incident Reports & Runbooks
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Autonomous post-incident analysis, root-cause assessments, and mitigation action summaries.
          </p>
        </div>

        <button
          onClick={() => {
            soundFX.playClick();
            window.print();
          }}
          className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs transition-all shadow-xs"
        >
          <Printer className="w-4 h-4 text-slate-500" />
          <span>Print / Export PDF</span>
        </button>
      </div>

      {/* Main Grid: List on Left, Viewer on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Reports List (4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search reports..."
              className="w-full bg-white border border-slate-200 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-900 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="space-y-2">
            {filteredReports.map((rep) => {
              const isSelected = selectedReport?.id === rep.id;
              return (
                <div
                  key={rep.id}
                  onClick={() => {
                    setSelectedReport(rep);
                    soundFX.playClick();
                  }}
                  className={`p-4 rounded-2xl border transition-all cursor-pointer space-y-1.5 ${
                    isSelected
                      ? 'bg-indigo-50/80 border-indigo-300 shadow-xs'
                      : 'bg-white border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>{new Date(rep.created_at).toLocaleDateString()}</span>
                    <span className="text-indigo-600 font-semibold">{rep.generated_by.split(' ')[1] || 'Agent'}</span>
                  </div>
                  <h3 className={`text-xs font-bold ${isSelected ? 'text-indigo-900' : 'text-slate-900'}`}>
                    {rep.title}
                  </h3>
                  <p className="text-[11px] text-slate-500 line-clamp-2">{rep.summary}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Report Document Viewer (8 cols) */}
        <div className="lg:col-span-8">
          {selectedReport ? (
            <div className="bg-white p-6 sm:p-8 rounded-2xl border border-slate-200 shadow-xs space-y-6">
              {/* Document Header */}
              <div className="border-b border-slate-100 pb-5 space-y-2">
                <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600">
                  <ShieldCheck className="w-4 h-4" />
                  <span>AEGIS-X INCIDENT BRIEFING DOCUMENT</span>
                </div>
                <h2 className="text-xl font-bold text-slate-900">{selectedReport.title}</h2>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
                  <span>Author: <strong className="text-slate-700">{selectedReport.generated_by}</strong></span>
                  <span>Date: <strong className="text-slate-700">{new Date(selectedReport.created_at).toLocaleString()}</strong></span>
                  <span>Alert Reference: <strong className="text-indigo-600 font-mono">{selectedReport.alert_id}</strong></span>
                </div>
              </div>

              {/* Summary */}
              <div className="space-y-2 text-xs leading-relaxed">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  1. Executive Incident Summary
                </h4>
                <p className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-700">
                  {selectedReport.summary}
                </p>
              </div>

              {/* Root Cause */}
              {selectedReport.root_cause && (
                <div className="space-y-2 text-xs leading-relaxed">
                  <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    2. Technical Root Cause Assessment
                  </h4>
                  <p className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-700">
                    {selectedReport.root_cause}
                  </p>
                </div>
              )}

              {/* Mitigation Actions */}
              {selectedReport.mitigation && (
                <div className="space-y-2 text-xs leading-relaxed">
                  <h4 className="text-xs font-bold text-emerald-900 uppercase tracking-wider">
                    3. Containment Actions & Security Runbook
                  </h4>
                  <pre className="p-4 rounded-xl bg-emerald-50/60 border border-emerald-200 text-emerald-900 font-mono text-xs whitespace-pre-wrap">
                    {selectedReport.mitigation}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center bg-white rounded-2xl border border-slate-200 text-slate-400 text-xs">
              Select an incident report from the list to view.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
