import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Clock, 
  Cpu, 
  Layers, 
  Flame, 
  Globe,
  ArrowUpRight
} from 'lucide-react';
import { useThreatFeed } from '../context/ThreatFeedContext';
import { soundFX } from '../services/soundEffects';
import type { Alert, AttackType } from '../types';

interface DashboardViewProps {
  onSelectAlert: (alert: Alert) => void;
  onNavigate: (view: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onSelectAlert, onNavigate }) => {
  const { alerts, stats, livePackets, triggerSimulationEvent } = useThreatFeed();
  const [selectedAttackFilter, setSelectedAttackFilter] = useState<string>('all');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  const handleSimulateAttack = async (type?: AttackType) => {
    setIsSimulating(true);
    soundFX.playScan();
    await triggerSimulationEvent(type);
    setIsSimulating(false);
  };

  // Compute Attack Breakdown counts
  const attackTypes: AttackType[] = ['ddos', 'brute_force', 'port_scan', 'sql_injection', 'botnet', 'web_attack', 'normal', 'other'];
  const attackCounts = attackTypes.map((type) => ({
    type,
    count: alerts.filter((a) => a.attack_type === type).length,
    percentage: alerts.length > 0 ? Math.round((alerts.filter((a) => a.attack_type === type).length / alerts.length) * 100) : 0,
  }));

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

  const filteredRecentAlerts = alerts
    .filter((a) => selectedAttackFilter === 'all' || a.attack_type === selectedAttackFilter)
    .slice(0, 6);

  return (
    <div className="space-y-6 pb-12">
      {/* Top Welcome Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600 mb-1">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500" />
            <span>SOC Operational Command</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Security Overview & Threat Defense Grid
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Real-time telemetry monitoring with Isolation Forest anomaly detection & XGBoost multi-class classifier.
          </p>
        </div>

        {/* Quick Simulation Trigger Buttons */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 font-medium text-xs">Simulate Event:</span>
          {[
            { label: 'DDoS SYN', type: 'ddos' as AttackType },
            { label: 'Brute Force', type: 'brute_force' as AttackType },
            { label: 'Port Scan', type: 'port_scan' as AttackType },
            { label: 'SQL Injection', type: 'sql_injection' as AttackType },
          ].map((btn) => (
            <button
              key={btn.label}
              onClick={() => handleSimulateAttack(btn.type)}
              disabled={isSimulating}
              className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-indigo-50 border border-slate-200 hover:border-indigo-200 text-slate-700 hover:text-indigo-700 font-medium transition-all active:scale-95 disabled:opacity-40"
            >
              + {btn.label}
            </button>
          ))}
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">Critical Incidents</span>
            <div className="p-2 rounded-xl bg-rose-50 text-rose-600">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl sm:text-3xl font-bold text-slate-900 font-mono">{stats.critical}</span>
            <span className="text-xs font-semibold text-rose-600">Requires Review</span>
          </div>
          <div className="text-xs text-slate-400">
            {stats.open} Open • {stats.investigating} In Triage
          </div>
        </div>

        {/* Card 2 */}
        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">AI Model Accuracy</span>
            <div className="p-2 rounded-xl bg-indigo-50 text-indigo-600">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl sm:text-3xl font-bold text-indigo-600 font-mono">97.82%</span>
            <span className="text-xs font-semibold text-emerald-600">0.73 Macro F1</span>
          </div>
          <div className="text-xs text-slate-400">
            Isolation Forest + XGBoost
          </div>
        </div>

        {/* Card 3 */}
        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">Avg. Response Time</span>
            <div className="p-2 rounded-xl bg-emerald-50 text-emerald-600">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl sm:text-3xl font-bold text-slate-900 font-mono">1.4 min</span>
            <span className="text-xs font-semibold text-emerald-600">-68% vs Target</span>
          </div>
          <div className="text-xs text-slate-400">
            Automated RAG containment active
          </div>
        </div>

        {/* Card 4 */}
        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">Multi-Agent Pipeline</span>
            <div className="p-2 rounded-xl bg-purple-50 text-purple-600">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl sm:text-3xl font-bold text-slate-900 font-mono">4 Agents</span>
            <span className="text-xs font-semibold text-purple-600">LangGraph</span>
          </div>
          <div className="text-xs text-slate-400">
            Detection → Investigate → RAG → Action
          </div>
        </div>
      </div>

      {/* Main Grid: Telemetry Radar & Attack Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Telemetry Radar & Live Packets (7 cols) */}
        <div className="lg:col-span-7 bg-white rounded-2xl border border-slate-200 p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Globe className="w-4 h-4 text-indigo-600" />
              <h3 className="text-sm font-bold text-slate-900">
                Network Ingress & Live Telemetry Stream
              </h3>
            </div>
            <span className="text-xs font-medium text-emerald-600 flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Monitoring Edge Ingress</span>
            </span>
          </div>

          {/* Clean Light Radar Display */}
          <div className="relative w-full h-48 rounded-xl bg-slate-50 border border-slate-200 overflow-hidden flex items-center justify-center">
            {/* Concentric Circles */}
            <div className="absolute w-40 h-40 rounded-full border border-slate-200" />
            <div className="absolute w-28 h-28 rounded-full border border-slate-200" />
            <div className="absolute w-16 h-16 rounded-full border border-slate-300" />
            <div className="absolute w-full h-[1px] bg-slate-200" />
            <div className="absolute h-full w-[1px] bg-slate-200" />

            {/* Rotating Beam */}
            <div className="absolute w-44 h-44 light-radar-beam animate-radar-sweep pointer-events-none" />

            {/* Radar Blips */}
            {livePackets.slice(0, 5).map((pkt, i) => {
              const angle = (i * 65 + 40) * (Math.PI / 180);
              const radius = 30 + (i * 12);
              const x = Math.cos(angle) * radius;
              const y = Math.sin(angle) * radius;

              return (
                <div
                  key={pkt.id}
                  className="absolute transition-all duration-700 flex items-center space-x-1.5 z-20"
                  style={{ transform: `translate(${x}px, ${y}px)` }}
                >
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      pkt.is_anomalous
                        ? 'bg-rose-500 shadow-sm animate-ping'
                        : 'bg-indigo-600'
                    }`}
                  />
                  {pkt.is_anomalous && (
                    <span className="px-1.5 py-0.2 rounded bg-rose-100 text-rose-800 text-[9px] font-bold">
                      {pkt.attack_label || 'ALERT'}
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Live Packet Stream Table */}
          <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1 text-xs">
            {livePackets.slice(0, 5).map((pkt) => (
              <div
                key={pkt.id}
                className={`px-3 py-1.5 rounded-lg border flex items-center justify-between font-mono text-[11px] ${
                  pkt.is_anomalous
                    ? 'bg-rose-50/70 border-rose-200 text-rose-900'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <div className="flex items-center space-x-2 truncate">
                  <span className="text-slate-400">{pkt.timestamp}</span>
                  <span className="font-semibold text-slate-900">{pkt.source_ip}</span>
                  <span className="text-slate-400">→</span>
                  <span className="text-indigo-600">{pkt.dest_ip}:{pkt.port}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="px-1.5 py-0.2 rounded bg-slate-200 text-[10px] text-slate-700 font-sans">
                    {pkt.protocol}
                  </span>
                  <span className="text-slate-500 font-sans">{pkt.bytes} B</span>
                  {pkt.is_anomalous ? (
                    <span className="px-1.5 py-0.2 rounded bg-rose-200 text-rose-800 text-[10px] font-bold font-sans">
                      ANOMALY
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.2 rounded bg-emerald-100 text-emerald-800 text-[10px] font-sans">
                      OK
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Attack Categories & Multi-Agent Link (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-indigo-600" />
                <span>Attack Classifications</span>
              </h3>
              <span className="text-xs text-slate-400 font-medium">8 Categories</span>
            </div>

            <div className="space-y-2 text-xs">
              {attackCounts.map((item) => (
                <div 
                  key={item.type} 
                  onClick={() => setSelectedAttackFilter(selectedAttackFilter === item.type ? 'all' : item.type)}
                  className={`space-y-1 p-1.5 rounded-lg cursor-pointer transition-colors ${
                    selectedAttackFilter === item.type ? 'bg-indigo-50 border border-indigo-200' : 'hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between text-slate-700">
                    <span className="capitalize font-medium">{item.type.replace('_', ' ')}</span>
                    <span className="font-semibold text-slate-900">
                      {item.count} <span className="text-slate-400 font-normal text-[11px]">({item.percentage}%)</span>
                    </span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-100 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        item.type === 'ddos'
                          ? 'bg-rose-500'
                          : item.type === 'brute_force'
                          ? 'bg-orange-500'
                          : item.type === 'port_scan'
                          ? 'bg-sky-500'
                          : item.type === 'sql_injection'
                          ? 'bg-purple-500'
                          : item.type === 'normal'
                          ? 'bg-emerald-500'
                          : 'bg-amber-500'
                      }`}
                      style={{ width: `${Math.max(4, item.percentage)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Multi-Agent Link Banner */}
          <div className="p-4 rounded-2xl bg-gradient-to-br from-indigo-50 via-purple-50 to-white border border-indigo-100 shadow-xs space-y-2">
            <div className="flex items-center justify-between text-indigo-900 font-semibold text-xs">
              <span className="flex items-center space-x-1.5">
                <Cpu className="w-4 h-4 text-indigo-600" />
                <span>LangGraph AI Multi-Agent Defense</span>
              </span>
              <span className="px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-700 text-[10px] font-bold">
                Active
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Detection → Investigation → RAG Retrieval → Automated Containment Actions.
            </p>
            <button
              onClick={() => onNavigate('agents')}
              className="w-full py-2 px-3 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-medium text-xs flex items-center justify-center space-x-1.5 transition-all shadow-xs"
            >
              <span>Open AI Defense Studio</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Bottom: Recent Incidents Queue */}
      <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-100 pb-3">
          <div>
            <h3 className="text-base font-bold text-slate-900">
              Active Threat Incidents Queue
            </h3>
            <p className="text-xs text-slate-500">
              Click any incident to open the Deep Investigation Modal with SHAP feature explainability.
            </p>
          </div>

          <button
            onClick={() => onNavigate('alerts')}
            className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 flex items-center space-x-1"
          >
            <span>View All ({alerts.length})</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Incident List */}
        <div className="space-y-2">
          {filteredRecentAlerts.map((alt) => (
            <div
              key={alt.id}
              onClick={() => onSelectAlert(alt)}
              className="p-3.5 rounded-xl border border-slate-200 hover:border-indigo-300 hover:bg-slate-50/80 transition-all cursor-pointer flex flex-col md:flex-row md:items-center md:justify-between gap-3 group"
            >
              <div className="flex items-start space-x-3">
                <span className={`mt-0.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(alt.severity)}`}>
                  {alt.severity}
                </span>
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-2">
                    <h4 className="text-xs sm:text-sm font-semibold text-slate-900 group-hover:text-indigo-600 transition-colors">
                      {alt.title}
                    </h4>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 uppercase">
                      {alt.attack_type.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 font-mono flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span>Source: <strong className="text-slate-800 font-semibold">{alt.source_ip || '185.220.101.5'}</strong></span>
                    <span>Target: <strong className="text-indigo-600 font-semibold">{alt.destination_ip || '198.51.100.24'}</strong></span>
                    {alt.mitre_technique_id && (
                      <span className="text-amber-700 font-sans">MITRE: {alt.mitre_technique_id}</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between md:justify-end space-x-3 text-xs border-t md:border-t-0 pt-2 md:pt-0 border-slate-100">
                <div className="text-right">
                  <div className="text-slate-700 font-semibold">
                    Risk: <span className="text-rose-600 font-bold">{alt.risk_score?.toFixed(0) || '85'}</span>/100
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono">
                    {new Date(alt.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>

                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                  alt.status === 'open'
                    ? 'bg-rose-50 text-rose-700 border border-rose-200'
                    : alt.status === 'investigating'
                    ? 'bg-amber-50 text-amber-700 border border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                }`}>
                  {alt.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
