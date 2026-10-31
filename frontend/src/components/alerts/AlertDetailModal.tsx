import React, { useState, useEffect } from 'react';
import { 
  X, 
  ShieldAlert, 
  Activity, 
  Clock, 
  Globe, 
  Cpu, 
  FileText, 
  Layers, 
  Send, 
  Download, 
  Copy,
  ExternalLink,
  BookOpen,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Lock
} from 'lucide-react';
import type { Alert, ThreatHistory, Report, AlertStatus, AlertSeverity, ResponseAction } from '../../types';
import { api } from '../../services/api';
import { soundFX } from '../../services/soundEffects';
import { MITRE_TECHNIQUES } from '../../services/mockData';
import { useAuth } from '../../context/AuthContext';

interface AlertDetailModalProps {
  alert: Alert | null;
  onClose: () => void;
  onAlertUpdated: (updated: Alert) => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  alert,
  onClose,
  onAlertUpdated,
}) => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'telemetry' | 'mitre' | 'timeline' | 'correlation' | 'report' | 'actions'>('telemetry');
  const [history, setHistory] = useState<ThreatHistory[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [relatedAlerts, setRelatedAlerts] = useState<Alert[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  
  // Note form state
  const [newNote, setNewNote] = useState<string>('');
  const [isAddingNote, setIsAddingNote] = useState<boolean>(false);
  const [statusUpdating, setStatusUpdating] = useState<boolean>(false);
  const [copiedRaw, setCopiedRaw] = useState<boolean>(false);

  useEffect(() => {
    if (!alert) return;
    const loadDetails = async () => {
      try {
        const [histData, repData, relData, actData] = await Promise.all([
          api.getAlertHistory(alert.id),
          api.getAlertReports(alert.id),
          api.getRelatedAlerts({ attack_type: alert.attack_type, source_ip: alert.source_ip || undefined, exclude_id: alert.id }),
          api.listActions({ alert_id: alert.id }),
        ]);
        setHistory(histData);
        setReports(repData);
        setRelatedAlerts(relData);
        setActions(actData);
      } catch (e) {
        console.error('Failed to load alert details', e);
      }
    };
    loadDetails();
  }, [alert]);

  if (!alert) return null;

  const handleStatusChange = async (newStatus: AlertStatus) => {
    setStatusUpdating(true);
    soundFX.playClick();
    try {
      const updated = await api.updateAlert(alert.id, { status: newStatus });
      onAlertUpdated(updated);
      
      const hist = await api.addAlertHistory(alert.id, {
        event_type: 'status_change',
        description: `Alert status updated to "${newStatus.toUpperCase()}" by SOC Analyst.`,
      });
      setHistory((prev) => [...prev, hist]);
      if (newStatus === 'resolved') soundFX.playSuccess();
    } catch (e) {
      console.error('Status update failed', e);
    } finally {
      setStatusUpdating(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setIsAddingNote(true);
    soundFX.playClick();
    try {
      const hist = await api.addAlertHistory(alert.id, {
        event_type: 'note',
        description: newNote,
      });
      setHistory((prev) => [...prev, hist]);
      setNewNote('');
    } catch (e) {
      console.error('Add note error', e);
    } finally {
      setIsAddingNote(false);
    }
  };

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(JSON.stringify(alert.raw_event || alert, null, 2));
    setCopiedRaw(true);
    soundFX.playClick();
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleDecideAction = async (actionId: string, decision: 'approved' | 'rejected') => {
    soundFX.playClick();
    setActionError(null);
    try {
      const updated = await api.decideAction(actionId, decision, `Analyst decided via Alert Drawer`);
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setActionSuccess(`Containment action [${updated.action_type.toUpperCase()}] ${decision === 'approved' ? 'executed' : 'rejected'}.`);
      soundFX.playSuccess();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (e: any) {
      console.error('Decide action error', e);
      setActionError(e.message || 'Action authorization failed');
      soundFX.playThreatAlarm();
    }
  };

  const handleGenerateRecommendation = async () => {
    soundFX.playScan();
    try {
      const isExternalIP = alert.source_ip && !alert.source_ip.startsWith('10.') && !alert.source_ip.startsWith('192.168.');
      const actionType = isExternalIP ? 'block_ip' : 'isolate_host';
      const blastRadius = isExternalIP ? 'LOW' : 'HIGH';
      const target = isExternalIP ? (alert.source_ip || 'unknown') : (alert.destination_ip || '192.168.1.100');
      
      const newAct = await api.createAction({
        alert_id: alert.id,
        action_type: actionType,
        target,
        blast_radius: blastRadius,
        required_role: blastRadius === 'HIGH' ? 'admin' : 'analyst',
        description: `Apply dynamic containment for incident ${alert.title}.`,
        rationale: `Anomaly score ${alert.anomaly_score?.toFixed(2)} with calibrated risk ${alert.risk_score?.toFixed(1)}.`,
        rollback_plan: isExternalIP ? `iptables -D INPUT -s ${target} -j DROP` : `edr un-isolate --target ${target}`,
      });
      setActions((prev) => [newAct, ...prev]);
      setActionSuccess('New containment recommendation staged for human approval.');
      soundFX.playSuccess();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (e: any) {
      console.error('Failed to generate recommendation', e);
      setActionError(e.message || 'Generation failed');
    }
  };


  const mitreInfo = MITRE_TECHNIQUES.find((m) => m.id === alert.mitre_technique_id) || {
    id: alert.mitre_technique_id || 'T1498',
    name: alert.mitre_technique_name || 'Network Denial of Service',
    tactic: 'Impact',
    description: 'Adversary executes network volumetric or application resource exhaustion to disrupt operations.',
    mitigation: 'Implement rate limiting, BGP Flowspec filtering, and edge web application firewall rules.',
    detection_hints: ['High flow packet rates', 'Abnormal TCP flag distribution', 'Repetitive payload signatures'],
    severity_typical: 'high' as AlertSeverity,
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-white rounded-2xl border border-slate-200 shadow-xl flex flex-col overflow-hidden text-slate-800 text-xs">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-100 flex flex-wrap items-center justify-between gap-3 bg-slate-50/50">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-rose-50 text-rose-600 border border-rose-100">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(alert.severity)}`}>
                  {alert.severity}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-700 uppercase">
                  {alert.attack_type.replace('_', ' ')}
                </span>
              </div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 mt-1">
                {alert.title}
              </h2>
            </div>
          </div>

          {/* Quick Status and Close */}
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-1.5 bg-white border border-slate-200 px-3 py-1.5 rounded-xl">
              <span className="text-slate-500 font-medium">Status:</span>
              <select
                value={alert.status}
                onChange={(e) => handleStatusChange(e.target.value as AlertStatus)}
                disabled={statusUpdating}
                aria-label="Alert Status"
                className="bg-transparent text-indigo-600 font-semibold focus:outline-none cursor-pointer"
              >
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>

            <button
              onClick={() => {
                soundFX.playClick();
                onClose();
              }}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-all"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Top KPI Metric Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 bg-slate-50 border-b border-slate-200">
          <div className="p-3 rounded-xl bg-white border border-slate-200 flex items-center justify-between shadow-2xs">
            <div>
              <div className="text-[11px] text-slate-500">Calculated Risk</div>
              <div className="text-lg font-bold text-rose-600">
                {alert.risk_score?.toFixed(1) || '85.0'}
                <span className="text-xs text-slate-400 font-normal"> / 100</span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-rose-50 text-rose-700 font-bold">
              {Math.round(alert.risk_score || 85)}%
            </span>
          </div>

          <div className="p-3 rounded-xl bg-white border border-slate-200 flex items-center justify-between shadow-2xs">
            <div>
              <div className="text-[11px] text-slate-500">Isolation Forest</div>
              <div className="text-lg font-bold text-slate-900 font-mono">
                {alert.anomaly_score?.toFixed(2) || '0.88'}
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-50 text-indigo-700 font-bold">
              OUTLIER
            </span>
          </div>

          <div className="p-3 rounded-xl bg-white border border-slate-200 flex items-center justify-between shadow-2xs">
            <div>
              <div className="text-[11px] text-slate-500">Model Confidence</div>
              <div className="text-lg font-bold text-indigo-600 font-mono">
                {((alert.confidence || 0.94) * 100).toFixed(1)}%
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-purple-50 text-purple-700 font-bold">
              XGBOOST
            </span>
          </div>

          <div className="p-3 rounded-xl bg-white border border-slate-200 flex items-center justify-between shadow-2xs">
            <div>
              <div className="text-[11px] text-slate-500">MITRE Technique</div>
              <div className="text-sm font-bold text-amber-700 truncate max-w-[120px]">
                {alert.mitre_technique_id || 'T1498'}
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-amber-50 text-amber-800 font-medium">
              {mitreInfo.tactic}
            </span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-200 px-4 bg-white overflow-x-auto">
          {[
            { id: 'telemetry', label: 'Flow & SHAP Explainability', icon: Activity },
            { id: 'actions', label: `Containment Actions (${actions.length})`, icon: ShieldCheck },
            { id: 'mitre', label: 'MITRE ATT&CK & Policy', icon: BookOpen },
            { id: 'timeline', label: `Timeline & Notes (${history.length})`, icon: Clock },
            { id: 'correlation', label: `Correlation (${relatedAlerts.length})`, icon: Layers },
            { id: 'report', label: 'Executive Incident Brief', icon: FileText },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id as any);
                  soundFX.playClick();
                }}
                className={`flex items-center space-x-2 py-3 px-4 text-xs font-medium border-b-2 transition-all whitespace-nowrap ${
                  isActive
                    ? 'border-indigo-600 text-indigo-600 font-bold'
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Modal Body */}
        <div className="p-5 sm:p-6 overflow-y-auto flex-1 space-y-6">
          {/* TAB 1: Telemetry & SHAP */}
          {activeTab === 'telemetry' && (
            <div className="space-y-6">
              {/* Telemetry Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
                  <div className="text-slate-900 font-semibold flex items-center space-x-2 border-b border-slate-200 pb-2">
                    <Globe className="w-4 h-4 text-indigo-600" />
                    <span>Network Flow Telemetry</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-slate-400 block text-[11px]">Source IP & Port</span>
                      <span className="font-semibold text-slate-900 font-mono">{alert.source_ip || '185.220.101.5'}:{alert.source_port || 44120}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[11px]">Target IP & Port</span>
                      <span className="font-semibold text-indigo-600 font-mono">{alert.destination_ip || '198.51.100.24'}:{alert.destination_port || 80}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[11px]">Protocol</span>
                      <span className="font-medium text-slate-800">{alert.protocol || 'TCP'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[11px]">Source Ingestion</span>
                      <span className="font-medium text-slate-800 uppercase">{alert.source.replace('_', ' ')}</span>
                    </div>
                  </div>
                </div>

                {/* AI Rationale */}
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
                  <div className="text-slate-900 font-semibold flex items-center space-x-2 border-b border-slate-200 pb-2">
                    <Cpu className="w-4 h-4 text-purple-600" />
                    <span>AI Detection Summary</span>
                  </div>
                  <p className="text-slate-600 leading-relaxed text-xs">
                    {alert.description || 'Isolation Forest outlier detection identified non-standard traffic surge.'}
                  </p>
                  <div className="p-2.5 rounded-lg bg-indigo-50 border border-indigo-100 text-[11px] text-indigo-900">
                    <strong>Ensemble Decision:</strong> Mapped to <strong>{alert.attack_type.toUpperCase()}</strong> with {((alert.confidence || 0.94) * 100).toFixed(1)}% statistical certainty.
                  </div>
                </div>
              </div>

              {/* SHAP Feature Contribution Chart */}
              <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-2xs space-y-3">
                <div>
                  <h3 className="text-sm font-bold text-slate-900">
                    SHAP Feature Importance & Model Weights
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    How specific network flow parameters pushed the XGBoost model towards this attack classification.
                  </p>
                </div>

                <div className="space-y-3 pt-2">
                  {(alert.shap_values || [
                    { feature: 'Flow Packets/s', impact: 0.42, value: '4,028.2 pkts/s' },
                    { feature: 'SYN Flag Count', impact: 0.31, value: 4850 },
                    { feature: 'Flow Duration', impact: 0.18, value: '1.20 ms' },
                    { feature: 'Bwd Packet Length Std', impact: 0.09, value: '0.00 bytes' },
                  ]).map((shap, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="font-semibold text-slate-800">{shap.feature} <span className="text-slate-400 font-normal font-mono">({shap.value})</span></span>
                        <span className="font-semibold text-indigo-600">+{Math.round(shap.impact * 100)}% contribution</span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-slate-100 overflow-hidden">
                        <div
                          className="h-full bg-indigo-600 rounded-full transition-all duration-300"
                          style={{ width: `${Math.min(100, Math.max(10, Math.abs(shap.impact) * 100))}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Raw JSON Inspector */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-700">
                    Raw Telemetry Event JSON
                  </span>
                  <button
                    onClick={handleCopyRaw}
                    className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-white border border-slate-200 text-xs text-slate-700 hover:bg-slate-100"
                  >
                    <Copy className="w-3 h-3 text-slate-500" />
                    <span>{copiedRaw ? 'Copied!' : 'Copy JSON'}</span>
                  </button>
                </div>
                <pre className="text-[11px] font-mono text-slate-800 overflow-x-auto p-3 bg-white rounded-lg border border-slate-200 max-h-36">
                  {JSON.stringify(alert.raw_event || {
                    flow_duration: 1204,
                    total_fwd_packets: 4850,
                    total_bwd_packets: 12,
                    flow_packets_per_s: 4028.2,
                    flow_bytes_per_s: 241692.0,
                    syn_flag_count: 4850,
                  }, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {/* TAB: Containment Actions */}
          {activeTab === 'actions' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-900">Incident Containment Actions</h3>
                  <p className="text-xs text-slate-500">
                    Defensive recommendations generated by Response Agent. All actions require analyst authorization.
                  </p>
                </div>
                <button
                  onClick={handleGenerateRecommendation}
                  className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold flex items-center gap-1 shadow-xs"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Stage Containment Action
                </button>
              </div>

              {actionError && (
                <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                  <span>{actionError}</span>
                </div>
              )}

              {actionSuccess && (
                <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>{actionSuccess}</span>
                </div>
              )}

              {actions.length === 0 ? (
                <div className="p-8 text-center bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                  <p className="text-slate-500 text-xs">No active containment actions for this alert.</p>
                  <button
                    onClick={handleGenerateRecommendation}
                    className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs inline-flex items-center gap-1.5"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    Stage Containment Recommendation
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  {actions.map((act) => {
                    const isHighRestricted = (act.blast_radius === 'HIGH' || act.required_role === 'admin') && user?.role !== 'admin';

                    return (
                      <div
                        key={act.id}
                        className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs space-y-3"
                      >
                        <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-slate-900 text-xs uppercase bg-slate-100 px-2 py-0.5 rounded">
                              {act.action_type.toUpperCase()}
                            </span>
                            <span className="text-slate-500 text-xs font-mono">
                              Target: <strong className="text-indigo-600">{act.target}</strong>
                            </span>
                            <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                              act.blast_radius === 'HIGH' ? 'bg-rose-100 text-rose-800' :
                              act.blast_radius === 'MEDIUM' ? 'bg-amber-100 text-amber-800' :
                              'bg-sky-100 text-sky-800'
                            }`}>
                              {act.blast_radius} BLAST
                            </span>
                          </div>

                          <span className={`px-2 py-0.5 text-[10px] font-semibold rounded uppercase ${
                            act.status === 'executed' ? 'bg-emerald-100 text-emerald-800' :
                            act.status === 'rejected' ? 'bg-slate-100 text-slate-600' :
                            'bg-amber-100 text-amber-800 animate-pulse'
                          }`}>
                            {act.status.replace('_', ' ')}
                          </span>
                        </div>

                        <div className="text-xs text-slate-700 space-y-1.5">
                          <div><span className="font-semibold text-slate-600">Description:</span> {act.description}</div>
                          {act.rationale && (
                            <div><span className="font-semibold text-slate-600">Rationale:</span> {act.rationale}</div>
                          )}
                          {act.rollback_plan && (
                            <div>
                              <span className="font-semibold text-slate-600">Rollback:</span>{' '}
                              <code className="text-indigo-600 font-mono text-[11px] bg-slate-50 px-1 py-0.5 rounded">
                                {act.rollback_plan}
                              </code>
                            </div>
                          )}
                        </div>

                        {act.status === 'pending_approval' && (
                          <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
                            <span className="text-[11px] text-slate-400 font-mono">
                              Required Role: <strong className="uppercase text-slate-600">{act.required_role}</strong>
                            </span>

                            <div className="flex items-center gap-2">
                              {isHighRestricted ? (
                                <span className="text-xs text-rose-600 bg-rose-50 px-2.5 py-1 rounded border border-rose-200 font-medium flex items-center gap-1">
                                  <Lock className="w-3 h-3" />
                                  Requires Admin Role
                                </span>
                              ) : (
                                <button
                                  onClick={() => handleDecideAction(act.id, 'approved')}
                                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold flex items-center gap-1 shadow-xs"
                                >
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                  Authorize & Execute
                                </button>
                              )}

                              <button
                                onClick={() => handleDecideAction(act.id, 'rejected')}
                                className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-100 text-slate-700 text-xs font-medium"
                              >
                                Reject
                              </button>
                            </div>
                          </div>
                        )}

                        {act.execution_log && (
                          <div className="mt-2 p-2.5 rounded-lg bg-slate-900 text-emerald-400 font-mono text-[10px]">
                            <div>✓ Containment Daemon Execution Confirmed</div>
                            <div className="text-slate-400 mt-0.5">Notes: {act.execution_log.notes || 'None'}</div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: MITRE & Policy */}
          {activeTab === 'mitre' && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-2xs space-y-3">
                <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                  <div className="flex items-center space-x-2.5">
                    <span className="px-2.5 py-1 rounded-lg bg-amber-100 text-amber-800 font-bold">
                      {mitreInfo.id}
                    </span>
                    <div>
                      <h3 className="text-sm font-bold text-slate-900">{mitreInfo.name}</h3>
                      <span className="text-xs text-slate-500">Tactic: {mitreInfo.tactic}</span>
                    </div>
                  </div>
                  <a
                    href={`https://attack.mitre.org/techniques/${mitreInfo.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 flex items-center space-x-1"
                  >
                    <span>MITRE Docs</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>

                <p className="text-slate-600 leading-relaxed text-xs">
                  {mitreInfo.description}
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                    <div className="font-semibold text-indigo-900">Recommended Mitigation</div>
                    <p className="text-slate-600 text-[11px] leading-relaxed">{mitreInfo.mitigation}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                    <div className="font-semibold text-emerald-900">Detection Signatures</div>
                    <ul className="list-disc list-inside space-y-0.5 text-slate-600 text-[11px]">
                      {mitreInfo.detection_hints.map((h, i) => (
                        <li key={i}>{h}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              {/* Security Policy */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between font-semibold text-slate-900">
                  <span className="flex items-center space-x-1.5">
                    <BookOpen className="w-4 h-4 text-indigo-600" />
                    <span>Matched Response Runbook (RAG Enriched)</span>
                  </span>
                  <span className="text-xs text-amber-700 font-medium">POL-002: SLA 5 Min</span>
                </div>
                <p className="text-slate-600 text-xs leading-relaxed">
                  Upon detection of sustained volumetric traffic exceeding 3x baseline from external IP addresses, the on-call analyst must immediately trigger edge traffic scrubbing and verify zero service degradation.
                </p>
              </div>
            </div>
          )}

          {/* TAB 3: Timeline & Notes */}
          {activeTab === 'timeline' && (
            <div className="space-y-5">
              {/* Note Form */}
              <form onSubmit={handleAddNote} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <label className="block text-xs font-semibold text-slate-800">
                  Add Analyst Note to Investigation Log
                </label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    placeholder="Type note or containment update..."
                    className="flex-1 bg-white border border-slate-200 rounded-xl px-3.5 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-indigo-500"
                  />
                  <button
                    type="submit"
                    disabled={isAddingNote || !newNote.trim()}
                    className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-medium text-xs transition-all flex items-center space-x-1.5 disabled:opacity-40"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Save</span>
                  </button>
                </div>
              </form>

              {/* Timeline list */}
              <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
                {history.map((hist, idx) => (
                  <div key={hist.id || idx} className="relative">
                    <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-indigo-600 border-2 border-white" />
                    <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-2xs space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-slate-900">{hist.actor_label || 'AEGIS-X Agent'}</span>
                        <span className="text-slate-400">{new Date(hist.created_at).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-slate-600 text-xs leading-relaxed">{hist.description}</p>
                      <div className="pt-1">
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 uppercase font-medium">
                          {hist.event_type}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: Correlation */}
          {activeTab === 'correlation' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-indigo-50/70 border border-indigo-100 text-xs text-indigo-900">
                Prior security alerts matching source IP <strong className="font-mono">{alert.source_ip || '185.220.101.5'}</strong> or attack vector <strong className="font-mono">{alert.attack_type}</strong>.
              </div>

              {relatedAlerts.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-xs">
                  No other historical events associated with this host.
                </div>
              ) : (
                <div className="space-y-2">
                  {relatedAlerts.map((rel) => (
                    <div
                      key={rel.id}
                      className="p-3.5 rounded-xl bg-white border border-slate-200 hover:border-indigo-300 transition-all flex items-center justify-between"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(rel.severity)}`}>
                            {rel.severity}
                          </span>
                          <span className="font-semibold text-slate-900 text-xs">{rel.title}</span>
                        </div>
                        <div className="text-slate-500 font-mono text-[11px]">
                          Src: {rel.source_ip} | Target: {rel.destination_ip}
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-medium uppercase text-[10px]">
                        {rel.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 5: Executive Report */}
          {activeTab === 'report' && (
            <div className="space-y-4">
              {reports.length === 0 ? (
                <div className="p-8 text-center bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                  <p className="text-slate-500 text-xs">No formal incident report compiled yet for this alert.</p>
                  <button
                    onClick={async () => {
                      const rep = await api.createAlertReport(alert.id, {
                        title: `Incident Response Briefing: ${alert.title}`,
                        summary: `Autonomous synthesis: Detection pipeline intercepted ${alert.attack_type.toUpperCase()} traffic targeting ${alert.destination_ip}:${alert.destination_port}. Anomaly score ${alert.anomaly_score} triggered automatic RAG containment policy.`,
                        root_cause: `External entity at ${alert.source_ip} leveraged MITRE technique ${alert.mitre_technique_id || 'T1498'}.`,
                        mitigation: `1. Enforce perimeter firewall drop on ${alert.source_ip}.\n2. Retain 90-day forensic pcap logs.\n3. Verify endpoint health.`,
                      });
                      setReports([rep]);
                      soundFX.playSuccess();
                    }}
                    className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs"
                  >
                    Generate Executive Briefing
                  </button>
                </div>
              ) : (
                reports.map((rep) => (
                  <div key={rep.id} className="p-5 rounded-xl bg-white border border-slate-200 shadow-2xs space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                      <div>
                        <h3 className="text-sm font-bold text-slate-900">{rep.title}</h3>
                        <div className="text-xs text-slate-400 mt-0.5">
                          Compiled by {rep.generated_by} • {new Date(rep.created_at).toLocaleString()}
                        </div>
                      </div>
                      <button
                        onClick={() => window.print()}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Print PDF</span>
                      </button>
                    </div>

                    <div className="space-y-3 text-xs text-slate-700 leading-relaxed">
                      <div>
                        <div className="font-semibold text-slate-900 mb-1">Executive Summary</div>
                        <p className="p-3 rounded-lg bg-slate-50 border border-slate-200">{rep.summary}</p>
                      </div>
                      {rep.root_cause && (
                        <div>
                          <div className="font-semibold text-slate-900 mb-1">Root Cause</div>
                          <p className="p-3 rounded-lg bg-slate-50 border border-slate-200">{rep.root_cause}</p>
                        </div>
                      )}
                      {rep.mitigation && (
                        <div>
                          <div className="font-semibold text-emerald-900 mb-1">Containment & Remediation Playbook</div>
                          <pre className="p-3 rounded-lg bg-emerald-50/50 border border-emerald-100 font-mono text-[11px] text-emerald-900 whitespace-pre-wrap">
                            {rep.mitigation}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
