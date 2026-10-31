import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Lock, 
  Server, 
  Filter, 
  RefreshCw,
  Terminal
} from 'lucide-react';
import { api } from '../services/api';
import { soundFX } from '../services/soundEffects';
import { useAuth } from '../context/AuthContext';
import type { ResponseAction, ActionStatus } from '../types';

interface ResponseManagementViewProps {
  onSelectAlert?: (alertId: string) => void;
}

export const ResponseManagementView: React.FC<ResponseManagementViewProps> = ({ onSelectAlert: _onSelectAlert }) => {
  const { user } = useAuth();
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [blastFilter, setBlastFilter] = useState<string>('all');
  const [actionTypeFilter, setActionTypeFilter] = useState<string>('all');
  const [selectedAction, setSelectedAction] = useState<ResponseAction | null>(null);
  
  // Decision modal state
  const [decisionModalAction, setDecisionModalAction] = useState<ResponseAction | null>(null);
  const [decisionType, setDecisionType] = useState<'approved' | 'rejected'>('approved');
  const [decisionNotes, setDecisionNotes] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);

  const fetchActions = async () => {
    setIsLoading(true);
    setActionError(null);
    try {
      const data = await api.listActions();
      setActions(data);
    } catch (e: any) {
      console.error('Failed to load response actions', e);
      setActionError(e.message || 'Failed to load containment actions');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchActions();
  }, []);

  const handleOpenDecision = (action: ResponseAction, type: 'approved' | 'rejected') => {
    soundFX.playClick();
    setDecisionModalAction(action);
    setDecisionType(type);
    setDecisionNotes('');
    setActionError(null);
  };

  const handleExecuteDecision = async () => {
    if (!decisionModalAction) return;
    setIsSubmitting(true);
    setActionError(null);
    soundFX.playScan();

    try {
      const updated = await api.decideAction(
        decisionModalAction.id,
        decisionType,
        decisionNotes || (decisionType === 'approved' ? 'Approved by SOC Analyst' : 'Rejected by SOC Analyst')
      );
      
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setDecisionModalAction(null);
      setFeedbackSuccess(
        decisionType === 'approved' 
          ? `Containment action [${updated.action_type.toUpperCase()}] executed on target ${updated.target}.`
          : `Containment action [${updated.action_type.toUpperCase()}] was rejected.`
      );
      soundFX.playSuccess();
      setTimeout(() => setFeedbackSuccess(null), 5000);
    } catch (e: any) {
      console.error('Decision execution error', e);
      setActionError(e.message || 'Execution failed. Ensure your user account holds required administrative permissions.');
      soundFX.playThreatAlarm();
    } finally {
      setIsSubmitting(false);
    }
  };

  const filteredActions = actions.filter((act) => {
    if (statusFilter !== 'all' && act.status !== statusFilter) return false;
    if (blastFilter !== 'all' && act.blast_radius !== blastFilter) return false;
    if (actionTypeFilter !== 'all' && act.action_type !== actionTypeFilter) return false;
    return true;
  });

  const pendingCount = actions.filter((a) => a.status === 'pending_approval').length;
  const executedCount = actions.filter((a) => a.status === 'executed').length;
  const highBlastPending = actions.filter((a) => a.status === 'pending_approval' && a.blast_radius === 'HIGH').length;

  const getBlastBadge = (blast: string) => {
    switch (blast) {
      case 'HIGH':
        return 'bg-rose-100 text-rose-800 border-rose-200';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      default:
        return 'bg-sky-100 text-sky-800 border-sky-200';
    }
  };

  const getStatusBadge = (status: ActionStatus) => {
    switch (status) {
      case 'pending_approval':
        return 'bg-amber-100 text-amber-800 border-amber-300 animate-pulse';
      case 'executed':
        return 'bg-emerald-100 text-emerald-800 border-emerald-300';
      case 'rejected':
        return 'bg-slate-100 text-slate-700 border-slate-300';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Page Header */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">
            <Lock className="w-4 h-4 text-indigo-600" />
            Human-in-the-Loop Safeguards
          </div>
          <h1 className="text-2xl font-bold text-slate-900">Incident Containment & Response Management</h1>
          <p className="text-sm text-slate-500 mt-1">
            Autonomous execution of destructive actions is prohibited. All host isolations, IP blocks, and account revocations require explicit authenticated human authorization.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              soundFX.playClick();
              fetchActions();
            }}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-200 text-slate-700 hover:bg-slate-50 text-sm font-medium transition-all"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {feedbackSuccess && (
        <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-sm flex items-center gap-2">
          <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
          <span>{feedbackSuccess}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Awaiting Authorization</div>
            <div className="text-2xl font-bold text-amber-600 mt-1">{pendingCount}</div>
            <div className="text-xs text-slate-500 mt-0.5">Pending analyst review</div>
          </div>
          <div className="p-3 rounded-xl bg-amber-50 text-amber-600">
            <Clock className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">High Blast Radius Pending</div>
            <div className="text-2xl font-bold text-rose-600 mt-1">{highBlastPending}</div>
            <div className="text-xs text-rose-600/80 mt-0.5">Requires 'admin' role</div>
          </div>
          <div className="p-3 rounded-xl bg-rose-50 text-rose-600">
            <AlertTriangle className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Executed Containments</div>
            <div className="text-2xl font-bold text-emerald-600 mt-1">{executedCount}</div>
            <div className="text-xs text-slate-500 mt-0.5">Audited & active containment</div>
          </div>
          <div className="p-3 rounded-xl bg-emerald-50 text-emerald-600">
            <ShieldCheck className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <Filter className="w-3.5 h-3.5" />
            Filters:
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="text-xs rounded-lg border border-slate-200 px-3 py-1.5 bg-white text-slate-700"
          >
            <option value="all">All Statuses</option>
            <option value="pending_approval">Pending Approval</option>
            <option value="executed">Executed</option>
            <option value="rejected">Rejected</option>
          </select>

          <select
            value={blastFilter}
            onChange={(e) => setBlastFilter(e.target.value)}
            className="text-xs rounded-lg border border-slate-200 px-3 py-1.5 bg-white text-slate-700"
          >
            <option value="all">All Blast Radii</option>
            <option value="LOW">Low Blast Radius</option>
            <option value="MEDIUM">Medium Blast Radius</option>
            <option value="HIGH">High Blast Radius</option>
          </select>

          <select
            value={actionTypeFilter}
            onChange={(e) => setActionTypeFilter(e.target.value)}
            className="text-xs rounded-lg border border-slate-200 px-3 py-1.5 bg-white text-slate-700"
          >
            <option value="all">All Action Types</option>
            <option value="block_ip">Block IP</option>
            <option value="isolate_host">Isolate Host</option>
            <option value="disable_user">Disable User</option>
            <option value="revoke_credentials">Revoke Credentials</option>
            <option value="kill_process">Kill Process</option>
          </select>
        </div>

        <div className="text-xs text-slate-500 font-mono">
          Showing {filteredActions.length} actions | Current user role: <span className="font-bold text-indigo-600 uppercase">{user?.role || 'analyst'}</span>
        </div>
      </div>

      {/* Actions Table */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-600 uppercase tracking-wider">
                <th className="py-3.5 px-4">Action & Target</th>
                <th className="py-3.5 px-4">Blast Radius</th>
                <th className="py-3.5 px-4">Required Role</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Created By</th>
                <th className="py-3.5 px-4 text-right">Decide & Audit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-sm text-slate-700">
              {filteredActions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400 text-sm">
                    No containment actions match the selected filters.
                  </td>
                </tr>
              ) : (
                filteredActions.map((act) => {
                  const isHighAdminRestricted = (act.blast_radius === 'HIGH' || act.required_role === 'admin') && user?.role !== 'admin';

                  return (
                    <tr 
                      key={act.id} 
                      className="hover:bg-slate-50/70 transition-colors cursor-pointer"
                      onClick={() => setSelectedAction(act)}
                    >
                      <td className="py-4 px-4">
                        <div className="flex items-center gap-2.5">
                          <div className="p-2 rounded-lg bg-slate-100 text-slate-700">
                            {act.action_type === 'isolate_host' ? (
                              <Server className="w-4 h-4 text-rose-600" />
                            ) : act.action_type === 'disable_user' ? (
                              <Lock className="w-4 h-4 text-amber-600" />
                            ) : (
                              <Terminal className="w-4 h-4 text-indigo-600" />
                            )}
                          </div>
                          <div>
                            <div className="font-semibold text-slate-900 font-mono">
                              {act.action_type.toUpperCase()}
                            </div>
                            <div className="text-xs text-slate-500 font-mono flex items-center gap-1.5">
                              Target: <span className="text-indigo-600 font-semibold">{act.target}</span>
                            </div>
                          </div>
                        </div>
                      </td>

                      <td className="py-4 px-4">
                        <span className={`inline-block px-2.5 py-1 text-xs font-bold rounded-md border ${getBlastBadge(act.blast_radius)}`}>
                          {act.blast_radius}
                        </span>
                      </td>

                      <td className="py-4 px-4">
                        <span className="text-xs font-mono font-medium text-slate-600 uppercase bg-slate-100 px-2 py-0.5 rounded">
                          {act.required_role}
                        </span>
                      </td>

                      <td className="py-4 px-4">
                        <span className={`inline-block px-2.5 py-1 text-xs font-semibold rounded-md border ${getStatusBadge(act.status)}`}>
                          {act.status.replace('_', ' ').toUpperCase()}
                        </span>
                      </td>

                      <td className="py-4 px-4 text-xs text-slate-500">
                        <div>{act.created_by}</div>
                        <div className="text-[11px] text-slate-400">{new Date(act.created_at).toLocaleTimeString()}</div>
                      </td>

                      <td className="py-4 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        {act.status === 'pending_approval' ? (
                          <div className="flex items-center justify-end gap-2">
                            {isHighAdminRestricted ? (
                              <span className="text-xs text-rose-600 bg-rose-50 px-2 py-1 rounded border border-rose-200 font-medium flex items-center gap-1">
                                <Lock className="w-3 h-3" />
                                Requires Admin
                              </span>
                            ) : (
                              <button
                                onClick={() => handleOpenDecision(act, 'approved')}
                                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold flex items-center gap-1 transition-all shadow-xs"
                              >
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                Approve
                              </button>
                            )}

                            <button
                              onClick={() => handleOpenDecision(act, 'rejected')}
                              className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-100 text-slate-700 text-xs font-medium transition-all"
                            >
                              Reject
                            </button>
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400 italic">
                            {act.status === 'executed' ? 'Executed' : 'Closed'}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Action Drawer / Details */}
      {selectedAction && (
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-0.5 text-xs font-bold rounded-md border ${getBlastBadge(selectedAction.blast_radius)}`}>
                  {selectedAction.blast_radius} BLAST RADIUS
                </span>
                <span className={`px-2.5 py-0.5 text-xs font-semibold rounded-md border ${getStatusBadge(selectedAction.status)}`}>
                  {selectedAction.status.toUpperCase()}
                </span>
              </div>
              <h3 className="text-lg font-bold text-slate-900 mt-1">
                {selectedAction.action_type.toUpperCase()} on {selectedAction.target}
              </h3>
            </div>
            <button
              onClick={() => setSelectedAction(null)}
              className="text-xs text-slate-500 hover:text-slate-800"
            >
              Close Details ✕
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="space-y-3">
              <div>
                <span className="font-semibold text-slate-600 uppercase block mb-0.5">Description:</span>
                <p className="text-slate-800 bg-slate-50 p-3 rounded-lg border border-slate-100">
                  {selectedAction.description}
                </p>
              </div>

              <div>
                <span className="font-semibold text-slate-600 uppercase block mb-0.5">Rationale:</span>
                <p className="text-slate-800 bg-slate-50 p-3 rounded-lg border border-slate-100">
                  {selectedAction.rationale || 'Automated containment recommendation generated by Response Agent.'}
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <span className="font-semibold text-slate-600 uppercase block mb-0.5">Rollback Plan:</span>
                <p className="text-slate-800 bg-slate-50 p-3 rounded-lg border border-slate-100 font-mono">
                  {selectedAction.rollback_plan || 'Reversal commands can be issued via daemon terminal.'}
                </p>
              </div>

              {selectedAction.execution_log && (
                <div>
                  <span className="font-semibold text-slate-600 uppercase block mb-0.5">Execution Log & Receipt:</span>
                  <pre className="text-slate-700 bg-slate-900 text-slate-100 p-3 rounded-lg font-mono text-[11px] overflow-x-auto">
                    {JSON.stringify(selectedAction.execution_log, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Decision Confirmation Modal */}
      {decisionModalAction && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4">
          <div className="bg-white rounded-2xl border border-slate-200 max-w-lg w-full p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95">
            <div className="flex items-center gap-3">
              <div className={`p-3 rounded-xl ${decisionType === 'approved' ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'}`}>
                {decisionType === 'approved' ? <CheckCircle2 className="w-6 h-6" /> : <XCircle className="w-6 h-6" />}
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-900">
                  {decisionType === 'approved' ? 'Authorize & Execute Containment' : 'Reject Containment Action'}
                </h3>
                <p className="text-xs text-slate-500 font-mono">
                  Target: {decisionModalAction.target} | Action: {decisionModalAction.action_type.toUpperCase()}
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-1">
              <div><span className="font-semibold">Blast Radius:</span> {decisionModalAction.blast_radius}</div>
              <div><span className="font-semibold">Rollback Plan:</span> {decisionModalAction.rollback_plan}</div>
            </div>

            {actionError && (
              <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{actionError}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Analyst Decision Notes & Justification:
              </label>
              <textarea
                value={decisionNotes}
                onChange={(e) => setDecisionNotes(e.target.value)}
                rows={3}
                placeholder={decisionType === 'approved' ? 'e.g. Host confirmed C2 infected; verified containment won’t disrupt production.' : 'e.g. False positive; IP belongs to external monitoring partner.'}
                className="w-full text-xs rounded-xl border border-slate-200 p-3 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setDecisionModalAction(null)}
                disabled={isSubmitting}
                className="px-4 py-2 rounded-xl border border-slate-200 text-slate-700 hover:bg-slate-50 text-xs font-medium"
              >
                Cancel
              </button>

              <button
                onClick={handleExecuteDecision}
                disabled={isSubmitting}
                className={`px-4 py-2 rounded-xl text-white text-xs font-semibold flex items-center gap-1.5 transition-all shadow-xs ${
                  decisionType === 'approved' ? 'bg-emerald-600 hover:bg-emerald-700' : 'bg-rose-600 hover:bg-rose-700'
                }`}
              >
                {isSubmitting ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : decisionType === 'approved' ? (
                  <CheckCircle2 className="w-3.5 h-3.5" />
                ) : (
                  <XCircle className="w-3.5 h-3.5" />
                )}
                {decisionType === 'approved' ? 'Confirm & Execute' : 'Confirm Rejection'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
