import type {
  Alert,
  AlertCreate,
  AlertUpdate,
  AlertStatus,
  AlertSeverity,
  AttackType,
  AlertSource,
  ThreatHistory,
  Report,
  User,
  TokenResponse,
  AuditLog,
  Setting,
  ResponseAction,
  ActionStatus,
  ActionType,
} from '../types';
import {
  INITIAL_ALERTS,
  INITIAL_HISTORIES,
  INITIAL_REPORTS,
  INITIAL_USERS,
  INITIAL_AUDIT_LOGS,
} from './mockData';

const BASE_URL = '/api/v1';

// In-memory/localStorage stores for offline fallback
const STORAGE_KEYS = {
  TOKEN: 'aegis_access_token',
  REFRESH_TOKEN: 'aegis_refresh_token',
  USER: 'aegis_current_user',
  ALERTS: 'aegis_local_alerts',
  HISTORIES: 'aegis_local_histories',
  REPORTS: 'aegis_local_reports',
  AUDIT_LOGS: 'aegis_local_audit_logs',
  SETTINGS_USER: 'aegis_local_settings_user',
  SETTINGS_SYSTEM: 'aegis_local_settings_system',
  ACTIONS: 'aegis_local_actions',
};

const INITIAL_ACTIONS: ResponseAction[] = [
  {
    id: 'act-001',
    alert_id: 'a1000000-0000-0000-0000-000000000001',
    action_type: 'block_ip',
    target: '185.220.101.5',
    status: 'pending_approval',
    required_role: 'analyst',
    blast_radius: 'LOW',
    description: 'Deploy perimeter iptables DROP rule on external interfaces for adversary source IP.',
    rationale: 'Active DDoS SYN flood exceeding 10,000 pkts/sec targeting edge web services.',
    rollback_plan: 'iptables -D INPUT -s 185.220.101.5 -j DROP',
    created_by: 'ai_response_agent',
    approved_by_id: null,
    approved_at: null,
    executed_at: null,
    execution_log: null,
    created_at: new Date(Date.now() - 15 * 60000).toISOString(),
    updated_at: new Date(Date.now() - 15 * 60000).toISOString(),
  },
  {
    id: 'act-002',
    alert_id: 'a1000000-0000-0000-0000-000000000002',
    action_type: 'isolate_host',
    target: '192.168.1.100',
    status: 'pending_approval',
    required_role: 'admin',
    blast_radius: 'HIGH',
    description: 'Sever network connectivity for endpoint 192.168.1.100 via EDR agent except for SecOps telemetry.',
    rationale: 'Detected lateral movement and C2 beaconing following compromised credential authentication.',
    rollback_plan: 'Issue EDR un-isolate command via agent API.',
    created_by: 'ai_response_agent',
    approved_by_id: null,
    approved_at: null,
    executed_at: null,
    execution_log: null,
    created_at: new Date(Date.now() - 45 * 60000).toISOString(),
    updated_at: new Date(Date.now() - 45 * 60000).toISOString(),
  },
  {
    id: 'act-003',
    alert_id: 'a1000000-0000-0000-0000-000000000003',
    action_type: 'disable_user',
    target: 'jsmith',
    status: 'executed',
    required_role: 'analyst',
    blast_radius: 'MEDIUM',
    description: 'Suspend Active Directory account and revoke active Kerberos/OAuth sessions.',
    rationale: 'Impossible travel anomaly detected: login from Kyiv and Tokyo within 8 minutes.',
    rollback_plan: 'Re-enable account in AD and trigger password reset workflow.',
    created_by: 'ai_response_agent',
    approved_by_id: 'u1000000-0000-0000-0000-000000000001',
    approved_at: new Date(Date.now() - 90 * 60000).toISOString(),
    executed_at: new Date(Date.now() - 89 * 60000).toISOString(),
    execution_log: {
      executor: 'aegis_containment_daemon',
      notes: 'Analyst approved suspension pending user callback.',
      result: 'success',
    },
    created_at: new Date(Date.now() - 120 * 60000).toISOString(),
    updated_at: new Date(Date.now() - 89 * 60000).toISOString(),
  },
];


// Initialize fallback state if not present
function getFallbackStore<T>(key: string, defaultVal: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) {
      localStorage.setItem(key, JSON.stringify(defaultVal));
      return defaultVal;
    }
    return JSON.parse(raw);
  } catch {
    return defaultVal;
  }
}

function setFallbackStore<T>(key: string, val: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(val));
  } catch (e) {
    console.error('Failed to save to local storage', e);
  }
}

class ApiService {
  private isOnline: boolean = false;
  private checkInterval: any = null;

  constructor() {
    this.checkHealth();
    // Periodically verify if the backend is reachable
    this.checkInterval = setInterval(() => this.checkHealth(), 15000);
  }

  public cleanup(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  public async checkHealth(): Promise<{ status: string; app_name?: string; environment?: string }> {
    try {
      const res = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        const data = await res.json();
        this.isOnline = true;
        return data;
      }
    } catch {
      this.isOnline = false;
    }
    return { status: 'fallback_offline', app_name: 'AEGIS-X (Demo Engine)', environment: 'local-hybrid' };
  }

  public getIsOnline(): boolean {
    return this.isOnline;
  }

  // Token management
  public getToken(): string | null {
    return localStorage.getItem(STORAGE_KEYS.TOKEN);
  }

  public setTokens(tokens: TokenResponse): void {
    localStorage.setItem(STORAGE_KEYS.TOKEN, tokens.access_token);
    localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, tokens.refresh_token);
  }

  public clearTokens(): void {
    localStorage.removeItem(STORAGE_KEYS.TOKEN);
    localStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
    localStorage.removeItem(STORAGE_KEYS.USER);
  }

  private getAuthHeaders(): Record<string, string> {
    const token = this.getToken();
    return {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }

  // --- Auth API ---
  public async login(email: string, password: string): Promise<TokenResponse> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        if (res.ok) {
          const data: TokenResponse = await res.json();
          this.setTokens(data);
          return data;
        }
      } catch (e) {
        console.warn('Backend login failed, using fallback auth', e);
      }
    }

    // Offline / Mock fallback
    const user = INITIAL_USERS.find((u) => u.email.toLowerCase() === email.toLowerCase()) || {
      id: 'mock-user-id-' + Math.random().toString(36).substring(7),
      email,
      full_name: email.split('@')[0].toUpperCase() + ' (SOC Analyst)',
      role: (email.includes('admin') ? 'admin' : 'analyst') as 'admin' | 'analyst',
      is_active: true,
      created_at: new Date().toISOString(),
    };

    const mockTokens: TokenResponse = {
      access_token: 'mock_jwt_access_' + Math.random().toString(36),
      refresh_token: 'mock_jwt_refresh_' + Math.random().toString(36),
      token_type: 'bearer',
    };

    this.setTokens(mockTokens);
    localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
    return mockTokens;
  }

  public async register(email: string, fullName: string, password: string): Promise<User> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, full_name: fullName, password }),
        });
        if (res.ok) {
          return await res.json();
        }
      } catch (e) {
        console.warn('Backend register failed, using fallback', e);
      }
    }

    const newUser: User = {
      id: 'usr-' + Math.random().toString(36).substring(7),
      email,
      full_name: fullName,
      role: 'analyst',
      is_active: true,
      created_at: new Date().toISOString(),
    };
    return newUser;
  }

  public async getMe(): Promise<User> {
    if (this.isOnline && this.getToken()) {
      try {
        const res = await fetch(`${BASE_URL}/auth/me`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) {
          return await res.json();
        }
      } catch (e) {}
    }

    const saved = localStorage.getItem(STORAGE_KEYS.USER);
    if (saved) {
      return JSON.parse(saved);
    }
    return INITIAL_USERS[0];
  }

  public getCurrentUser(): User {
    const saved = localStorage.getItem(STORAGE_KEYS.USER);
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {}
    }
    return INITIAL_USERS[0];
  }


  // --- Alerts API ---
  public async listAlerts(params?: {
    status?: AlertStatus;
    severity?: AlertSeverity;
    attack_type?: AttackType;
    source?: AlertSource;
    page?: number;
    page_size?: number;
    search?: string;
  }): Promise<{ items: Alert[]; total: number; page: number; page_size: number }> {
    if (this.isOnline) {
      try {
        const q = new URLSearchParams();
        if (params?.status) q.append('status', params.status);
        if (params?.severity) q.append('severity', params.severity);
        if (params?.attack_type) q.append('attack_type', params.attack_type);
        if (params?.source) q.append('source', params.source);
        if (params?.page) q.append('page', params.page.toString());
        if (params?.page_size) q.append('page_size', params.page_size.toString());

        const res = await fetch(`${BASE_URL}/alerts?${q.toString()}`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) {
          const data = await res.json();
          return data;
        }
      } catch (e) {
        console.warn('Backend list alerts failed, using local store', e);
      }
    }

    // Local fallback with filtering
    let alerts = getFallbackStore<Alert[]>(STORAGE_KEYS.ALERTS, INITIAL_ALERTS);

    if (params?.status) alerts = alerts.filter((a) => a.status === params.status);
    if (params?.severity) alerts = alerts.filter((a) => a.severity === params.severity);
    if (params?.attack_type) alerts = alerts.filter((a) => a.attack_type === params.attack_type);
    if (params?.source) alerts = alerts.filter((a) => a.source === params.source);
    if (params?.search) {
      const s = params.search.toLowerCase();
      alerts = alerts.filter(
        (a) =>
          a.title.toLowerCase().includes(s) ||
          a.source_ip?.toLowerCase().includes(s) ||
          a.destination_ip?.toLowerCase().includes(s) ||
          a.mitre_technique_id?.toLowerCase().includes(s)
      );
    }

    const page = params?.page || 1;
    const pageSize = params?.page_size || 50;
    const start = (page - 1) * pageSize;
    const paginated = alerts.slice(start, start + pageSize);

    return {
      items: paginated,
      total: alerts.length,
      page,
      page_size: pageSize,
    };
  }

  public async getAlert(alertId: string): Promise<Alert> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/alerts/${alertId}`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const alerts = getFallbackStore<Alert[]>(STORAGE_KEYS.ALERTS, INITIAL_ALERTS);
    const found = alerts.find((a) => a.id === alertId);
    if (found) return found;
    return INITIAL_ALERTS[0];
  }

  public async createAlert(payload: AlertCreate): Promise<Alert> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/alerts`, {
          method: 'POST',
          headers: this.getAuthHeaders(),
          body: JSON.stringify(payload),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const alerts = getFallbackStore<Alert[]>(STORAGE_KEYS.ALERTS, INITIAL_ALERTS);
    const now = new Date().toISOString();
    const newAlert: Alert = {
      id: 'alt-' + Math.random().toString(36).substring(2, 10),
      title: payload.title,
      description: payload.description || '',
      source: payload.source,
      attack_type: payload.attack_type,
      status: 'open',
      severity: payload.severity,
      anomaly_score: payload.anomaly_score ?? 0.85,
      risk_score: payload.risk_score ?? 80,
      confidence: payload.confidence ?? 0.9,
      source_ip: payload.source_ip || '198.51.100.99',
      destination_ip: payload.destination_ip || '10.0.1.10',
      source_port: payload.source_port || 49200,
      destination_port: payload.destination_port || 80,
      protocol: payload.protocol || 'TCP',
      mitre_technique_id: payload.mitre_technique_id || 'T1498',
      mitre_technique_name: payload.mitre_technique_name || 'Network Denial of Service',
      assigned_to_id: null,
      detected_at: now,
      created_at: now,
      updated_at: now,
      raw_event: payload.raw_event || {},
      is_anomaly: (payload.anomaly_score ?? 0.85) > 0.5,
    };

    alerts.unshift(newAlert);
    setFallbackStore(STORAGE_KEYS.ALERTS, alerts);
    return newAlert;
  }

  public async updateAlert(alertId: string, payload: AlertUpdate): Promise<Alert> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/alerts/${alertId}`, {
          method: 'PATCH',
          headers: this.getAuthHeaders(),
          body: JSON.stringify(payload),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const alerts = getFallbackStore<Alert[]>(STORAGE_KEYS.ALERTS, INITIAL_ALERTS);
    const idx = alerts.findIndex((a) => a.id === alertId);
    if (idx !== -1) {
      alerts[idx] = {
        ...alerts[idx],
        ...payload,
        updated_at: new Date().toISOString(),
      };
      setFallbackStore(STORAGE_KEYS.ALERTS, alerts);
      return alerts[idx];
    }
    return INITIAL_ALERTS[0];
  }

  public async getRelatedAlerts(params: {
    attack_type?: AttackType;
    source_ip?: string;
    exclude_id?: string;
  }): Promise<Alert[]> {
    if (this.isOnline) {
      try {
        const q = new URLSearchParams();
        if (params.attack_type) q.append('attack_type', params.attack_type);
        if (params.source_ip) q.append('source_ip', params.source_ip);
        if (params.exclude_id) q.append('exclude_id', params.exclude_id);
        const res = await fetch(`${BASE_URL}/alerts/related?${q.toString()}`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const alerts = getFallbackStore<Alert[]>(STORAGE_KEYS.ALERTS, INITIAL_ALERTS);
    return alerts
      .filter((a) => {
        if (params.exclude_id && a.id === params.exclude_id) return false;
        if (params.source_ip && a.source_ip === params.source_ip) return true;
        if (params.attack_type && a.attack_type === params.attack_type) return true;
        return false;
      })
      .slice(0, 10);
  }

  // --- Threat History Timeline API ---
  public async getAlertHistory(alertId: string): Promise<ThreatHistory[]> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/alerts/${alertId}/history`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const histories = getFallbackStore<Record<string, ThreatHistory[]>>(
      STORAGE_KEYS.HISTORIES,
      INITIAL_HISTORIES
    );
    return histories[alertId] || [
      {
        id: 'h-auto',
        alert_id: alertId,
        event_type: 'detected',
        description: 'Anomaly and attack signature detected by AEGIS-X Threat Detection Agent.',
        actor_label: 'AI Detection Engine',
        created_at: new Date().toISOString(),
      },
    ];
  }

  public async addAlertHistory(
    alertId: string,
    payload: { event_type: string; description: string; event_metadata?: any }
  ): Promise<ThreatHistory> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/alerts/${alertId}/history`, {
          method: 'POST',
          headers: this.getAuthHeaders(),
          body: JSON.stringify(payload),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const histories = getFallbackStore<Record<string, ThreatHistory[]>>(
      STORAGE_KEYS.HISTORIES,
      INITIAL_HISTORIES
    );
    const newEntry: ThreatHistory = {
      id: 'h-' + Math.random().toString(36).substring(7),
      alert_id: alertId,
      event_type: payload.event_type as any,
      description: payload.description,
      actor_label: 'Alex Vance (Lead Analyst)',
      event_metadata: payload.event_metadata,
      created_at: new Date().toISOString(),
    };

    if (!histories[alertId]) histories[alertId] = [];
    histories[alertId].push(newEntry);
    setFallbackStore(STORAGE_KEYS.HISTORIES, histories);
    return newEntry;
  }

  // --- Reports API ---
  public async getAlertReports(alertId: string): Promise<Report[]> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/alerts/${alertId}/reports`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const reports = getFallbackStore<Record<string, Report[]>>(
      STORAGE_KEYS.REPORTS,
      INITIAL_REPORTS
    );
    return reports[alertId] || [];
  }

  public async createAlertReport(
    alertId: string,
    payload: { title: string; summary: string; root_cause?: string; mitigation?: string }
  ): Promise<Report> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/alerts/${alertId}/reports`, {
          method: 'POST',
          headers: this.getAuthHeaders(),
          body: JSON.stringify(payload),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const reports = getFallbackStore<Record<string, Report[]>>(
      STORAGE_KEYS.REPORTS,
      INITIAL_REPORTS
    );
    const newReport: Report = {
      id: 'rep-' + Math.random().toString(36).substring(7),
      alert_id: alertId,
      title: payload.title,
      summary: payload.summary,
      root_cause: payload.root_cause,
      mitigation: payload.mitigation,
      generated_by: 'AEGIS-X Response Agent v0.1.0',
      created_at: new Date().toISOString(),
    };

    if (!reports[alertId]) reports[alertId] = [];
    reports[alertId].push(newReport);
    setFallbackStore(STORAGE_KEYS.REPORTS, reports);
    return newReport;
  }

  // --- Audit Logs API ---
  public async listAuditLogs(params?: { page?: number; page_size?: number }): Promise<{
    items: AuditLog[];
    total: number;
    page: number;
    page_size: number;
  }> {
    if (this.isOnline) {
      try {
        const q = new URLSearchParams();
        if (params?.page) q.append('page', params.page.toString());
        if (params?.page_size) q.append('page_size', params.page_size.toString());
        const res = await fetch(`${BASE_URL}/audit-logs?${q.toString()}`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }

    const logs = getFallbackStore<AuditLog[]>(STORAGE_KEYS.AUDIT_LOGS, INITIAL_AUDIT_LOGS);
    return {
      items: logs,
      total: logs.length,
      page: params?.page || 1,
      page_size: params?.page_size || 50,
    };
  }

  // --- Settings API ---
  public async getMySettings(): Promise<Setting[]> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/settings/me`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }
    return [
      { id: 's1', scope: 'user', key: 'theme', value: 'cyber_dark', created_at: '', updated_at: '' },
      { id: 's2', scope: 'user', key: 'audio_alerts', value: true, created_at: '', updated_at: '' },
      { id: 's3', scope: 'user', key: 'auto_refresh_sec', value: 10, created_at: '', updated_at: '' },
    ];
  }

  public async getSystemSettings(): Promise<Setting[]> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/settings/system`, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {}
    }
    return [
      { id: 'sys1', scope: 'system', key: 'anomaly_threshold', value: 0.65, created_at: '', updated_at: '' },
      { id: 'sys2', scope: 'system', key: 'xgboost_confidence_cutoff', value: 0.70, created_at: '', updated_at: '' },
      { id: 'sys3', scope: 'system', key: 'qdrant_similarity_cutoff', value: 0.75, created_at: '', updated_at: '' },
      { id: 'sys4', scope: 'system', key: 'auto_mitigation_enabled', value: true, created_at: '', updated_at: '' },
    ];
  }

  // --- Human-in-the-Loop Incident Response Actions API ---
  public async listActions(params?: { alert_id?: string; status?: ActionStatus }): Promise<ResponseAction[]> {
    if (this.isOnline) {
      try {
        const q = new URLSearchParams();
        if (params?.alert_id) q.append('alert_id', params.alert_id);
        const endpoint = params?.status === 'pending_approval' ? `${BASE_URL}/actions/pending` : `${BASE_URL}/actions?${q.toString()}`;
        const res = await fetch(endpoint, {
          headers: this.getAuthHeaders(),
        });
        if (res.ok) return await res.json();
      } catch (e) {
        console.warn('Backend list actions failed, fallback to local', e);
      }
    }

    let actions = getFallbackStore<ResponseAction[]>(STORAGE_KEYS.ACTIONS, INITIAL_ACTIONS);
    if (params?.alert_id) actions = actions.filter((a) => a.alert_id === params.alert_id);
    if (params?.status) actions = actions.filter((a) => a.status === params.status);
    return actions;
  }

  public async decideAction(actionId: string, decision: 'approved' | 'rejected', notes?: string): Promise<ResponseAction> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/actions/${actionId}/decision`, {
          method: 'POST',
          headers: this.getAuthHeaders(),
          body: JSON.stringify({ decision, notes }),
        });
        if (res.ok) return await res.json();
        const err = await res.json();
        throw new Error(err.detail || 'Action decision failed');
      } catch (e: any) {
        if (e.message && e.message.includes('Insufficient permissions')) {
          throw e;
        }
        console.warn('Backend decide action failed, fallback to local', e);
      }
    }

    const actions = getFallbackStore<ResponseAction[]>(STORAGE_KEYS.ACTIONS, INITIAL_ACTIONS);
    const idx = actions.findIndex((a) => a.id === actionId);
    if (idx === -1) throw new Error('Action not found');

    const currentUser = this.getCurrentUser();
    const action = actions[idx];

    if ((action.required_role === 'admin' || action.blast_radius === 'HIGH') && currentUser?.role !== 'admin') {
      throw new Error("Insufficient permissions: HIGH blast radius or administrative actions require 'admin' role.");
    }

    const now = new Date().toISOString();
    const updated: ResponseAction = {
      ...action,
      status: decision === 'approved' ? 'executed' : 'rejected',
      approved_by_id: currentUser?.id || 'u1',
      approved_at: decision === 'approved' ? now : null,
      executed_at: decision === 'approved' ? now : null,
      execution_log: decision === 'approved' ? {
        executor: 'aegis_containment_daemon',
        notes: notes || 'Analyst approved containment',
        result: 'success',
      } : null,
      updated_at: now,
    };

    actions[idx] = updated;
    setFallbackStore(STORAGE_KEYS.ACTIONS, actions);
    return updated;
  }

  public async createAction(payload: {
    alert_id: string;
    action_type: ActionType;
    target: string;
    required_role?: 'analyst' | 'admin';
    blast_radius?: 'LOW' | 'MEDIUM' | 'HIGH';
    description: string;
    rationale?: string;
    rollback_plan?: string;
  }): Promise<ResponseAction> {
    if (this.isOnline) {
      try {
        const res = await fetch(`${BASE_URL}/actions`, {
          method: 'POST',
          headers: this.getAuthHeaders(),
          body: JSON.stringify(payload),
        });
        if (res.ok) return await res.json();
      } catch (e) {
        console.warn('Backend create action failed, fallback to local', e);
      }
    }

    const actions = getFallbackStore<ResponseAction[]>(STORAGE_KEYS.ACTIONS, INITIAL_ACTIONS);
    const now = new Date().toISOString();
    const newAct: ResponseAction = {
      id: 'act-' + Math.random().toString(36).substring(2, 9),
      alert_id: payload.alert_id,
      action_type: payload.action_type,
      target: payload.target,
      status: 'pending_approval',
      required_role: payload.required_role || 'analyst',
      blast_radius: payload.blast_radius || 'LOW',
      description: payload.description,
      rationale: payload.rationale || null,
      rollback_plan: payload.rollback_plan || null,
      created_by: 'ai_response_agent',
      approved_by_id: null,
      approved_at: null,
      executed_at: null,
      execution_log: null,
      created_at: now,
      updated_at: now,
    };
    actions.unshift(newAct);
    setFallbackStore(STORAGE_KEYS.ACTIONS, actions);
    return newAct;
  }
}

export const api = new ApiService();
