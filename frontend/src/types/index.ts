export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false_positive';
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type AttackType = 
  | 'normal'
  | 'brute_force'
  | 'ddos'
  | 'botnet'
  | 'port_scan'
  | 'sql_injection'
  | 'web_attack'
  | 'other';

export type AlertSource = 
  | 'network_flow'
  | 'auth_log'
  | 'firewall'
  | 'ids_ips'
  | 'endpoint'
  | 'cloud_audit'
  | 'user_behaviour'
  | 'threat_intel';

export interface Alert {
  id: string;
  title: string;
  description?: string | null;
  source: AlertSource;
  attack_type: AttackType;
  status: AlertStatus;
  severity: AlertSeverity;
  anomaly_score?: number | null;
  risk_score?: number | null;
  confidence?: number | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol?: string | null;
  mitre_technique_id?: string | null;
  mitre_technique_name?: string | null;
  assigned_to_id?: string | null;
  assigned_to_name?: string | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
  raw_event?: Record<string, any> | null;
  shap_values?: Array<{ feature: string; impact: number; value: any }>;
  is_anomaly?: boolean;
}

export interface AlertCreate {
  title: string;
  description?: string;
  source: AlertSource;
  attack_type: AttackType;
  severity: AlertSeverity;
  anomaly_score?: number;
  risk_score?: number;
  confidence?: number;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  raw_event?: Record<string, any>;
}

export interface AlertUpdate {
  status?: AlertStatus;
  severity?: AlertSeverity;
  assigned_to_id?: string | null;
}

export type ThreatHistoryEventType = 
  | 'detected' 
  | 'status_change' 
  | 'note' 
  | 'assignment' 
  | 'correlation' 
  | 'report_generated';

export interface ThreatHistory {
  id: string;
  alert_id: string;
  event_type: ThreatHistoryEventType;
  description: string;
  actor_id?: string | null;
  actor_label?: string | null;
  event_metadata?: Record<string, any> | null;
  created_at: string;
}

export interface Report {
  id: string;
  alert_id: string;
  title: string;
  summary: string;
  root_cause?: string | null;
  mitigation?: string | null;
  file_path?: string | null;
  generated_by: string;
  created_by_id?: string | null;
  created_at: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'analyst' | 'admin' | 'viewer';
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface AuditLog {
  id: string;
  actor_id?: string | null;
  actor_email?: string | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip_address?: string | null;
  details?: Record<string, any> | null;
  created_at: string;
}

export interface Setting {
  id: string;
  scope: 'user' | 'system';
  key: string;
  value: any;
  user_id?: string | null;
  created_at: string;
  updated_at: string;
}

// Multi-Agent Pipeline Trace Types
export interface AgentTraceStep {
  agent_name: 'ThreatDetectionAgent' | 'InvestigationAgent' | 'KnowledgeAgent' | 'ResponseAgent';
  title: string;
  status: 'pending' | 'running' | 'completed' | 'skipped';
  timestamp?: string;
  duration_ms?: number;
  input_summary?: string;
  output_summary?: string;
  details?: Record<string, any>;
  reasoning?: string;
}

export interface MultiAgentInvestigationResult {
  alert: Alert;
  steps: AgentTraceStep[];
  threat_detection: {
    is_anomaly: boolean;
    anomaly_score: number;
    attack_type: AttackType;
    confidence: number;
    risk_score: number;
    severity: AlertSeverity;
    mitre_technique_id: string;
    mitre_technique_name: string;
  };
  investigation: {
    correlated_events_count: number;
    repeat_offender: boolean;
    blast_radius: string;
    investigation_decision: string;
  };
  knowledge_rag: {
    retrieved_mitre: Array<{ id: string; name: string; tactic: string; description: string; score: number }>;
    retrieved_cves: Array<{ id: string; cvss: number; summary: string; score: number }>;
    retrieved_policies: Array<{ title: string; policy_id: string; requirements: string; score: number }>;
  };
  response: {
    recommended_actions: string[];
    firewall_rule: string;
    containment_status: string;
    executive_summary: string;
  };
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  mitigation: string;
  detection_hints: string[];
  severity_typical: AlertSeverity;
}

export interface CveRecord {
  id: string;
  title: string;
  cvss: number;
  severity: AlertSeverity;
  affected_software: string;
  summary: string;
  published_date: string;
  patch_status: string;
  related_attack_type?: string;
}

export interface SecurityPolicy {
  policy_id: string;
  title: string;
  category: string;
  sla_minutes: number;
  mandate: string;
  escalation_path: string;
}

// Human-in-the-Loop Incident Response Action Types
export type ActionType =
  | 'block_ip'
  | 'isolate_host'
  | 'disable_user'
  | 'revoke_credentials'
  | 'kill_process'
  | 'sinkhole_domain'
  | 'quarantine_file';

export type ActionStatus =
  | 'pending_approval'
  | 'approved'
  | 'rejected'
  | 'executed'
  | 'failed'
  | 'cancelled';

export interface ResponseAction {
  id: string;
  alert_id: string;
  action_type: ActionType;
  target: string;
  status: ActionStatus;
  required_role: 'analyst' | 'admin';
  blast_radius: 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
  rationale?: string | null;
  rollback_plan?: string | null;
  created_by: string;
  approved_by_id?: string | null;
  approved_at?: string | null;
  executed_at?: string | null;
  execution_log?: Record<string, any> | null;
  created_at: string;
  updated_at: string;
}

