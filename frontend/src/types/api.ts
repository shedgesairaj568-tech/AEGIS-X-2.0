// Mirrors backend/app/schemas/*.py and backend/app/core/enums.py exactly.
// Keeping these in sync by hand (rather than codegen) since the backend
// is small and stable enough that drift would be caught immediately by
// TypeScript errors at the API call sites.

export type AlertStatus = "open" | "investigating" | "resolved" | "false_positive";
export type AlertSeverity = "low" | "medium" | "high" | "critical";
export type AttackType =
  | "normal"
  | "brute_force"
  | "ddos"
  | "botnet"
  | "port_scan"
  | "sql_injection"
  | "web_attack"
  | "other";
export type AlertSource =
  | "network_flow"
  | "auth_log"
  | "firewall"
  | "ids_ips"
  | "endpoint"
  | "cloud_audit"
  | "user_behaviour"
  | "threat_intel";
export type ThreatHistoryEventType =
  | "detected"
  | "status_change"
  | "note"
  | "assignment"
  | "correlation"
  | "report_generated";

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface Alert {
  id: string;
  title: string;
  description: string | null;
  source: AlertSource;
  attack_type: AttackType;
  status: AlertStatus;
  severity: AlertSeverity;
  anomaly_score: number | null;
  risk_score: number | null;
  confidence: number | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
  assigned_to_id: string | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
}

export interface AlertListResponse {
  items: Alert[];
  total: number;
  page: number;
  page_size: number;
}

export interface AlertUpdate {
  status?: AlertStatus;
  severity?: AlertSeverity;
  assigned_to_id?: string;
}

export interface ThreatHistoryEntry {
  id: string;
  alert_id: string;
  event_type: ThreatHistoryEventType;
  description: string;
  actor_id: string | null;
  actor_label: string | null;
  event_metadata: Record<string, unknown> | null;
  created_at: string;
}

export interface Report {
  id: string;
  alert_id: string;
  title: string;
  summary: string;
  root_cause: string | null;
  mitigation: string | null;
  file_path: string | null;
  generated_by: string;
  created_by_id: string | null;
  created_at: string;
}

export interface ApiError {
  error_code: string;
  message: string;
}

export interface AlertFilters {
  status?: AlertStatus;
  severity?: AlertSeverity;
  attack_type?: AttackType;
  source?: AlertSource;
  page?: number;
  page_size?: number;
}

export type ActionType =
  | "block_ip"
  | "isolate_host"
  | "disable_user"
  | "revoke_credentials"
  | "kill_process"
  | "sinkhole_domain"
  | "quarantine_file";

export type ActionStatus =
  | "pending_approval"
  | "approved"
  | "rejected"
  | "executed"
  | "failed"
  | "cancelled";

export interface ResponseAction {
  id: string;
  alert_id: string;
  action_type: ActionType;
  target: string;
  status: ActionStatus;
  required_role: "analyst" | "admin";
  blast_radius: "LOW" | "MEDIUM" | "HIGH";
  description: string;
  rationale: string | null;
  rollback_plan: string | null;
  created_by: string;
  approved_by_id: string | null;
  approved_at: string | null;
  executed_at: string | null;
  execution_log: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

