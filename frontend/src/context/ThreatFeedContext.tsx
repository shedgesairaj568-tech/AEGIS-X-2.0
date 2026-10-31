import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { Alert, AlertSeverity, AttackType } from '../types';
import { api } from '../services/api';
import { soundFX } from '../services/soundEffects';

export interface LivePacket {
  id: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  port: number;
  protocol: string;
  bytes: number;
  is_anomalous: boolean;
  attack_label?: string;
}

interface ThreatFeedContextType {
  alerts: Alert[];
  isLoadingAlerts: boolean;
  isStreaming: boolean;
  setIsStreaming: (streaming: boolean) => void;
  streamSpeed: number;
  setStreamSpeed: (speed: number) => void;
  isAudioMuted: boolean;
  toggleAudioMute: () => void;
  defconLevel: number; // 1 (Critical Emergency) to 5 (Nominal)
  livePackets: LivePacket[];
  fetchAlerts: () => Promise<void>;
  injectAlert: (alert: Partial<Alert>) => Promise<Alert>;
  triggerSimulationEvent: (type?: AttackType) => Promise<Alert>;
  stats: {
    total: number;
    open: number;
    investigating: number;
    resolved: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    avgAnomalyScore: number;
    avgConfidence: number;
  };
}

const ThreatFeedContext = createContext<ThreatFeedContextType | undefined>(undefined);

const RANDOM_IPS = [
  '185.220.101.5',
  '91.240.118.172',
  '45.154.255.89',
  '194.26.29.112',
  '103.145.13.2',
  '195.181.164.21',
  '89.248.165.74',
  '178.128.241.9',
  '10.0.1.45',
  '10.0.2.88',
  '192.168.1.10',
];

export const ThreatFeedProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoadingAlerts, setIsLoadingAlerts] = useState<boolean>(true);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [streamSpeed, setStreamSpeed] = useState<number>(1);
  const [isAudioMuted, setIsAudioMuted] = useState<boolean>(false);
  const [livePackets, setLivePackets] = useState<LivePacket[]>([]);

  const toggleAudioMute = () => {
    const next = !isAudioMuted;
    setIsAudioMuted(next);
    soundFX.setMuted(next);
    if (!next) soundFX.playClick();
  };

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await api.listAlerts({ page_size: 100 });
      setAlerts(res.items);
    } catch (e) {
      console.error('Failed to fetch alerts', e);
    } finally {
      setIsLoadingAlerts(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  // Compute DEFCON and Stats
  const criticalCount = alerts.filter((a) => a.severity === 'critical' && a.status !== 'resolved').length;
  const highCount = alerts.filter((a) => a.severity === 'high' && a.status !== 'resolved').length;
  
  let defconLevel = 5;
  if (criticalCount >= 2) defconLevel = 1;
  else if (criticalCount === 1) defconLevel = 2;
  else if (highCount >= 2) defconLevel = 3;
  else if (highCount === 1) defconLevel = 4;

  const stats = {
    total: alerts.length,
    open: alerts.filter((a) => a.status === 'open').length,
    investigating: alerts.filter((a) => a.status === 'investigating').length,
    resolved: alerts.filter((a) => a.status === 'resolved').length,
    critical: alerts.filter((a) => a.severity === 'critical').length,
    high: alerts.filter((a) => a.severity === 'high').length,
    medium: alerts.filter((a) => a.severity === 'medium').length,
    low: alerts.filter((a) => a.severity === 'low').length,
    avgAnomalyScore:
      alerts.length > 0
        ? Number(
            (
              alerts.reduce((acc, curr) => acc + (curr.anomaly_score || 0), 0) / alerts.length
            ).toFixed(2)
          )
        : 0.82,
    avgConfidence:
      alerts.length > 0
        ? Number(
            (
              alerts.reduce((acc, curr) => acc + (curr.confidence || 0), 0) / alerts.length
            ).toFixed(2)
          )
        : 0.94,
  };

  // Live Packet Telemetry Streamer
  useEffect(() => {
    if (!isStreaming) return;
    const intervalTime = Math.max(400, 1200 / streamSpeed);

    const timer = setInterval(() => {
      const isAnomaly = Math.random() > 0.75;
      const src = RANDOM_IPS[Math.floor(Math.random() * RANDOM_IPS.length)];
      const dst = '10.0.4.' + (Math.floor(Math.random() * 20) + 1);
      const protocols = ['TCP', 'UDP', 'HTTPS', 'SSH', 'DNS', 'HTTP'];
      const proto = protocols[Math.floor(Math.random() * protocols.length)];
      const ports = [80, 443, 22, 53, 8080, 3306, 4242, 8443];

      const newPkt: LivePacket = {
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toLocaleTimeString(),
        source_ip: src,
        dest_ip: dst,
        port: ports[Math.floor(Math.random() * ports.length)],
        protocol: proto,
        bytes: Math.floor(Math.random() * 4500) + 64,
        is_anomalous: isAnomaly,
        attack_label: isAnomaly
          ? ['DDoS SYN Probe', 'Port Scan Ingress', 'SQLi Pattern', 'Auth Burst'][
              Math.floor(Math.random() * 4)
            ]
          : undefined,
      };

      setLivePackets((prev) => [newPkt, ...prev.slice(0, 40)]);
    }, intervalTime);

    return () => clearInterval(timer);
  }, [isStreaming, streamSpeed]);

  const injectAlert = async (partialAlert: Partial<Alert>): Promise<Alert> => {
    const attackType = partialAlert.attack_type || 'ddos';
    const severity: AlertSeverity = partialAlert.severity || (attackType === 'normal' ? 'low' : 'high');

    const created = await api.createAlert({
      title: partialAlert.title || `Live Anomaly Detected: ${attackType.toUpperCase()}`,
      description: partialAlert.description || 'Automated multi-agent detection trigger from telemetry ingestion pipeline.',
      source: partialAlert.source || 'network_flow',
      attack_type: attackType,
      severity: severity,
      anomaly_score: partialAlert.anomaly_score ?? 0.88,
      risk_score: partialAlert.risk_score ?? 85,
      confidence: partialAlert.confidence ?? 0.94,
      source_ip: partialAlert.source_ip || RANDOM_IPS[Math.floor(Math.random() * RANDOM_IPS.length)],
      destination_ip: partialAlert.destination_ip || '10.0.4.15',
      source_port: partialAlert.source_port || 44210,
      destination_port: partialAlert.destination_port || 80,
      protocol: partialAlert.protocol || 'TCP',
      mitre_technique_id: partialAlert.mitre_technique_id || 'T1498',
      mitre_technique_name: partialAlert.mitre_technique_name || 'Network Denial of Service',
      raw_event: partialAlert.raw_event || undefined,
    });

    setAlerts((prev) => [created, ...prev]);
    if (severity === 'critical' || severity === 'high') {
      soundFX.playThreatAlarm();
    } else {
      soundFX.playClick();
    }
    return created;
  };

  const triggerSimulationEvent = async (type?: AttackType): Promise<Alert> => {
    const attackTypes: AttackType[] = ['ddos', 'brute_force', 'port_scan', 'sql_injection', 'botnet', 'web_attack'];
    const chosenType = type || attackTypes[Math.floor(Math.random() * attackTypes.length)];

    const metaMap: Record<AttackType, { title: string; mitreId: string; mitreName: string; severity: AlertSeverity }> = {
      ddos: { title: 'Volumetric SYN Flood Traffic Spike', mitreId: 'T1498', mitreName: 'Network Denial of Service', severity: 'critical' },
      brute_force: { title: 'High-Frequency SSH Credential Stuffing', mitreId: 'T1110', mitreName: 'Brute Force', severity: 'high' },
      port_scan: { title: 'Rapid Horizontal Subnet Port Scan', mitreId: 'T1046', mitreName: 'Network Service Discovery', severity: 'medium' },
      sql_injection: { title: 'SQL Injection Payload in HTTP GET Parameter', mitreId: 'T1190', mitreName: 'Exploit Public-Facing Application', severity: 'critical' },
      botnet: { title: 'Suspicious Periodic Outbound C2 Beaconing', mitreId: 'T1584', mitreName: 'Compromise Infrastructure', severity: 'high' },
      web_attack: { title: 'Apache Log4Shell JNDI Exploit String Attempt', mitreId: 'T1190', mitreName: 'Exploit Public-Facing Application', severity: 'critical' },
      other: { title: 'Unclassified Network Outlier Traffic', mitreId: 'T1499', mitreName: 'Endpoint Denial of Service', severity: 'medium' },
      normal: { title: 'Nominal Baseline Telemetry', mitreId: '', mitreName: '', severity: 'low' },
    };

    const info = metaMap[chosenType] || metaMap.ddos;
    return await injectAlert({
      title: info.title,
      attack_type: chosenType,
      severity: info.severity,
      anomaly_score: Number((0.8 + Math.random() * 0.18).toFixed(2)),
      risk_score: Number((75 + Math.random() * 23).toFixed(1)),
      confidence: Number((0.9 + Math.random() * 0.08).toFixed(2)),
      mitre_technique_id: info.mitreId,
      mitre_technique_name: info.mitreName,
    });
  };

  return (
    <ThreatFeedContext.Provider
      value={{
        alerts,
        isLoadingAlerts,
        isStreaming,
        setIsStreaming,
        streamSpeed,
        setStreamSpeed,
        isAudioMuted,
        toggleAudioMute,
        defconLevel,
        livePackets,
        fetchAlerts,
        injectAlert,
        triggerSimulationEvent,
        stats,
      }}
    >
      {children}
    </ThreatFeedContext.Provider>
  );
};

export const useThreatFeed = (): ThreatFeedContextType => {
  const ctx = useContext(ThreatFeedContext);
  if (!ctx) throw new Error('useThreatFeed must be used within a ThreatFeedProvider');
  return ctx;
};
