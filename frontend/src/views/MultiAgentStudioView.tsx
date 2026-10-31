import React, { useState } from 'react';
import { 
  Cpu, 
  Search, 
  BookOpen, 
  FileText, 
  Play, 
  CheckCircle2, 
  RefreshCw, 
  Sliders, 
  ShieldCheck, 
  Flame 
} from 'lucide-react';
import { AI_SIMULATOR_PRESETS } from '../services/mockData';
import { soundFX } from '../services/soundEffects';
import { useThreatFeed } from '../context/ThreatFeedContext';
import type { MultiAgentInvestigationResult, AgentTraceStep, AttackType, AlertSeverity } from '../types';

export const MultiAgentStudioView: React.FC = () => {
  const { injectAlert } = useThreatFeed();
  const [selectedPresetId, setSelectedPresetId] = useState<string>('ddos_syn');
  const [features, setFeatures] = useState(AI_SIMULATOR_PRESETS[0].features);
  
  // Execution state
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(-1);
  const [result, setResult] = useState<MultiAgentInvestigationResult | null>(null);

  const selectedPreset = AI_SIMULATOR_PRESETS.find((p) => p.id === selectedPresetId) || AI_SIMULATOR_PRESETS[0];

  const handleSelectPreset = (preset: typeof AI_SIMULATOR_PRESETS[0]) => {
    setSelectedPresetId(preset.id);
    setFeatures({ ...preset.features });
    setResult(null);
    setActiveStepIndex(-1);
    soundFX.playClick();
  };

  const handleFeatureChange = (key: keyof typeof features, val: number) => {
    setFeatures((prev) => ({ ...prev, [key]: val }));
  };

  const handleRunPipeline = async () => {
    setIsRunning(true);
    setResult(null);
    setActiveStepIndex(0);
    soundFX.playScan();

    const steps: AgentTraceStep[] = [];

    // Step 1: Threat Detection Agent
    await new Promise((r) => setTimeout(r, 600));
    setActiveStepIndex(0);
    const isAnomalous = features.flow_packets_per_s > 1000 || features.syn_flag_count > 500 || features.flow_duration < 5000;
    const anomalyScore = isAnomalous ? selectedPreset.expectedOutput.anomaly_score : 0.12;
    const predictedAttack: AttackType = isAnomalous ? selectedPreset.expectedOutput.attack_type : 'normal';
    const confidence = isAnomalous ? selectedPreset.expectedOutput.confidence : 0.98;
    const riskScore = isAnomalous ? selectedPreset.expectedOutput.risk_score : 12.0;
    const severity: AlertSeverity = isAnomalous ? selectedPreset.expectedOutput.severity : 'low';
    const mitreId = selectedPreset.expectedOutput.mitre_id;
    const mitreName = selectedPreset.expectedOutput.mitre_name;

    steps.push({
      agent_name: 'ThreatDetectionAgent',
      title: 'Statistical Flow Anomaly & Classification',
      status: 'completed',
      timestamp: new Date().toLocaleTimeString(),
      output_summary: `Analyzed 8 CIC-IDS2017 flow metrics. Isolation Forest anomaly score: ${anomalyScore.toFixed(2)}. XGBoost: ${predictedAttack.toUpperCase()} (${(confidence * 100).toFixed(1)}% confidence).`,
      details: {
        anomaly_score: anomalyScore,
        predicted_class: predictedAttack,
        confidence: confidence,
      },
    });

    // Step 2: Investigation Agent
    await new Promise((r) => setTimeout(r, 700));
    setActiveStepIndex(1);
    soundFX.playClick();

    steps.push({
      agent_name: 'InvestigationAgent',
      title: 'Historical Blast Radius & Correlation',
      status: 'completed',
      timestamp: new Date().toLocaleTimeString(),
      output_summary: `Correlated telemetry against 1,240 historical records. Calculated composite risk index: ${riskScore.toFixed(1)}/100. Target host isolation recommended.`,
      details: {
        risk_score: riskScore,
        mitre_id: mitreId,
        mitre_name: mitreName,
      },
    });

    // Step 3: Knowledge Agent (RAG)
    await new Promise((r) => setTimeout(r, 700));
    setActiveStepIndex(2);
    soundFX.playClick();

    steps.push({
      agent_name: 'KnowledgeAgent',
      title: 'Dense Vector Knowledge Retrieval',
      status: 'completed',
      timestamp: new Date().toLocaleTimeString(),
      output_summary: `Embedded query into Qdrant vector store. Retrieved MITRE ATT&CK technique ${mitreId} (${mitreName}) & Corporate SLA Runbook POL-002 with 0.94 cosine similarity.`,
      details: {
        rag_hits: 3,
        matched_policy: 'POL-002: Perimeter Denial & Scrubbing SLA',
      },
    });

    // Step 4: Response Agent
    await new Promise((r) => setTimeout(r, 600));
    setActiveStepIndex(3);
    soundFX.playSuccess();

    const firewallRule = isAnomalous
      ? `iptables -A INPUT -s 185.220.101.5 -p tcp -j DROP`
      : 'ALLOW DEFAULT';

    const execSummary = isAnomalous
      ? `Autonomous multi-agent defense intercepted ${predictedAttack.toUpperCase()} activity. RAG policy POL-002 applied with automated perimeter firewall rule.`
      : 'Traffic characteristics evaluated within baseline tolerance.';

    steps.push({
      agent_name: 'ResponseAgent',
      title: 'Playbook Synthesis & Containment',
      status: 'completed',
      timestamp: new Date().toLocaleTimeString(),
      output_summary: `Generated containment actions. Action: ${isAnomalous ? 'Perimeter Drop Rule Applied' : 'Logged Normal Event'}.`,
      details: {
        action_taken: isAnomalous ? 'CONTAINMENT_DEPLOYED' : 'NORMAL_LOGGED',
        firewall_rule: firewallRule,
      },
    });

    const mockAlert = {
      id: 'sim-' + Date.now(),
      title: `AI Studio Simulation: ${predictedAttack.toUpperCase()} Intercepted`,
      description: execSummary,
      source: 'network_flow' as const,
      attack_type: predictedAttack,
      severity: severity,
      status: 'open' as const,
      anomaly_score: anomalyScore,
      risk_score: riskScore,
      confidence: confidence,
      source_ip: '185.220.101.5',
      destination_ip: '198.51.100.24',
      source_port: 44210,
      destination_port: 80,
      protocol: 'TCP',
      mitre_technique_id: mitreId,
      mitre_technique_name: mitreName,
      detected_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      is_anomaly: isAnomalous,
    };

    const finalResult: MultiAgentInvestigationResult = {
      alert: mockAlert,
      steps: steps,
      threat_detection: {
        is_anomaly: isAnomalous,
        anomaly_score: anomalyScore,
        attack_type: predictedAttack,
        confidence: confidence,
        risk_score: riskScore,
        severity: severity,
        mitre_technique_id: mitreId,
        mitre_technique_name: mitreName,
      },
      investigation: {
        correlated_events_count: 4,
        repeat_offender: true,
        blast_radius: 'Edge Web Service Cluster',
        investigation_decision: 'CONFIRMED_ANOMALY',
      },
      knowledge_rag: {
        retrieved_mitre: [{ id: mitreId, name: mitreName, tactic: 'Impact', description: 'Network volumetric disruption.', score: 0.94 }],
        retrieved_cves: [{ id: 'CVE-2023-44487', cvss: 7.5, summary: 'HTTP/2 Rapid Reset DDoS', score: 0.88 }],
        retrieved_policies: [{ title: 'DDoS Containment SLA', policy_id: 'POL-002', requirements: 'Drop source IP within 5 mins', score: 0.92 }],
      },
      response: {
        recommended_actions: ['Drop source IP on edge firewall', 'Alert on-call SecOps engineer', 'Enable BGP Flowspec'],
        firewall_rule: firewallRule,
        containment_status: isAnomalous ? 'DEPLOYED' : 'NOT_REQUIRED',
        executive_summary: execSummary,
      },
    };

    setResult(finalResult);
    setIsRunning(false);

    if (isAnomalous) {
      injectAlert(mockAlert);
    }
  };

  const agentNodes = [
    {
      name: '1. Threat Detection Agent',
      role: 'Isolation Forest & XGBoost Classifier',
      icon: Cpu,
      color: 'text-indigo-600 bg-indigo-50 border-indigo-200',
    },
    {
      name: '2. Investigation Agent',
      role: 'Correlation & Blast Radius Engine',
      icon: Search,
      color: 'text-blue-600 bg-blue-50 border-blue-200',
    },
    {
      name: '3. Knowledge Agent',
      role: 'Qdrant Vector Store & MITRE RAG',
      icon: BookOpen,
      color: 'text-purple-600 bg-purple-50 border-purple-200',
    },
    {
      name: '4. Response Agent',
      role: 'Containment Playbook Synthesizer',
      icon: FileText,
      color: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600 mb-1">
            <Cpu className="w-4 h-4" />
            <span>LANGGRAPH ORCHESTRATION</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Multi-Agent AI Defense Studio
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Interactive multi-agent pipeline: Real-time ML detection, RAG retrieval, and automated SOC incident mitigation.
          </p>
        </div>

        <button
          onClick={handleRunPipeline}
          disabled={isRunning}
          className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-all shadow-xs active:scale-95 disabled:opacity-50"
        >
          {isRunning ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Executing Pipeline...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              <span>Execute AI Pipeline</span>
            </>
          )}
        </button>
      </div>

      {/* 4-Agent Pipeline Workflow Diagram */}
      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-3">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
          Multi-Agent Execution Pipeline
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {agentNodes.map((node, index) => {
            const Icon = node.icon;
            const isCurrent = activeStepIndex === index;
            const isDone = activeStepIndex > index || (result && !isRunning);

            return (
              <div
                key={node.name}
                className={`p-4 rounded-xl border transition-all ${
                  isCurrent
                    ? 'border-indigo-600 bg-indigo-50/50 shadow-sm ring-1 ring-indigo-500'
                    : isDone
                    ? 'border-emerald-200 bg-emerald-50/30'
                    : 'border-slate-200 bg-slate-50/60'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className={`p-2 rounded-xl border ${node.color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  {isDone ? (
                    <span className="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-bold">
                      Completed
                    </span>
                  ) : isCurrent ? (
                    <span className="px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-800 text-[10px] font-bold animate-pulse">
                      Running...
                    </span>
                  ) : (
                    <span className="text-[10px] text-slate-400 font-medium">Ready</span>
                  )}
                </div>
                <div className="font-bold text-slate-900 text-xs">{node.name}</div>
                <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">{node.role}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Simulator Workspace: Sliders on Left, Results on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Attack Presets & Traffic Sliders (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Attack Presets */}
          <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-3">
            <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
              <Flame className="w-4 h-4 text-indigo-600" />
              <span>Select Attack Preset</span>
            </h3>

            <div className="grid grid-cols-2 gap-2 text-xs">
              {AI_SIMULATOR_PRESETS.map((preset) => {
                const isSelected = preset.id === selectedPresetId;
                return (
                  <button
                    key={preset.id}
                    onClick={() => handleSelectPreset(preset)}
                    className={`p-3 rounded-xl border text-left transition-all ${
                      isSelected
                        ? 'bg-indigo-50 border-indigo-300 text-indigo-900 font-semibold'
                        : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    <div className="font-bold text-xs truncate">{preset.name}</div>
                    <div className="text-[10px] text-slate-400 mt-0.5 uppercase">
                      {preset.expectedOutput.attack_type.replace('_', ' ')}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Traffic Parameters Sliders */}
          <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-indigo-600" />
                <span>Flow Telemetry Sliders</span>
              </h3>
              <span className="text-[11px] text-slate-400">CIC-IDS2017</span>
            </div>

            <div className="space-y-3 text-xs">
              {/* Flow Packets / s */}
              <div className="space-y-1">
                <div className="flex justify-between">
                  <span className="text-slate-600 font-medium">Flow Packets/s</span>
                  <span className="font-mono font-bold text-indigo-600">{features.flow_packets_per_s.toLocaleString()} pkts/s</span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="10000"
                  step="50"
                  value={features.flow_packets_per_s}
                  onChange={(e) => handleFeatureChange('flow_packets_per_s', Number(e.target.value))}
                  aria-label="Flow Packets per second"
                  className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                />
              </div>

              {/* SYN Flags */}
              <div className="space-y-1">
                <div className="flex justify-between">
                  <span className="text-slate-600 font-medium">SYN Flag Count</span>
                  <span className="font-mono font-bold text-indigo-600">{features.syn_flag_count.toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="10000"
                  step="50"
                  value={features.syn_flag_count}
                  onChange={(e) => handleFeatureChange('syn_flag_count', Number(e.target.value))}
                  aria-label="SYN Flag Count"
                  className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                />
              </div>

              {/* Flow Duration */}
              <div className="space-y-1">
                <div className="flex justify-between">
                  <span className="text-slate-600 font-medium">Flow Duration</span>
                  <span className="font-mono font-bold text-indigo-600">{features.flow_duration.toLocaleString()} µs</span>
                </div>
                <input
                  type="range"
                  min="100"
                  max="2000000"
                  step="5000"
                  value={features.flow_duration}
                  onChange={(e) => handleFeatureChange('flow_duration', Number(e.target.value))}
                  aria-label="Flow Duration"
                  className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                />
              </div>

              {/* Total Fwd Packets */}
              <div className="space-y-1">
                <div className="flex justify-between">
                  <span className="text-slate-600 font-medium">Total Forward Packets</span>
                  <span className="font-mono font-bold text-indigo-600">{features.total_fwd_packets.toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="10000"
                  step="50"
                  value={features.total_fwd_packets}
                  onChange={(e) => handleFeatureChange('total_fwd_packets', Number(e.target.value))}
                  aria-label="Total Forward Packets"
                  className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Right: Live Agent Trace & Final Decision (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {result ? (
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-5">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-600">
                    Execution Complete
                  </span>
                  <h3 className="text-lg font-bold text-slate-900">
                    {result.threat_detection.attack_type.toUpperCase()} Attack Intercepted
                  </h3>
                </div>

                <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${
                  result.threat_detection.severity === 'critical'
                    ? 'badge-critical'
                    : result.threat_detection.severity === 'high'
                    ? 'badge-high'
                    : 'badge-low'
                }`}>
                  {result.threat_detection.severity}
                </span>
              </div>

              {/* Decision KPI Cards */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-[11px] text-slate-500">Risk Score</div>
                  <div className="text-lg font-bold text-rose-600 font-mono">
                    {result.threat_detection.risk_score.toFixed(0)}/100
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-[11px] text-slate-500">Anomaly Index</div>
                  <div className="text-lg font-bold text-indigo-600 font-mono">
                    {result.threat_detection.anomaly_score.toFixed(2)}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-[11px] text-slate-500">Confidence</div>
                  <div className="text-lg font-bold text-purple-600 font-mono">
                    {(result.threat_detection.confidence * 100).toFixed(1)}%
                  </div>
                </div>
              </div>

              {/* Step-by-Step Agent Trace */}
              <div className="space-y-2.5">
                <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Agent Execution Log
                </h4>
                {result.steps.map((step: AgentTraceStep, idx: number) => (
                  <div key={idx} className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-1">
                    <div className="flex items-center justify-between text-slate-900 font-semibold">
                      <span className="flex items-center space-x-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                        <span>{step.agent_name}</span>
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">{step.timestamp}</span>
                    </div>
                    <p className="text-slate-600 text-[11px] leading-relaxed">{step.output_summary}</p>
                  </div>
                ))}
              </div>

              {/* Containment Playbook */}
              <div className="p-4 rounded-xl bg-emerald-50/60 border border-emerald-200 space-y-2">
                <div className="font-bold text-emerald-900 text-xs flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-600" />
                  <span>Synthesized Containment Playbook (Response Agent)</span>
                </div>
                <pre className="text-[11px] font-mono text-emerald-900 bg-white p-3 rounded-lg border border-emerald-200 whitespace-pre-wrap">
                  {result.response.firewall_rule}
                </pre>
              </div>
            </div>
          ) : (
            <div className="bg-white p-12 rounded-2xl border border-slate-200 shadow-xs flex flex-col items-center justify-center text-center space-y-3 text-slate-400">
              <Cpu className="w-12 h-12 text-slate-300" />
              <div className="text-sm font-bold text-slate-700">Multi-Agent Studio Ready</div>
              <p className="text-xs text-slate-500 max-w-sm">
                Select an attack preset and click <strong>"Execute AI Pipeline"</strong> to watch the 4 LangGraph agents detect, investigate, and mitigate the simulated incident.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
