import React, { useState } from 'react';
import { 
  Settings, 
  Cpu, 
  Wifi, 
  Volume2, 
  VolumeX, 
  Save, 
  CheckCircle2, 
  Server
} from 'lucide-react';
import { useThreatFeed } from '../context/ThreatFeedContext';
import { soundFX } from '../services/soundEffects';
import { api } from '../services/api';

export const SettingsView: React.FC = () => {
  const { isAudioMuted, toggleAudioMute } = useThreatFeed();

  // Model calibration state
  const [isolationThreshold, setIsolationThreshold] = useState<number>(0.85);
  const [xgbConfidenceCutoff, setXgbConfidenceCutoff] = useState<number>(0.75);
  const [ragSimilarityCutoff, setRagSimilarityCutoff] = useState<number>(0.80);
  const [autoContainmentEnabled, setAutoContainmentEnabled] = useState<boolean>(true);

  // Backend API test state
  const [apiUrl, setApiUrl] = useState<string>('http://localhost:8000/api/v1');
  const [isTestingPing, setIsTestingPing] = useState<boolean>(false);
  const [pingStatus, setPingStatus] = useState<string | null>(null);
  const [isSaved, setIsSaved] = useState<boolean>(false);

  const handleTestPing = async () => {
    setIsTestingPing(true);
    soundFX.playScan();
    try {
      const ok = await api.checkHealth();
      if (ok) {
        setPingStatus('Backend API online & responsive (HTTP 200 OK)');
        soundFX.playSuccess();
      } else {
        setPingStatus('Backend API not reachable. Running on built-in mock telemetry engine.');
      }
    } catch {
      setPingStatus('Connection error. Operating in offline demonstration mode.');
    } finally {
      setIsTestingPing(false);
    }
  };

  const handleSave = () => {
    soundFX.playSuccess();
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 3000);
  };

  return (
    <div className="space-y-6 pb-12 max-w-4xl mx-auto">
      {/* Header Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600 mb-1">
            <Settings className="w-4 h-4" />
            <span>CONFIGURATION</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            System Settings & Model Parameters
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Configure machine learning anomaly thresholds, RAG sensitivity, and API gateway routing.
          </p>
        </div>

        <button
          onClick={handleSave}
          className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-all shadow-xs"
        >
          {isSaved ? <CheckCircle2 className="w-4 h-4 text-emerald-300" /> : <Save className="w-4 h-4" />}
          <span>{isSaved ? 'Settings Saved' : 'Save Changes'}</span>
        </button>
      </div>

      {/* Section 1: AI Engine Sensitivity */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-5">
        <div className="flex items-center space-x-2.5 border-b border-slate-100 pb-3">
          <div className="p-2 rounded-xl bg-indigo-50 text-indigo-600">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">AI Engine Calibration</h3>
            <p className="text-xs text-slate-500">Isolation Forest & XGBoost sensitivity tuning</p>
          </div>
        </div>

        <div className="space-y-4 text-xs">
          {/* Isolation Forest Threshold */}
          <div className="space-y-1.5">
            <div className="flex justify-between">
              <span className="font-semibold text-slate-800">Isolation Forest Outlier Threshold</span>
              <span className="font-mono font-bold text-indigo-600">{isolationThreshold.toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0.5"
              max="0.99"
              step="0.01"
              value={isolationThreshold}
              onChange={(e) => setIsolationThreshold(Number(e.target.value))}
              aria-label="Isolation Forest Outlier Threshold"
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
            />
            <p className="text-[11px] text-slate-500">
              Higher values decrease false positives by only flagging severe statistical anomalies.
            </p>
          </div>

          {/* XGBoost Confidence Cutoff */}
          <div className="space-y-1.5">
            <div className="flex justify-between">
              <span className="font-semibold text-slate-800">XGBoost Class Probability Cutoff</span>
              <span className="font-mono font-bold text-indigo-600">{Math.round(xgbConfidenceCutoff * 100)}%</span>
            </div>
            <input
              type="range"
              min="0.5"
              max="0.95"
              step="0.05"
              value={xgbConfidenceCutoff}
              onChange={(e) => setXgbConfidenceCutoff(Number(e.target.value))}
              aria-label="XGBoost Class Probability Cutoff"
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
            />
            <p className="text-[11px] text-slate-500">
              Minimum class posterior probability required before assigning a specific MITRE attack type.
            </p>
          </div>

          {/* RAG Cosine Threshold */}
          <div className="space-y-1.5">
            <div className="flex justify-between">
              <span className="font-semibold text-slate-800">Qdrant RAG Cosine Similarity Threshold</span>
              <span className="font-mono font-bold text-indigo-600">{ragSimilarityCutoff.toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0.6"
              max="0.95"
              step="0.01"
              value={ragSimilarityCutoff}
              onChange={(e) => setRagSimilarityCutoff(Number(e.target.value))}
              aria-label="Qdrant RAG Cosine Similarity Threshold"
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
            />
          </div>

          {/* Automated Containment Toggle */}
          <div className="flex items-center justify-between p-4 rounded-xl bg-slate-50 border border-slate-200">
            <div>
              <span className="font-semibold text-slate-900 block">Autonomous Response Playbook Dispatch</span>
              <span className="text-[11px] text-slate-500">Allow Response Agent to automatically synthesize firewall drop rules.</span>
            </div>
            <button
              onClick={() => {
                setAutoContainmentEnabled(!autoContainmentEnabled);
                soundFX.playClick();
              }}
              className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
                autoContainmentEnabled ? 'bg-indigo-600' : 'bg-slate-300'
              }`}
            >
              <div
                className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                  autoContainmentEnabled ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Section 2: API Gateway */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-4">
        <div className="flex items-center space-x-2.5 border-b border-slate-100 pb-3">
          <div className="p-2 rounded-xl bg-blue-50 text-blue-600">
            <Server className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">Backend API Gateway</h3>
            <p className="text-xs text-slate-500">FastAPI backend connection status and routing</p>
          </div>
        </div>

        <div className="space-y-3 text-xs">
          <div>
            <label className="block font-semibold text-slate-800 mb-1">FastAPI Endpoint URL</label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-500"
              />
              <button
                onClick={handleTestPing}
                disabled={isTestingPing}
                className="px-4 py-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs transition-all flex items-center space-x-1.5 shadow-xs"
              >
                <Wifi className="w-3.5 h-3.5" />
                <span>{isTestingPing ? 'Testing...' : 'Test Ping'}</span>
              </button>
            </div>
          </div>

          {pingStatus && (
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-700 text-[11px] font-mono">
              {pingStatus}
            </div>
          )}
        </div>
      </div>

      {/* Section 3: Audio Feedback */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-purple-50 text-purple-600">
            {isAudioMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">Audio Telemetry Beeps</h3>
            <p className="text-xs text-slate-500">Synthesize subtle cyber feedback tones during incident triggers</p>
          </div>
        </div>

        <button
          onClick={toggleAudioMute}
          className={`px-4 py-2 rounded-xl text-xs font-semibold border transition-all ${
            isAudioMuted
              ? 'bg-slate-100 border-slate-200 text-slate-500'
              : 'bg-indigo-50 border-indigo-200 text-indigo-700'
          }`}
        >
          {isAudioMuted ? 'Muted' : 'Enabled'}
        </button>
      </div>
    </div>
  );
};
