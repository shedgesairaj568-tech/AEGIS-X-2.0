import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Activity, 
  Volume2, 
  VolumeX, 
  Play, 
  Pause, 
  User as UserIcon, 
  LogOut, 
  LogIn, 
  Zap,
  ChevronDown
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useThreatFeed } from '../../context/ThreatFeedContext';
import { soundFX } from '../../services/soundEffects';

interface HeaderProps {
  onOpenAuth: () => void;
  currentView: string;
  setCurrentView: (view: string) => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenAuth, setCurrentView }) => {
  const { user, isAuthenticated, logout, isBackendConnected, refreshHealth } = useAuth();
  const { 
    defconLevel, 
    isStreaming, 
    setIsStreaming, 
    isAudioMuted, 
    toggleAudioMute,
    triggerSimulationEvent 
  } = useThreatFeed();

  const [timeStr, setTimeStr] = useState<string>('');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [showUserMenu, setShowUserMenu] = useState<boolean>(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulate = async () => {
    setIsSimulating(true);
    soundFX.playScan();
    await triggerSimulationEvent();
    setIsSimulating(false);
  };

  const getDefconBadge = (level: number) => {
    switch (level) {
      case 1:
        return {
          bg: 'bg-rose-50 text-rose-700 border-rose-200',
          text: 'Threat Level: Critical',
          dot: 'bg-rose-500 animate-ping',
        };
      case 2:
        return {
          bg: 'bg-orange-50 text-orange-700 border-orange-200',
          text: 'Threat Level: High',
          dot: 'bg-orange-500',
        };
      case 3:
        return {
          bg: 'bg-amber-50 text-amber-700 border-amber-200',
          text: 'Threat Level: Elevated',
          dot: 'bg-amber-500',
        };
      case 4:
        return {
          bg: 'bg-blue-50 text-blue-700 border-blue-200',
          text: 'Threat Level: Guarded',
          dot: 'bg-blue-500',
        };
      default:
        return {
          bg: 'bg-emerald-50 text-emerald-700 border-emerald-200',
          text: 'Threat Level: Nominal',
          dot: 'bg-emerald-500',
        };
    }
  };

  const defcon = getDefconBadge(defconLevel);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200/80 bg-white/95 backdrop-blur-md px-4 lg:px-6 py-3 flex items-center justify-between shadow-xs">
      {/* Left: Branding & Status */}
      <div className="flex items-center space-x-4 lg:space-x-6">
        <div 
          onClick={() => setCurrentView('dashboard')}
          className="flex items-center space-x-3 cursor-pointer group select-none"
        >
          <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-indigo-600 text-white shadow-sm group-hover:bg-indigo-700 transition-all">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-base font-bold text-slate-900 tracking-tight">
                AEGIS-X
              </span>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-700 border border-indigo-100">
                SOC Platform
              </span>
            </div>
            <p className="text-[11px] text-slate-500 hidden sm:block">
              Autonomous Cybersecurity & AI Incident Defense
            </p>
          </div>
        </div>

        {/* Threat Status Badge */}
        <div className={`hidden md:flex items-center space-x-2 px-3 py-1 rounded-full border text-xs font-medium ${defcon.bg}`}>
          <span className="relative flex h-2 w-2">
            <span className={`relative inline-flex rounded-full h-2 w-2 ${defcon.dot.split(' ')[0]}`}></span>
          </span>
          <span>{defcon.text}</span>
        </div>
      </div>

      {/* Center: Simple Live Telemetry Toggle */}
      <div className="hidden lg:flex items-center space-x-3 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-xl text-xs">
        <div className="flex items-center space-x-2">
          <Activity className={`w-3.5 h-3.5 ${isStreaming ? 'text-emerald-600' : 'text-slate-400'}`} />
          <span className="text-slate-600 font-medium">Live Feed:</span>
          <button
            onClick={() => {
              setIsStreaming(!isStreaming);
              soundFX.playClick();
            }}
            className={`px-2.5 py-0.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1 ${
              isStreaming
                ? 'bg-emerald-100 text-emerald-800 hover:bg-emerald-200'
                : 'bg-slate-200 text-slate-700 hover:bg-slate-300'
            }`}
          >
            {isStreaming ? (
              <>
                <Pause className="w-2.5 h-2.5 mr-0.5" />
                <span>Streaming</span>
              </>
            ) : (
              <>
                <Play className="w-2.5 h-2.5 mr-0.5" />
                <span>Paused</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center space-x-2 sm:space-x-3">
        {/* Real-time Clock */}
        <div className="hidden sm:block text-right text-xs font-mono text-slate-500 border-r border-slate-200 pr-3">
          <div className="text-slate-800 font-semibold">{timeStr}</div>
          <div className="text-[10px] text-slate-400">SOC LOCAL</div>
        </div>

        {/* Quick Test Threat Button */}
        <button
          onClick={handleSimulate}
          disabled={isSimulating}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-rose-50 border border-rose-200 text-rose-700 hover:bg-rose-100 transition-all active:scale-95 disabled:opacity-50"
          title="Simulate an inbound security event"
        >
          <Zap className="w-3.5 h-3.5 text-rose-600" />
          <span className="hidden sm:inline">{isSimulating ? 'Simulating...' : 'Test Incident'}</span>
        </button>

        {/* Audio Toggle */}
        <button
          onClick={toggleAudioMute}
          className={`p-2 rounded-xl border text-xs transition-all ${
            isAudioMuted
              ? 'bg-slate-100 border-slate-200 text-slate-400 hover:text-slate-600'
              : 'bg-indigo-50 border-indigo-200 text-indigo-700 hover:bg-indigo-100'
          }`}
          title={isAudioMuted ? 'Unmute Sound FX' : 'Mute Sound FX'}
        >
          {isAudioMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
        </button>

        {/* Backend API Health Status */}
        <button
          onClick={refreshHealth}
          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-xl border text-xs font-medium transition-all ${
            isBackendConnected
              ? 'bg-emerald-50 border-emerald-200 text-emerald-700 hover:bg-emerald-100'
              : 'bg-slate-100 border-slate-200 text-slate-700 hover:bg-slate-200'
          }`}
          title={isBackendConnected ? 'FastAPI API Connected' : 'Demo Engine Active (Click to test connection)'}
        >
          <span className={`w-2 h-2 rounded-full ${isBackendConnected ? 'bg-emerald-500' : 'bg-indigo-500'}`} />
          <span className="hidden md:inline">{isBackendConnected ? 'Backend Connected' : 'Demo Ready'}</span>
        </button>

        {/* User Profile / Login */}
        <div className="relative">
          {isAuthenticated && user ? (
            <div>
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center space-x-2 p-1.5 pr-2.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-xs text-slate-700 transition-all"
              >
                <div className="w-6 h-6 rounded-lg bg-indigo-600 text-white font-bold text-xs flex items-center justify-center">
                  {user.full_name.charAt(0)}
                </div>
                <span className="hidden md:inline font-semibold truncate max-w-[120px]">
                  {user.full_name.split(' ')[0]}
                </span>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>

              {showUserMenu && (
                <div 
                  className="absolute right-0 mt-2 w-56 bg-white rounded-2xl border border-slate-200 p-2 shadow-lg z-50 animate-in fade-in zoom-in-95 duration-100"
                  onClick={() => setShowUserMenu(false)}
                >
                  <div className="px-3 py-2 border-b border-slate-100">
                    <div className="font-semibold text-slate-900 text-xs truncate">{user.full_name}</div>
                    <div className="text-[11px] text-slate-500 truncate">{user.email}</div>
                    <div className="mt-1 inline-block px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 text-[10px] uppercase font-bold">
                      {user.role}
                    </div>
                  </div>
                  <button
                    onClick={() => setCurrentView('settings')}
                    className="w-full text-left px-3 py-2 text-xs text-slate-700 hover:bg-slate-50 hover:text-indigo-600 rounded-lg flex items-center space-x-2 transition-colors"
                  >
                    <UserIcon className="w-3.5 h-3.5" />
                    <span>Settings & Preferences</span>
                  </button>
                  <button
                    onClick={logout}
                    className="w-full text-left px-3 py-2 text-xs text-rose-600 hover:bg-rose-50 rounded-lg flex items-center space-x-2 transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              )}
            </div>
          ) : (
            <button
              onClick={onOpenAuth}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white transition-all shadow-xs"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
