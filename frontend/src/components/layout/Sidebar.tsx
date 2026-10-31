import React from 'react';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Cpu, 
  BookOpen, 
  FileText, 
  ListFilter, 
  Settings, 
  ChevronLeft, 
  ChevronRight,
  Zap
} from 'lucide-react';
import { useThreatFeed } from '../../context/ThreatFeedContext';
import { soundFX } from '../../services/soundEffects';

interface SidebarProps {
  currentView: string;
  setCurrentView: (view: string) => void;
  isCollapsed: boolean;
  setIsCollapsed: (collapsed: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  setCurrentView,
  isCollapsed,
  setIsCollapsed,
}) => {
  const { stats, triggerSimulationEvent } = useThreatFeed();

  const navItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'alerts',
      label: 'Incidents & Alerts',
      icon: ShieldAlert,
      badge: stats.open > 0 ? stats.open : null,
      badgeColor: 'bg-rose-100 text-rose-700',
    },
    {
      id: 'agents',
      label: 'AI Defense Studio',
      icon: Cpu,
      badge: '4 Agents',
      badgeColor: 'bg-purple-100 text-purple-700',
    },
    {
      id: 'intel',
      label: 'Threat Intelligence',
      icon: BookOpen,
      badge: 'MITRE',
      badgeColor: 'bg-indigo-100 text-indigo-700',
    },
    {
      id: 'reports',
      label: 'Incident Reports',
      icon: FileText,
      badge: null,
    },
    {
      id: 'audit',
      label: 'Audit Trail',
      icon: ListFilter,
      badge: null,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
      badge: null,
    },
  ];

  return (
    <aside
      className={`fixed left-0 top-[61px] bottom-0 z-30 bg-white border-r border-slate-200 flex flex-col justify-between transition-all duration-300 ${
        isCollapsed ? 'w-16' : 'w-60'
      }`}
    >
      {/* Top Nav List */}
      <div className="p-3 space-y-1 overflow-y-auto">
        {!isCollapsed && (
          <div className="px-3 py-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Menu
          </div>
        )}

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => {
                setCurrentView(item.id);
                soundFX.playClick();
              }}
              title={isCollapsed ? item.label : undefined}
              className={`w-full flex items-center rounded-xl text-xs font-medium transition-all duration-150 group relative ${
                isCollapsed ? 'justify-center p-3' : 'px-3.5 py-2.5 justify-between'
              } ${
                isActive
                  ? 'bg-indigo-50 text-indigo-700 font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon
                  className={`w-4 h-4 transition-colors ${
                    isActive ? 'text-indigo-600' : 'text-slate-400 group-hover:text-slate-600'
                  }`}
                />
                {!isCollapsed && <span>{item.label}</span>}
              </div>

              {!isCollapsed && item.badge && (
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                    item.badgeColor || 'bg-slate-100 text-slate-600'
                  }`}
                >
                  {item.badge}
                </span>
              )}

              {/* Collapsed Badge Dot */}
              {isCollapsed && item.badge && (
                <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-indigo-600" />
              )}
            </button>
          );
        })}
      </div>

      {/* Bottom Controls */}
      <div className="p-3 border-t border-slate-100 space-y-2">
        {/* Quick Simulation Trigger Button */}
        {!isCollapsed && (
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs">
            <div className="flex items-center justify-between text-slate-800 font-semibold mb-1">
              <span className="flex items-center space-x-1.5">
                <Zap className="w-3.5 h-3.5 text-indigo-600" />
                <span>Simulate Event</span>
              </span>
              <span className="text-[10px] text-slate-400 font-normal">AI Triage</span>
            </div>
            <p className="text-[11px] text-slate-500 mb-2">
              Inject synthetic telemetry to test automated response.
            </p>
            <button
              onClick={() => {
                triggerSimulationEvent();
                soundFX.playScan();
              }}
              className="w-full py-1.5 px-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-medium text-xs flex items-center justify-center space-x-1 transition-all shadow-xs"
            >
              <span>Test Random Threat</span>
            </button>
          </div>
        )}

        {/* Collapse toggle */}
        <button
          onClick={() => {
            setIsCollapsed(!isCollapsed);
            soundFX.playClick();
          }}
          className="w-full flex items-center justify-center p-2 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-50 border border-transparent text-xs transition-all"
          title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          {!isCollapsed && <span className="ml-2 font-medium">Collapse</span>}
        </button>
      </div>
    </aside>
  );
};
