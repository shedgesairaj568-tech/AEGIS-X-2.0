import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Cpu, 
  ShieldCheck, 
  BookOpen, 
  FileText, 
  ListFilter, 
  Settings, 
  LogOut, 
  Shield 
} from "lucide-react";
import { useAuthStore } from "../store/authStore";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/alerts", label: "Alerts & Incidents", icon: ShieldAlert },
  { to: "/agents", label: "AI Defense Studio", icon: Cpu },
  { to: "/actions", label: "Incident Containment", icon: ShieldCheck },
  { to: "/intel", label: "Threat Intelligence", icon: BookOpen },
  { to: "/reports", label: "Incident Reports", icon: FileText },
  { to: "/audit", label: "Audit Trail", icon: ListFilter },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function AppShell() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="flex h-screen bg-slate-900 text-slate-100 font-sans">
      {/* Sidebar */}
      <aside className="flex w-64 flex-col border-r border-slate-800 bg-slate-950">
        <div className="flex h-16 items-center gap-3 border-b border-slate-800 px-5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600/20 text-indigo-400 border border-indigo-500/30">
            <Shield className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <div className="font-bold tracking-wider text-sm text-white">AEGIS-X 2.0</div>
            <div className="text-[10px] leading-tight text-indigo-400 font-mono tracking-widest uppercase">
              DEFENSE SOC CONSOLE
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1.5 px-3 py-4 overflow-y-auto">
          <div className="px-3 pb-1 text-[10px] font-semibold tracking-wider text-slate-500 uppercase">
            Operations & AI
          </div>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-2 text-xs font-semibold transition-all ${
                    isActive
                      ? "bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 shadow-xs"
                      : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>

        {/* User Footer */}
        <div className="border-t border-slate-800 p-3 bg-slate-950/80">
          <div className="flex items-center gap-2.5 rounded-lg px-2 py-2">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-xs font-bold text-indigo-400 border border-slate-700">
              {user?.full_name?.[0]?.toUpperCase() ?? "A"}
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-semibold text-slate-200">
                {user?.full_name || "SOC Analyst"}
              </div>
              <div className="truncate text-[10px] text-slate-500 font-mono uppercase">
                Role: <span className="text-indigo-400 font-bold">{user?.role || "analyst"}</span>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-800 hover:text-slate-200 transition-colors"
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto bg-slate-100 text-slate-900">
        <Outlet />
      </main>
    </div>
  );
}
