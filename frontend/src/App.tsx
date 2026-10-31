import { useEffect, useState } from "react";
import { BrowserRouter, Route, Routes, useNavigate } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { useAuthStore } from "./store/authStore";

import { AuthProvider } from "./context/AuthContext";
import { ThreatFeedProvider } from "./context/ThreatFeedContext";

// SOC Console Views
import { DashboardView } from "./views/DashboardView";
import { AlertsView } from "./views/AlertsView";
import { MultiAgentStudioView } from "./views/MultiAgentStudioView";
import { ResponseManagementView } from "./views/ResponseManagementView";
import { ThreatIntelView } from "./views/ThreatIntelView";
import { ReportsView } from "./views/ReportsView";
import { AuditLogsView } from "./views/AuditLogsView";
import { SettingsView } from "./views/SettingsView";
import { AlertDetailModal } from "./components/alerts/AlertDetailModal";

import type { Alert } from "./types";

function DashboardViewWrapper({ onSelectAlert }: { onSelectAlert: (alert: Alert) => void }) {
  const navigate = useNavigate();
  return (
    <div className="p-6">
      <DashboardView 
        onSelectAlert={onSelectAlert} 
        onNavigate={(view) => {
          if (view === 'alerts') navigate('/alerts');
          else if (view === 'agents') navigate('/agents');
          else if (view === 'intel') navigate('/intel');
          else if (view === 'actions') navigate('/actions');
          else if (view === 'reports') navigate('/reports');
          else if (view === 'audit') navigate('/audit');
          else if (view === 'settings') navigate('/settings');
          else navigate('/');
        }} 
      />
    </div>
  );
}

function AlertsViewWrapper({ onSelectAlert }: { onSelectAlert: (alert: Alert) => void }) {
  return (
    <div className="p-6">
      <AlertsView onSelectAlert={onSelectAlert} />
    </div>
  );
}

function MainAppShell() {
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  return (
    <>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<DashboardViewWrapper onSelectAlert={setSelectedAlert} />} />
          <Route path="/alerts" element={<AlertsViewWrapper onSelectAlert={setSelectedAlert} />} />
          <Route path="/agents" element={<div className="p-6"><MultiAgentStudioView /></div>} />
          <Route path="/actions" element={<div className="p-6"><ResponseManagementView onSelectAlert={(_id) => {}} /></div>} />
          <Route path="/intel" element={<div className="p-6"><ThreatIntelView /></div>} />
          <Route path="/reports" element={<div className="p-6"><ReportsView /></div>} />
          <Route path="/audit" element={<div className="p-6"><AuditLogsView /></div>} />
          <Route path="/settings" element={<div className="p-6"><SettingsView /></div>} />
        </Route>
      </Routes>

      {/* Global Drill-Down & Explainability Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onAlertUpdated={(updated) => setSelectedAlert(updated)}
        />
      )}
    </>
  );
}

function App() {
  const initialize = useAuthStore((s) => s.initialize);

  useEffect(() => {
    initialize();
  }, [initialize]);

  return (
    <AuthProvider>
      <ThreatFeedProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <MainAppShell />
                </ProtectedRoute>
              }
            />
          </Routes>
        </BrowserRouter>
      </ThreatFeedProvider>
    </AuthProvider>
  );
}

export default App;
