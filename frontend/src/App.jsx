import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import DashboardView from './components/DashboardView';
import LogExplorerView from './components/LogExplorerView';
import AlertTriageView from './components/AlertTriageView';
import IncidentRoomView from './components/IncidentRoomView';
import SettingsView from './components/SettingsView';
import AIChatDrawer from './components/AIChatDrawer';
import { fetchStats, fetchLogs, fetchAlerts } from './services/api';
import { Bell, ShieldAlert, X } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [simulatorRunning, setSimulatorRunning] = useState(true);
  const [stats, setStats] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  
  // Navigation & Drilldown states
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [isAIChatOpen, setIsAIChatOpen] = useState(false);
  const [chatIncidentContext, setChatIncidentContext] = useState(null);
  
  // Cyber alert toast notification
  const [activeToast, setActiveToast] = useState(null);

  const socketRef = useRef(null);

  // Poll high-level metrics every 3 seconds
  const refreshMetrics = async () => {
    try {
      const [statsData, logsData, alertsData] = await Promise.all([
        fetchStats(),
        fetchLogs({ limit: 20 }),
        fetchAlerts({ limit: 15 }),
      ]);
      setStats(statsData);
      setRecentLogs(logsData.logs || []);
      setRecentAlerts(alertsData.alerts || []);
    } catch (err) {
      console.error("Metrics sync error:", err);
    }
  };

  useEffect(() => {
    refreshMetrics();
    const interval = setInterval(refreshMetrics, 3000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket Live Stream Connection
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/logs`;

    const connectWS = () => {
      try {
        const ws = new WebSocket(wsUrl);
        socketRef.current = ws;

        ws.onopen = () => {
          console.log("[SIEM WebSocket] Connected to real-time telemetry stream.");
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'NEW_LOG') {
              setRecentLogs((prev) => [data.log, ...prev.slice(0, 49)]);

              if (data.alerts_triggered && data.alerts_triggered.length > 0) {
                const latestAlert = data.alerts_triggered[0];
                setRecentAlerts((prev) => [latestAlert, ...prev.slice(0, 19)]);

                // Pop cyber alert toast if high or critical
                if (latestAlert.severity === 'CRITICAL' || latestAlert.severity === 'HIGH') {
                  setActiveToast({
                    id: latestAlert.id,
                    title: latestAlert.title,
                    severity: latestAlert.severity,
                    incidentId: latestAlert.incident_id,
                  });
                  setTimeout(() => setActiveToast(null), 6000);
                }
              }
            }
          } catch (e) {
            console.error("WS message parse error:", e);
          }
        };

        ws.onclose = () => {
          console.log("[SIEM WebSocket] Disconnected. Reconnecting in 3s...");
          setTimeout(connectWS, 3000);
        };
      } catch (err) {
        console.error("WebSocket setup error:", err);
      }
    };

    connectWS();
    return () => {
      if (socketRef.current) socketRef.current.close();
    };
  }, []);

  const handleSelectAlert = (alert) => {
    if (alert.incident_id) {
      setSelectedIncidentId(alert.incident_id);
      setCurrentTab('incidents');
    } else {
      setCurrentTab('alerts');
    }
  };

  const handleSelectIncident = (incidentId) => {
    setSelectedIncidentId(incidentId);
    setChatIncidentContext(incidentId);
    setCurrentTab('incidents');
  };

  const handleOpenAIChat = (incidentId = null) => {
    setChatIncidentContext(incidentId || selectedIncidentId);
    setIsAIChatOpen(true);
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 cyber-grid relative">
      {/* Navbar */}
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        simulatorRunning={simulatorRunning}
        setSimulatorRunning={setSimulatorRunning}
        onScenarioTriggered={() => refreshMetrics()}
        onOpenAIChat={() => handleOpenAIChat()}
        dedupRate={stats?.deduplication_rate || 0}
      />

      {/* Main Content View Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 pb-20">
        {currentTab === 'dashboard' && (
          <DashboardView
            stats={stats}
            recentLogs={recentLogs}
            recentAlerts={recentAlerts}
            onSelectAlert={handleSelectAlert}
            onSelectIncident={handleSelectIncident}
            onNavigateTab={setCurrentTab}
          />
        )}

        {currentTab === 'logs' && (
          <LogExplorerView onTriggerAlertRefresh={refreshMetrics} />
        )}

        {currentTab === 'alerts' && (
          <AlertTriageView
            onSelectIncident={handleSelectIncident}
            onOpenAIChat={handleOpenAIChat}
          />
        )}

        {currentTab === 'incidents' && (
          <IncidentRoomView
            initialIncidentId={selectedIncidentId}
            onOpenAIChat={handleOpenAIChat}
          />
        )}

        {currentTab === 'settings' && <SettingsView />}
      </main>

      {/* Cyber SOC Live Toast Alert */}
      {activeToast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm w-full bg-slate-900 border border-rose-500/60 p-4 rounded-xl shadow-2xl glow-red animate-bounce">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <div className="p-2 rounded-lg bg-rose-950 text-rose-400 mt-0.5">
                <ShieldAlert className="w-4 h-4 animate-pulse" />
              </div>
              <div>
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                  {activeToast.severity} ALERT DETECTED
                </span>
                <h4 className="text-xs font-mono font-bold text-slate-100 mt-1 leading-snug">
                  {activeToast.title}
                </h4>
                {activeToast.incidentId && (
                  <button
                    onClick={() => {
                      handleSelectIncident(activeToast.incidentId);
                      setActiveToast(null);
                    }}
                    className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 mt-1 block font-semibold underline"
                  >
                    Investigate Case {activeToast.incidentId} →
                  </button>
                )}
              </div>
            </div>
            <button
              onClick={() => setActiveToast(null)}
              className="text-slate-400 hover:text-slate-200"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Slide-over AI SOC Assistant Drawer */}
      <AIChatDrawer
        isOpen={isAIChatOpen}
        onClose={() => setIsAIChatOpen(false)}
        incidentId={chatIncidentContext}
      />
    </div>
  );
}
