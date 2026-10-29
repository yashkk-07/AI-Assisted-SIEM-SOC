import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Layers, 
  Filter, 
  CheckCircle, 
  AlertOctagon, 
  Eye, 
  XCircle, 
  ChevronRight,
  ExternalLink,
  Flame,
  Check,
  RefreshCw
} from 'lucide-react';
import { fetchAlerts, triageAlert, fetchAlertDetail } from '../services/api';

export default function AlertTriageView({ onSelectIncident, onOpenAIChat }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  
  // Selected alert for detail inspector
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [alertLogs, setAlertLogs] = useState([]);
  const [inspectLoading, setInspectLoading] = useState(false);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const params = {};
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      const res = await fetchAlerts(params);
      setAlerts(res.alerts || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [statusFilter, severityFilter]);

  const handleTriageAction = async (alertId, newStatus) => {
    try {
      await triageAlert(alertId, newStatus);
      loadAlerts();
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(prev => ({ ...prev, status: newStatus }));
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleInspectAlert = async (alert) => {
    setSelectedAlert(alert);
    try {
      setInspectLoading(true);
      const detail = await fetchAlertDetail(alert.id);
      setAlertLogs(detail.correlated_logs || []);
    } catch (err) {
      console.error(err);
    } finally {
      setInspectLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Filters Bar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-4 h-4 text-amber-400" />
            Alert Correlation & Noise Deduplication Queue
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-0.5">
            Grouped by fingerprint sliding window. Repetitive events are aggregated to prevent analyst alert fatigue.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="ESCALATED">Escalated</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="SUPPRESSED">Suppressed Noise</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <button
            onClick={loadAlerts}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Refresh alerts"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Grid: Alerts List & Side Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Alerts List */}
        <div className={`${selectedAlert ? 'lg:col-span-7' : 'lg:col-span-12'} space-y-3`}>
          {alerts.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-400">
              No alerts found matching filter criteria.
            </div>
          ) : (
            alerts.map((alert) => {
              const isCrit = alert.severity === 'CRITICAL';
              const isHigh = alert.severity === 'HIGH';
              const isSelected = selectedAlert?.id === alert.id;

              return (
                <div
                  key={alert.id}
                  className={`p-4 rounded-xl border transition-all ${
                    isSelected 
                      ? 'bg-slate-900 border-cyan-500/70 shadow-lg shadow-cyan-500/10' 
                      : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        isCrit 
                          ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                          : isHigh 
                          ? 'bg-amber-950 text-amber-300 border border-amber-800' 
                          : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                      }`}>
                        {alert.severity}
                      </span>

                      <span className="text-xs font-mono font-bold text-slate-300">
                        {alert.id}
                      </span>

                      {alert.mitre_technique_id && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {alert.mitre_technique_id} ({alert.mitre_technique_name || alert.category})
                        </span>
                      )}

                      {alert.duplicate_count > 1 && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                          +{alert.duplicate_count - 1} Suppressed Duplicates
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <div className="text-right">
                        <span className="text-xs font-mono font-black text-amber-400">
                          Risk {alert.risk_score}/100
                        </span>
                      </div>
                    </div>
                  </div>

                  <h3 className="text-sm font-mono font-bold text-slate-100 mb-1">
                    {alert.title}
                  </h3>

                  <p className="text-xs font-mono text-slate-400 mb-3 leading-relaxed">
                    {alert.description}
                  </p>

                  {/* Entities Metadata Line */}
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-slate-400 py-2 px-3 rounded bg-slate-950 border border-slate-800/80 mb-3">
                    <span>Host: <strong className="text-slate-300">{alert.affected_host || 'N/A'}</strong></span>
                    <span>User: <strong className="text-slate-300">{alert.affected_user || 'N/A'}</strong></span>
                    <span>Source IP: <strong className="text-amber-300">{alert.source_ip || 'N/A'}</strong></span>
                    {alert.incident_id && (
                      <span className="text-cyan-400 font-bold">
                        Linked Case: {alert.incident_id}
                      </span>
                    )}
                  </div>

                  {/* Triage Actions Toolbar */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleTriageAction(alert.id, 'ESCALATED')}
                        disabled={alert.status === 'ESCALATED'}
                        className="px-2.5 py-1 text-xs font-mono rounded bg-rose-950/70 text-rose-300 border border-rose-800 hover:bg-rose-900/60 transition-colors disabled:opacity-40"
                      >
                        Escalate
                      </button>
                      <button
                        onClick={() => handleTriageAction(alert.id, 'FALSE_POSITIVE')}
                        disabled={alert.status === 'FALSE_POSITIVE'}
                        className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 transition-colors disabled:opacity-40"
                      >
                        False Positive
                      </button>
                      <button
                        onClick={() => handleTriageAction(alert.id, 'SUPPRESSED')}
                        disabled={alert.status === 'SUPPRESSED'}
                        className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700 transition-colors disabled:opacity-40"
                      >
                        Suppress
                      </button>
                    </div>

                    <button
                      onClick={() => handleInspectAlert(alert)}
                      className="px-3 py-1 text-xs font-mono rounded bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900/60 transition-colors flex items-center gap-1 font-semibold"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Inspect Telemetry</span>
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Alert Forensic Telemetry Drawer */}
        {selectedAlert && (
          <div className="lg:col-span-5 space-y-4">
            <div className="p-5 rounded-xl bg-slate-900 border border-cyan-500/50 shadow-2xl sticky top-28">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div>
                  <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase">
                    Forensic Evidence Locker
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">{selectedAlert.id}</p>
                </div>
                <button 
                  onClick={() => setSelectedAlert(null)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  <XCircle className="w-4 h-4" />
                </button>
              </div>

              <div className="mt-3 space-y-2 text-xs font-mono">
                <p><span className="text-slate-500">MITRE Tactic:</span> <span className="text-slate-200 font-bold">{selectedAlert.mitre_tactic}</span></p>
                <p><span className="text-slate-500">First Observed:</span> <span className="text-slate-300">{selectedAlert.first_seen?.substring(0, 19)}</span></p>
                <p><span className="text-slate-500">Last Observed:</span> <span className="text-slate-300">{selectedAlert.last_seen?.substring(0, 19)}</span></p>
                <p><span className="text-slate-500">Deduplication Fingerprint:</span> <code className="text-slate-400 bg-slate-950 px-1 py-0.5 rounded">{selectedAlert.dedup_fingerprint}</code></p>
              </div>

              <div className="mt-4">
                <h4 className="text-xs font-mono font-bold text-slate-300 mb-2 flex items-center justify-between">
                  <span>Correlated Raw Log Events ({alertLogs.length})</span>
                  {inspectLoading && <RefreshCw className="w-3 h-3 animate-spin text-cyan-400" />}
                </h4>

                <div className="max-h-[350px] overflow-y-auto space-y-2 pr-1 font-mono text-xs">
                  {alertLogs.length === 0 ? (
                    <div className="p-4 text-center text-slate-500 bg-slate-950 rounded">
                      Loading correlated log records...
                    </div>
                  ) : (
                    alertLogs.map((l) => (
                      <div key={l.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px]">
                        <div className="flex justify-between text-slate-500 mb-1">
                          <span>{l.timestamp?.substring(11, 19)} [{l.source}]</span>
                          <span className="text-cyan-400">{l.event_id}</span>
                        </div>
                        <p className="text-slate-300 leading-snug">{l.message}</p>
                        {l.command_line && (
                          <p className="mt-1 text-rose-300 bg-slate-900 p-1 rounded font-mono text-[10px] break-all">
                            cmd: {l.command_line}
                          </p>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>

              {selectedAlert.incident_id && (
                <div className="mt-4 pt-3 border-t border-slate-800">
                  <button
                    onClick={() => onSelectIncident(selectedAlert.incident_id)}
                    className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <span>Open Case {selectedAlert.incident_id} in Command Room</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
