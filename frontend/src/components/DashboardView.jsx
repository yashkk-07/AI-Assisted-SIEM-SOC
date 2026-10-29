import React from 'react';
import { 
  Activity, 
  Layers, 
  ShieldAlert, 
  Clock, 
  ArrowUpRight, 
  CheckCircle2, 
  Filter, 
  AlertTriangle,
  Zap,
  Server,
  Crosshair
} from 'lucide-react';
import StatCard from './StatCard';

export default function DashboardView({ 
  stats, 
  recentLogs = [], 
  recentAlerts = [], 
  onSelectAlert, 
  onSelectIncident,
  onNavigateTab
}) {
  const sevDist = stats?.severity_distribution || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const tactics = stats?.mitre_tactics_distribution || {};

  return (
    <div className="space-y-6">
      {/* Top SOC Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Logs Ingested"
          value={stats?.total_logs?.toLocaleString() || '0'}
          subtext="Continuous telemetry feed"
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Active Alerts"
          value={stats?.total_alerts?.toLocaleString() || '0'}
          subtext={`Suppressed: ${stats?.total_suppressed_alerts || 0} dups`}
          icon={Layers}
          color="amber"
        />
        <StatCard
          title="Deduplication Rate"
          value={`${stats?.deduplication_rate || 0}%`}
          subtext="Alert noise eliminated"
          icon={CheckCircle2}
          color="emerald"
          highlight={true}
        />
        <StatCard
          title="Critical Incidents"
          value={stats?.critical_incidents || 0}
          subtext={`${stats?.open_incidents_count || 0} total open cases`}
          icon={ShieldAlert}
          color="rose"
          highlight={Boolean(stats?.critical_incidents > 0)}
        />
        <StatCard
          title="Mean Triage Time"
          value={stats?.mean_time_to_triage || '3.8s'}
          subtext="MTTD: 1.4s (Automated)"
          icon={Clock}
          color="purple"
        />
      </div>

      {/* Threat Distribution & MITRE ATT&CK Matrix Radar Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Card */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-cyan-400" />
                Threat Priority Distribution
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">Normalized Risk</span>
            </div>

            <div className="space-y-3.5">
              {/* Critical */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-rose-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
                    CRITICAL (Score 85-100)
                  </span>
                  <span className="text-slate-300 font-bold">{sevDist.CRITICAL}</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-rose-500 to-red-600 rounded-full transition-all duration-500" 
                    style={{ width: `${Math.min(100, (sevDist.CRITICAL / (stats?.total_alerts || 1)) * 100)}%` }} 
                  />
                </div>
              </div>

              {/* High */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-amber-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                    HIGH (Score 68-84)
                  </span>
                  <span className="text-slate-300 font-bold">{sevDist.HIGH}</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-amber-500 to-orange-500 rounded-full transition-all duration-500" 
                    style={{ width: `${Math.min(100, (sevDist.HIGH / (stats?.total_alerts || 1)) * 100)}%` }} 
                  />
                </div>
              </div>

              {/* Medium */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-cyan-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
                    MEDIUM (Score 40-67)
                  </span>
                  <span className="text-slate-300 font-bold">{sevDist.MEDIUM}</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500" 
                    style={{ width: `${Math.min(100, (sevDist.MEDIUM / (stats?.total_alerts || 1)) * 100)}%` }} 
                  />
                </div>
              </div>

              {/* Low */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-slate-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-slate-500"></span>
                    LOW (Score 0-39)
                  </span>
                  <span className="text-slate-300 font-bold">{sevDist.LOW}</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div 
                    className="h-full bg-slate-600 rounded-full transition-all duration-500" 
                    style={{ width: `${Math.min(100, (sevDist.LOW / (stats?.total_alerts || 1)) * 100)}%` }} 
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Deduplication Suppression:</span>
            <span className="text-emerald-400 font-bold">+{stats?.total_suppressed_alerts || 0} alerts saved</span>
          </div>
        </div>

        {/* MITRE ATT&CK Observed Tactics */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              MITRE ATT&CK Matrix Activity
            </h3>
            <button 
              onClick={() => onNavigateTab('incidents')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              View Command Room <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {[
              { tactic: 'Credential Access', icon: '🔑', count: tactics['Credential Access'] || 0, id: 'TA0006' },
              { tactic: 'Lateral Movement', icon: '🔄', count: tactics['Lateral Movement'] || 0, id: 'TA0008' },
              { tactic: 'Initial Access', icon: '🌐', count: tactics['Initial Access'] || 0, id: 'TA0001' },
              { tactic: 'Execution', icon: '⚙️', count: tactics['Execution'] || 0, id: 'TA0002' },
              { tactic: 'Impact / Ransomware', icon: '💥', count: (tactics['Impact'] || 0) + (tactics['Ransomware Canary'] || 0), id: 'TA0040' },
              { tactic: 'Data Exfiltration', icon: '📤', count: tactics['Exfiltration'] || 0, id: 'TA0010' },
            ].map((item) => {
              const hasHits = item.count > 0;
              return (
                <div 
                  key={item.tactic} 
                  className={`p-3 rounded-lg border transition-all ${
                    hasHits 
                      ? 'bg-slate-950/80 border-cyan-500/40 shadow-sm shadow-cyan-500/10' 
                      : 'bg-slate-950/40 border-slate-800/60 opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span>{item.id}</span>
                    <span className="text-base">{item.icon}</span>
                  </div>
                  <p className="text-xs font-mono font-bold text-slate-200 mt-1 truncate">{item.tactic}</p>
                  <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-slate-800 text-[11px] font-mono">
                    <span className="text-slate-400">Detections:</span>
                    <span className={`font-bold ${hasHits ? 'text-amber-400' : 'text-slate-500'}`}>{item.count}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Correlated Alerts & Real-Time Live Log Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Priority Security Alerts */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl">
          <div className="flex items-center justify-between mb-3.5">
            <h3 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Correlated Security Alerts
            </h3>
            <button 
              onClick={() => onNavigateTab('alerts')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              All Alerts ({stats?.total_alerts || 0}) <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
            {recentAlerts.length === 0 ? (
              <div className="text-center py-10 text-xs font-mono text-slate-400">
                No alerts detected. Trigger an attack above to watch correlation in action!
              </div>
            ) : (
              recentAlerts.slice(0, 6).map((alert) => {
                const isCrit = alert.severity === 'CRITICAL';
                const isHigh = alert.severity === 'HIGH';
                return (
                  <div 
                    key={alert.id}
                    onClick={() => onSelectAlert && onSelectAlert(alert)}
                    className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex items-start justify-between gap-3 group"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          isCrit 
                            ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                            : isHigh 
                            ? 'bg-amber-950 text-amber-300 border border-amber-800' 
                            : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                        }`}>
                          {alert.severity}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400 truncate">
                          {alert.mitre_technique_id} • {alert.category}
                        </span>
                        {alert.duplicate_count > 1 && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800">
                            +{alert.duplicate_count - 1} deduped
                          </span>
                        )}
                      </div>
                      <h4 className="text-xs font-mono font-semibold text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                        {alert.title}
                      </h4>
                      <p className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                        Target: <span className="text-slate-300">{alert.affected_host || alert.affected_user || 'Network'}</span> | IP: <span className="text-slate-300">{alert.source_ip || 'N/A'}</span>
                      </p>
                    </div>

                    <div className="text-right flex-shrink-0">
                      <div className="text-xs font-mono font-bold text-amber-400">
                        Score {alert.risk_score}
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        {alert.status}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Real-time Live Log Stream Ticker */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3.5">
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
                </span>
                <h3 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider">
                  Live Log Telemetry Stream
                </h3>
              </div>
              <button 
                onClick={() => onNavigateTab('logs')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                Log Explorer <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-1.5 font-mono text-xs max-h-[380px] overflow-y-auto pr-1 bg-slate-950 p-3 rounded-lg border border-slate-800/80">
              {recentLogs.length === 0 ? (
                <div className="text-center py-10 text-slate-500 text-xs">
                  Streaming logs...
                </div>
              ) : (
                recentLogs.slice(0, 10).map((log) => {
                  const isSuspicious = log.severity === 'CRITICAL' || log.severity === 'HIGH';
                  return (
                    <div 
                      key={log.id} 
                      className={`py-1 px-1.5 rounded transition-all flex items-start justify-between gap-2 border-l-2 ${
                        isSuspicious 
                          ? 'border-rose-500 bg-rose-950/20 text-rose-200' 
                          : 'border-slate-700 hover:bg-slate-900 text-slate-300'
                      }`}
                    >
                      <div className="min-w-0 flex-1 truncate">
                        <span className="text-slate-400 mr-2">[{log.source}]</span>
                        <span className="font-semibold text-cyan-400 mr-1.5">{log.action || log.event_id}</span>
                        <span>{log.message}</span>
                      </div>
                      <span className="text-[10px] text-slate-400 flex-shrink-0">
                        {log.timestamp ? log.timestamp.substring(11, 19) : ''}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <span>Filter: Ingesting Syslog, Windows Security, WAF, Firewall</span>
            <span className="text-cyan-400">WebSocket Live Feed</span>
          </div>
        </div>
      </div>
    </div>
  );
}
