import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  Upload, 
  RefreshCw, 
  ChevronRight, 
  ChevronDown, 
  Terminal, 
  Check, 
  X,
  FileCode,
  ShieldAlert
} from 'lucide-react';
import { fetchLogs, ingestRawLog } from '../services/api';

export default function LogExplorerView({ onTriggerAlertRefresh }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [expandedLogId, setExpandedLogId] = useState(null);

  // Ingest modal state
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [rawLogInput, setRawLogInput] = useState('');
  const [ingestSource, setIngestSource] = useState('windows-security');
  const [ingestSuccess, setIngestSuccess] = useState(null);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const params = { limit: 100 };
      if (search) params.search = search;
      if (sourceFilter) params.source = sourceFilter;
      if (sevFilter) params.severity = sevFilter;
      const res = await fetchLogs(params);
      setLogs(res.logs || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [sourceFilter, sevFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadLogs();
  };

  const handleIngestSubmit = async (e) => {
    e.preventDefault();
    if (!rawLogInput.trim()) return;
    try {
      const res = await ingestRawLog(rawLogInput, ingestSource);
      setIngestSuccess(`Log ingested successfully! Triggered ${res.alerts_triggered?.length || 0} alerts.`);
      setRawLogInput('');
      loadLogs();
      if (onTriggerAlertRefresh) onTriggerAlertRefresh();
      setTimeout(() => setIngestSuccess(null), 4000);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search & Filter Header Bar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[280px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search logs by IP, user, event ID, process, or message..."
            className="w-full pl-10 pr-4 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </form>

        <div className="flex flex-wrap items-center gap-2">
          {/* Source Filter */}
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Sources</option>
            <option value="windows-security">Windows Security</option>
            <option value="nginx">Nginx Web</option>
            <option value="firewall">Firewall / Network</option>
            <option value="auth-linux">Linux Auth</option>
          </select>

          {/* Severity Filter */}
          <select
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="INFO">Info</option>
          </select>

          <button
            onClick={loadLogs}
            disabled={loading}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors disabled:opacity-50"
            title="Refresh logs"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={() => setShowIngestModal(true)}
            className="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium flex items-center gap-1.5 transition-colors"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Ingest Raw Log</span>
          </button>
        </div>
      </div>

      {/* Ingest Raw Log Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                Ingest Raw Forensic Log Record
              </h3>
              <button 
                onClick={() => setShowIngestModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs font-mono text-slate-400 mb-4">
              Paste raw Syslog, Nginx access line, or JSON. The SIEM parser will extract entities and run live correlation!
            </p>

            <form onSubmit={handleIngestSubmit} className="space-y-4">
              <div>
                <label className="text-xs font-mono text-slate-300 block mb-1">Source Format</label>
                <select
                  value={ingestSource}
                  onChange={(e) => setIngestSource(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300"
                >
                  <option value="windows-security">Windows Security Event</option>
                  <option value="nginx">Nginx / Apache Web Log</option>
                  <option value="auth-linux">Linux Syslog Auth</option>
                  <option value="firewall">Firewall / Network Alert</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-mono text-slate-300 block mb-1">Raw Log Content</label>
                <textarea
                  rows={4}
                  value={rawLogInput}
                  onChange={(e) => setRawLogInput(e.target.value)}
                  placeholder={`Example:\n192.168.1.50 - - [22/Oct/2026:14:20:00 +0000] "GET /login?user=' OR 1=1 HTTP/1.1" 500 240`}
                  className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              {ingestSuccess && (
                <div className="p-2.5 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-2">
                  <Check className="w-4 h-4 text-emerald-400" />
                  {ingestSuccess}
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowIngestModal(false)}
                  className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
                >
                  Close
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold"
                >
                  Submit & Correlate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Logs Table */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>Showing {logs.length} Log Records</span>
          <span>Click any row to inspect raw forensic payload</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/90 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="py-2.5 px-4 w-8"></th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Source</th>
                <th className="py-2.5 px-4">Event ID</th>
                <th className="py-2.5 px-4">Entity (IP / User)</th>
                <th className="py-2.5 px-4">Host</th>
                <th className="py-2.5 px-4">Message Preview</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    No logs found matching current filters.
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const isExpanded = expandedLogId === log.id;
                  const isCrit = log.severity === 'CRITICAL';
                  const isHigh = log.severity === 'HIGH';

                  return (
                    <React.Fragment key={log.id}>
                      <tr 
                        onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                        className={`cursor-pointer transition-colors ${
                          isExpanded 
                            ? 'bg-cyan-950/20' 
                            : isCrit 
                            ? 'bg-rose-950/10 hover:bg-rose-950/20' 
                            : 'hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="py-2.5 px-4 text-slate-500">
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-cyan-400" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                          {log.timestamp ? log.timestamp.replace('T', ' ').substring(0, 19) : ''}
                        </td>
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isCrit 
                              ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                              : isHigh 
                              ? 'bg-amber-950 text-amber-300 border border-amber-800' 
                              : 'bg-slate-800 text-slate-300'
                          }`}>
                            {log.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-slate-300 whitespace-nowrap">{log.source}</td>
                        <td className="py-2.5 px-4 font-semibold text-cyan-400 whitespace-nowrap">{log.event_id}</td>
                        <td className="py-2.5 px-4 text-slate-300 whitespace-nowrap">
                          {log.source_ip || log.user || '—'}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">{log.host || '—'}</td>
                        <td className="py-2.5 px-4 text-slate-300 max-w-md truncate">
                          {log.message}
                        </td>
                      </tr>

                      {/* Expanded Forensic Detail Row */}
                      {isExpanded && (
                        <tr className="bg-slate-950/80 border-b border-cyan-900/40">
                          <td colSpan={8} className="p-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                              <div className="space-y-1.5 p-3 rounded bg-slate-900 border border-slate-800">
                                <p className="text-cyan-400 font-bold mb-2">Parsed Security Indicators</p>
                                <p><span className="text-slate-500">Log ID:</span> <span className="text-slate-300">{log.id}</span></p>
                                <p><span className="text-slate-500">Action:</span> <span className="text-emerald-400">{log.action || 'N/A'}</span></p>
                                <p><span className="text-slate-500">Source IP:</span> <span className="text-amber-300">{log.source_ip || 'None'}</span></p>
                                <p><span className="text-slate-500">Destination:</span> <span className="text-slate-300">{log.destination_ip ? `${log.destination_ip}:${log.destination_port}` : 'None'}</span></p>
                                <p><span className="text-slate-500">User Identity:</span> <span className="text-slate-300">{log.user || 'None'}</span></p>
                                <p><span className="text-slate-500">Process / Binary:</span> <span className="text-slate-300">{log.process_name || 'None'}</span></p>
                                {log.command_line && (
                                  <p><span className="text-slate-500">Command Line:</span> <code className="text-rose-300 bg-black/40 px-1 py-0.5 rounded">{log.command_line}</code></p>
                                )}
                              </div>

                              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                                <p className="text-cyan-400 font-bold mb-2">Full Message & Telemetry</p>
                                <p className="text-slate-300 whitespace-pre-wrap leading-relaxed bg-black/50 p-2.5 rounded border border-slate-800">
                                  {log.message}
                                </p>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
