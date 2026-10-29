import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Sparkles, 
  FileText, 
  Clock, 
  CheckSquare, 
  Square, 
  ExternalLink, 
  AlertTriangle, 
  User, 
  Server, 
  Globe, 
  Share2, 
  ChevronRight,
  RefreshCw,
  Cpu,
  Layers,
  ArrowRight,
  Terminal
} from 'lucide-react';
import { 
  fetchIncidents, 
  fetchIncidentDetail, 
  updateIncidentStatus, 
  updatePlaybookStep, 
  triggerAIInvestigation 
} from '../services/api';
import ReportModal from './ReportModal';

export default function IncidentRoomView({ initialIncidentId, onOpenAIChat }) {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(initialIncidentId || null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [aiRunning, setAiRunning] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);

  const loadIncidents = async () => {
    try {
      setLoading(true);
      const res = await fetchIncidents();
      const list = res.incidents || [];
      setIncidents(list);
      if (list.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(list[0].id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadIncidentDetail = async (id) => {
    if (!id) return;
    try {
      const res = await fetchIncidentDetail(id);
      setIncidentDetail(res);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      loadIncidentDetail(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const handleStatusChange = async (newStatus) => {
    if (!selectedIncidentId) return;
    try {
      await updateIncidentStatus(selectedIncidentId, newStatus);
      loadIncidentDetail(selectedIncidentId);
      loadIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handlePlaybookToggle = async (index, currentCompleted) => {
    if (!selectedIncidentId) return;
    try {
      await updatePlaybookStep(selectedIncidentId, index, !currentCompleted);
      loadIncidentDetail(selectedIncidentId);
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunAI = async () => {
    if (!selectedIncidentId) return;
    try {
      setAiRunning(true);
      await triggerAIInvestigation(selectedIncidentId);
      await loadIncidentDetail(selectedIncidentId);
    } catch (err) {
      console.error(err);
    } finally {
      setAiRunning(false);
    }
  };

  const incident = incidentDetail?.incident;
  const correlatedAlerts = incidentDetail?.correlated_alerts || [];
  const correlatedLogs = incidentDetail?.correlated_logs || [];

  return (
    <div className="space-y-6">
      {/* Incident Case Selector Bar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
              SOC Incident Investigation Command Room
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Autonomous Correlation, Attack Sequence Reconstruction & Containment Playbook
            </p>
          </div>
        </div>

        {/* Case Selector Dropdown */}
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-slate-400 hidden sm:inline">Active Case:</span>
          <select
            value={selectedIncidentId || ''}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 font-bold focus:outline-none focus:border-cyan-500"
          >
            {incidents.map((inc) => (
              <option key={inc.id} value={inc.id}>
                {inc.id} - {inc.severity} [{inc.threat_score}/100]
              </option>
            ))}
          </select>

          <button
            onClick={() => loadIncidentDetail(selectedIncidentId)}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Reload incident"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {!incident ? (
        <div className="p-16 text-center rounded-xl bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-400">
          No incident selected. Ingest logs or trigger an attack scenario from the top banner to generate an incident.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Incident Banner & Quick Actions */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl relative overflow-hidden">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="space-y-1.5 flex-1 min-w-[280px]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-black ${
                    incident.severity === 'CRITICAL' 
                      ? 'bg-rose-950 text-rose-300 border border-rose-800 glow-red' 
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    {incident.severity} PRIORITY
                  </span>
                  <span className="text-xs font-mono font-bold text-slate-400">{incident.id}</span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    Analyst: {incident.assigned_analyst}
                  </span>
                </div>

                <h1 className="text-lg font-mono font-bold text-slate-100 mt-1">
                  {incident.title}
                </h1>

                <p className="text-xs font-mono text-slate-400">
                  Created: {incident.created_at?.replace('T', ' ').substring(0, 19)} UTC • Updated: {incident.updated_at?.replace('T', ' ').substring(0, 19)} UTC
                </p>
              </div>

              {/* Status & Action Buttons */}
              <div className="flex flex-wrap items-center gap-2.5">
                <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
                  <span className="text-slate-500 px-2">Status:</span>
                  {['NEW', 'INVESTIGATING', 'CONTAINED', 'CLOSED'].map((st) => (
                    <button
                      key={st}
                      onClick={() => handleStatusChange(st)}
                      className={`px-2.5 py-1 rounded text-xs font-mono transition-all ${
                        incident.status === st 
                          ? 'bg-cyan-600 text-white font-bold' 
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>

                {/* AI Investigation Trigger */}
                <button
                  onClick={handleRunAI}
                  disabled={aiRunning}
                  className="px-3.5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold flex items-center gap-1.5 shadow-lg shadow-cyan-500/20 disabled:opacity-50 transition-all"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${aiRunning ? 'animate-spin' : ''}`} />
                  <span>{aiRunning ? 'AI Investigating...' : 'Run AI Investigation'}</span>
                </button>

                {/* Export Report Button */}
                <button
                  onClick={() => setShowReportModal(true)}
                  className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors"
                >
                  <FileText className="w-3.5 h-3.5 text-amber-400" />
                  <span>Export Report</span>
                </button>
              </div>
            </div>
          </div>

          {/* AI Forensic Analysis & Blast Radius Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  Autonomous AI Forensic Reasoning
                </h3>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                  AI Confidence: {incident.ai_confidence || 90}%
                </span>
              </div>

              <div>
                <h4 className="text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                  Executive Briefing
                </h4>
                <p className="text-xs font-mono text-slate-300 leading-relaxed bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
                  {incident.summary || 'Awaiting initial forensic synthesis.'}
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs font-mono font-semibold text-amber-400 uppercase tracking-wider mb-1">
                    Root Cause Hypothesis
                  </h4>
                  <p className="text-xs font-mono text-slate-300 leading-relaxed bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 h-full">
                    {incident.root_cause || 'Analyzing initial entry vector and boundary credentials.'}
                  </p>
                </div>

                <div>
                  <h4 className="text-xs font-mono font-semibold text-rose-400 uppercase tracking-wider mb-1">
                    Perimeter & Blast Radius
                  </h4>
                  <p className="text-xs font-mono text-slate-300 leading-relaxed bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 h-full">
                    {incident.blast_radius || 'Scoping compromised subnets and directory accounts.'}
                  </p>
                </div>
              </div>
            </div>

            {/* Entity Blast Radius Visualization Card */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2 mb-3">
                  <Share2 className="w-4 h-4 text-purple-400" />
                  Entity Blast Radius & Assets
                </h3>
                
                <div className="space-y-2.5">
                  {(incident.affected_assets || []).map((asset, idx) => {
                    const isAttacker = asset.type === 'IP_ATTACKER';
                    const isHost = asset.type === 'HOST';
                    const isUser = asset.type === 'USER';
                    return (
                      <div 
                        key={idx}
                        className={`p-2.5 rounded-lg border flex items-center justify-between text-xs font-mono ${
                          isAttacker 
                            ? 'bg-rose-950/30 border-rose-500/40 text-rose-300' 
                            : isHost 
                            ? 'bg-cyan-950/30 border-cyan-500/40 text-cyan-300' 
                            : 'bg-amber-950/30 border-amber-500/40 text-amber-300'
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          {isAttacker ? <Globe className="w-4 h-4 flex-shrink-0" /> : isHost ? <Server className="w-4 h-4 flex-shrink-0" /> : <User className="w-4 h-4 flex-shrink-0" />}
                          <span className="font-semibold truncate">{asset.value}</span>
                        </div>
                        <span className="text-[10px] uppercase font-bold text-slate-400">{asset.type}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-400">
                <span>Threat Score: </span>
                <strong className="text-amber-400 text-sm">{incident.threat_score}/100</strong>
              </div>
            </div>
          </div>

          {/* Attack Timeline & Chronology */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl">
            <h3 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2 mb-4">
              <Clock className="w-4 h-4 text-cyan-400" />
              Attack Progression Timeline
            </h3>

            <div className="space-y-4">
              {(incident.timeline || []).map((event, idx) => {
                const isCrit = event.severity === 'CRITICAL';
                const isHigh = event.severity === 'HIGH';
                return (
                  <div key={idx} className="relative pl-6 pb-2 border-l-2 border-cyan-500/40 last:border-l-0">
                    <div className="absolute -left-1.5 top-0 w-3 h-3 rounded-full bg-cyan-400 ring-4 ring-slate-900" />
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono">
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                        <span className="text-cyan-400 font-bold">
                          {event.timestamp?.replace('T', ' ').substring(11, 19)} UTC • [{event.stage}]
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isCrit ? 'bg-rose-950 text-rose-300' : isHigh ? 'bg-amber-950 text-amber-300' : 'bg-slate-800 text-slate-300'
                        }`}>
                          {event.severity}
                        </span>
                      </div>
                      <h4 className="font-bold text-slate-200">{event.title}</h4>
                      <p className="text-slate-400 mt-0.5">{event.description}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Containment Playbook (Interactive PICERL Checklist) */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl">
            <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
                  <CheckSquare className="w-4 h-4 text-emerald-400" />
                  Incident Remediation Playbook (PICERL Action Plan)
                </h3>
                <p className="text-xs font-mono text-slate-400">
                  Standard Operating Procedures dynamically tailored for this intrusion vector. Click to track execution.
                </p>
              </div>

              <span className="text-xs font-mono text-slate-400">
                Completed: <strong className="text-emerald-400">{(incident.playbook || []).filter(p => p.completed).length}</strong> / {(incident.playbook || []).length}
              </span>
            </div>

            <div className="space-y-2.5">
              {(incident.playbook || []).map((step, idx) => (
                <div 
                  key={idx}
                  onClick={() => handlePlaybookToggle(idx, step.completed)}
                  className={`p-3 rounded-lg border transition-all cursor-pointer flex items-center justify-between gap-3 ${
                    step.completed 
                      ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300' 
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    {step.completed ? (
                      <CheckSquare className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <Square className="w-5 h-5 text-slate-500 flex-shrink-0" />
                    )}
                    <span className={`text-xs font-mono ${step.completed ? 'line-through text-slate-400' : 'text-slate-200 font-medium'}`}>
                      {step.action}
                    </span>
                  </div>

                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 uppercase font-semibold">
                    {step.category || 'Remediation'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Report Modal */}
      {showReportModal && (
        <ReportModal 
          incidentId={selectedIncidentId} 
          onClose={() => setShowReportModal(false)} 
        />
      )}
    </div>
  );
}
