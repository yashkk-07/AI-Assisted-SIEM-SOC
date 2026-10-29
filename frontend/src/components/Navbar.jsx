import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Terminal, 
  Layers, 
  Radio, 
  Cpu, 
  Sliders, 
  Play, 
  Pause, 
  Flame, 
  Sparkles,
  Zap
} from 'lucide-react';
import { triggerScenario, toggleSimulator } from '../services/api';

export default function Navbar({ 
  currentTab, 
  setCurrentTab, 
  simulatorRunning, 
  setSimulatorRunning, 
  onScenarioTriggered,
  onOpenAIChat,
  dedupRate = 0
}) {
  const [triggering, setTriggering] = useState(false);

  const handleTrigger = async (scenarioName) => {
    try {
      setTriggering(true);
      await triggerScenario(scenarioName);
      if (onScenarioTriggered) onScenarioTriggered(scenarioName);
    } catch (err) {
      console.error(err);
    } finally {
      setTriggering(false);
    }
  };

  const handleToggleSimulator = async () => {
    try {
      const nextState = !simulatorRunning;
      await toggleSimulator(nextState);
      setSimulatorRunning(nextState);
    } catch (err) {
      console.error(err);
    }
  };

  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'logs', label: 'Log Explorer', icon: Terminal },
    { id: 'alerts', label: 'Alert Triage & Dedup', icon: Layers },
    { id: 'incidents', label: 'Incident Room', icon: ShieldAlert },
    { id: 'settings', label: 'AI & Detection Rules', icon: Sliders },
  ];

  return (
    <header className="bg-slate-950/90 backdrop-blur-md border-b border-slate-800 sticky top-0 z-40">
      {/* Top Banner: Cyber Header & Quick Scenarios */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setCurrentTab('dashboard')}>
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400 glow-cyan">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-500" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold tracking-wider text-slate-100 text-lg uppercase font-mono">
                Sentinel<span className="text-cyan-400">AI</span>
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                SIEM v1.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block"></span>
              Autonomous Mini-SOC Platform
            </p>
          </div>
        </div>

        {/* Live Attack Simulator Quick Bar */}
        <div className="flex items-center space-x-2 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg shadow-inner">
          <div className="flex items-center space-x-1.5 text-xs text-slate-400 font-mono mr-2 border-r border-slate-800 pr-2.5">
            <Flame className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-300 font-semibold hidden md:inline">Simulate Attack:</span>
          </div>

          <button
            onClick={() => handleTrigger('brute_force_lateral')}
            disabled={triggering}
            title="External Brute Force leading to Internal Lateral Movement"
            className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20 transition-all flex items-center gap-1 disabled:opacity-50"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
            Crimson Pivot
          </button>

          <button
            onClick={() => handleTrigger('web_sqli_exfil')}
            disabled={triggering}
            title="SQL Injection & Data Exfiltration"
            className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20 transition-all flex items-center gap-1 disabled:opacity-50"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
            SQLi & Exfil
          </button>

          <button
            onClick={() => handleTrigger('ransomware_inhibit')}
            disabled={triggering}
            title="Ransomware Canary & Shadow Copy Purge"
            className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-purple-500/10 text-purple-300 border border-purple-500/30 hover:bg-purple-500/20 transition-all flex items-center gap-1 disabled:opacity-50"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-purple-500"></span>
            Ransomware
          </button>

          {/* Background Ambient Toggle */}
          <button
            onClick={handleToggleSimulator}
            title={simulatorRunning ? "Pause live ambient telemetry" : "Resume live ambient telemetry"}
            className={`p-1.5 rounded border transition-all ${
              simulatorRunning 
                ? 'bg-emerald-950/60 border-emerald-600/40 text-emerald-400 hover:bg-emerald-900/50' 
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
            }`}
          >
            {simulatorRunning ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* AI Copilot & Status */}
        <div className="flex items-center space-x-3">
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300">
            <span className="text-slate-400">Dedup Rate:</span>
            <span className="text-emerald-400 font-bold">{dedupRate}% suppressed</span>
          </div>

          <button
            onClick={onOpenAIChat}
            className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 text-white text-xs font-mono font-semibold flex items-center gap-1.5 shadow-lg shadow-cyan-500/20 hover:from-cyan-500 hover:to-blue-500 transition-all"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-200 animate-pulse" />
            <span>AI Copilot</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex space-x-1 border-t border-slate-800/80 overflow-x-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentTab(item.id)}
              className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-mono font-medium transition-all border-b-2 whitespace-nowrap ${
                isActive
                  ? 'border-cyan-400 text-cyan-300 bg-cyan-950/30'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
}
