import React, { useState, useEffect } from 'react';
import { Sliders, Key, Cpu, ShieldCheck, Check, Save } from 'lucide-react';
import { fetchAISettings, updateAISettings } from '../services/api';

export default function SettingsView() {
  const [aiMode, setAiMode] = useState('hybrid');
  const [geminiKey, setGeminiKey] = useState('');
  const [openaiKey, setOpenaiKey] = useState('');
  const [activeProvider, setActiveProvider] = useState('');
  const [hasGemini, setHasGemini] = useState(false);
  const [hasOpenai, setHasOpenai] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const res = await fetchAISettings();
      setAiMode(res.ai_mode || 'hybrid');
      setActiveProvider(res.active_provider || 'Built-in Expert Engine');
      setHasGemini(res.has_gemini_key);
      setHasOpenai(res.has_openai_key);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    try {
      const payload = { ai_mode: aiMode };
      if (geminiKey) payload.gemini_api_key = geminiKey;
      if (openaiKey) payload.openai_api_key = openaiKey;

      await updateAISettings(payload);
      setSavedSuccess(true);
      setGeminiKey('');
      setOpenaiKey('');
      loadSettings();
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch (err) {
      console.error(err);
    }
  };

  const rules = [
    { id: "RULE_BRUTE_FORCE", name: "Brute Force Authentication", tactic: "Credential Access (T1110)", threshold: ">= 5 failures", window: "60s", sev: "HIGH" },
    { id: "RULE_ACCOUNT_TAKEOVER", name: "Account Compromise Indicator", tactic: "Initial Access (T1078)", threshold: "1 success after fails", window: "180s", sev: "CRITICAL" },
    { id: "RULE_SUSPICIOUS_POWERSHELL", name: "Obfuscated PowerShell Execution", tactic: "Execution (T1059.001)", threshold: "Encoded / bypass flags", window: "10s", sev: "HIGH" },
    { id: "RULE_WEB_EXPLOIT", name: "Web Application SQLi / LFI Attack", tactic: "Initial Access (T1190)", threshold: "SQL injection patterns", window: "30s", sev: "HIGH" },
    { id: "RULE_LATERAL_MOVEMENT", name: "Internal Lateral Movement", tactic: "Lateral Movement (T1021)", threshold: "Cross-subnet remote service", window: "60s", sev: "HIGH" },
    { id: "RULE_RANSOMWARE_RECOVERY", name: "Ransomware Inhibit Recovery", tactic: "Impact (T1490)", threshold: "vssadmin delete shadows", window: "10s", sev: "CRITICAL" },
    { id: "RULE_EXFILTRATION", name: "High Volume Data Exfiltration", tactic: "Exfiltration (T1048)", threshold: "Anomalous egress burst", window: "60s", sev: "CRITICAL" },
  ];

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex items-center justify-between">
        <div>
          <h2 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            AI Reasoning Engine & Detection Logic Settings
          </h2>
          <p className="text-xs font-mono text-slate-400">
            Configure generative LLM integration, offline heuristic fallbacks, and inspect active correlation rules.
          </p>
        </div>

        <span className="text-xs font-mono px-3 py-1 rounded bg-slate-950 border border-slate-800 text-cyan-300">
          Provider: <strong>{activeProvider}</strong>
        </span>
      </div>

      {/* AI Settings Form */}
      <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl">
        <form onSubmit={handleSave} className="space-y-5">
          <div>
            <label className="text-xs font-mono text-slate-300 font-bold block mb-2">
              AI SOC Analyst Operational Mode
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                { id: 'hybrid', label: 'Hybrid (Recommended)', desc: 'Zero-setup offline expert engine + Gemini API acceleration if key provided' },
                { id: 'local', label: 'Local Only', desc: '100% deterministic cybersecurity rules and heuristic reasoning with zero external network calls' },
                { id: 'gemini', label: 'Gemini Generative API', desc: 'Strictly route incident reasoning and analyst chat through Google Gemini 2.0 Flash' },
              ].map((m) => (
                <div
                  key={m.id}
                  onClick={() => setAiMode(m.id)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    aiMode === m.id
                      ? 'bg-cyan-950/40 border-cyan-500 text-cyan-200 shadow-lg shadow-cyan-500/10'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <p className="text-xs font-mono font-bold text-slate-200">{m.label}</p>
                  <p className="text-[11px] font-mono text-slate-400 mt-1">{m.desc}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div>
              <label className="text-xs font-mono text-slate-300 block mb-1 flex items-center justify-between">
                <span>Google Gemini API Key (Optional)</span>
                {hasGemini && <span className="text-emerald-400 text-[10px]">✓ Configured</span>}
              </label>
              <input
                type="password"
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                placeholder={hasGemini ? "••••••••••••••••••••••••" : "Paste AIzaSy... key"}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-xs font-mono text-slate-300 block mb-1 flex items-center justify-between">
                <span>OpenAI API Key (Optional)</span>
                {hasOpenai && <span className="text-emerald-400 text-[10px]">✓ Configured</span>}
              </label>
              <input
                type="password"
                value={openaiKey}
                onChange={(e) => setOpenaiKey(e.target.value)}
                placeholder={hasOpenai ? "••••••••••••••••••••••••" : "Paste sk-... key"}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {savedSuccess && (
            <div className="p-3 rounded bg-emerald-950/70 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-400" />
              Settings updated successfully!
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold flex items-center gap-2 transition-colors shadow-lg shadow-cyan-600/20"
            >
              <Save className="w-4 h-4" />
              <span>Save Settings</span>
            </button>
          </div>
        </form>
      </div>

      {/* Active Correlation Detection Rules */}
      <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Active Correlation Rules ({rules.length})
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Sliding Window & Sequence Tracking</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-4">Rule Name</th>
                <th className="py-2.5 px-4">MITRE Technique</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Condition Threshold</th>
                <th className="py-2.5 px-4">Window</th>
                <th className="py-2.5 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {rules.map((r) => (
                <tr key={r.id} className="hover:bg-slate-950/50">
                  <td className="py-2.5 px-4 font-semibold text-slate-200">{r.name}</td>
                  <td className="py-2.5 px-4 text-slate-300">{r.tactic}</td>
                  <td className="py-2.5 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      r.sev === 'CRITICAL' ? 'bg-rose-950 text-rose-300' : 'bg-amber-950 text-amber-300'
                    }`}>
                      {r.sev}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-400">{r.threshold}</td>
                  <td className="py-2.5 px-4 text-slate-400">{r.window}</td>
                  <td className="py-2.5 px-4 text-right">
                    <span className="text-emerald-400 text-[11px] font-bold">ACTIVE</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
