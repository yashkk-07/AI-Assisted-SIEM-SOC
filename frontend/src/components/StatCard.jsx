import React from 'react';

export default function StatCard({ title, value, subtext, icon: Icon, color = 'cyan', highlight = false }) {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/30',
      bg: 'bg-cyan-950/20',
      text: 'text-cyan-400',
      glow: 'glow-cyan'
    },
    emerald: {
      border: 'border-emerald-500/30',
      bg: 'bg-emerald-950/20',
      text: 'text-emerald-400',
      glow: ''
    },
    rose: {
      border: 'border-rose-500/40',
      bg: 'bg-rose-950/25',
      text: 'text-rose-400',
      glow: 'glow-red'
    },
    amber: {
      border: 'border-amber-500/30',
      bg: 'bg-amber-950/20',
      text: 'text-amber-400',
      glow: 'glow-amber'
    },
    purple: {
      border: 'border-purple-500/30',
      bg: 'bg-purple-950/20',
      text: 'text-purple-400',
      glow: ''
    }
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`p-4 rounded-xl bg-slate-900/80 border ${scheme.border} ${scheme.bg} backdrop-blur-sm relative overflow-hidden transition-all duration-300 hover:scale-[1.02] ${highlight ? scheme.glow : ''}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-mono font-medium text-slate-400 tracking-wider uppercase">{title}</p>
          <h3 className={`text-2xl font-black font-mono mt-1 ${scheme.text}`}>{value}</h3>
          {subtext && <p className="text-[11px] font-mono text-slate-400 mt-1 flex items-center gap-1">{subtext}</p>}
        </div>
        {Icon && (
          <div className={`p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 ${scheme.text}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      <div className="absolute -bottom-6 -right-6 w-16 h-16 rounded-full bg-slate-800/10 blur-xl pointer-events-none" />
    </div>
  );
}
