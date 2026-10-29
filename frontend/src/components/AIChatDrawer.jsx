import React, { useState, useRef, useEffect } from 'react';
import { Sparkles, Send, X, Bot, User, ShieldAlert, Cpu } from 'lucide-react';
import { askAIChat } from '../services/api';

export default function AIChatDrawer({ isOpen, onClose, incidentId = null }) {
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: "Hello, Analyst! I'm SentinelAI, your autonomous Tier-3 SOC Incident Commander. Ask me anything about active incidents, MITRE ATT&CK techniques, host isolation steps, or firewall containment rules."
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  const handleSend = async (queryText) => {
    const textToSend = queryText || input;
    if (!textToSend.trim()) return;

    const userMsg = { sender: 'user', text: textToSend };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await askAIChat(textToSend, incidentId);
      const aiReply = { sender: 'ai', text: res.response || "No response generated." };
      setMessages(prev => [...prev, aiReply]);
    } catch (err) {
      setMessages(prev => [...prev, { sender: 'ai', text: "Error connecting to AI SOC analyst engine." }]);
    } finally {
      setLoading(false);
    }
  };

  const quickPrompts = [
    "What should be our immediate containment step?",
    "Show me the attacker origin and blast radius",
    "Draft firewall drop rule for the malicious IP",
    "Explain the MITRE ATT&CK techniques identified"
  ];

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md bg-slate-900 border-l border-slate-700 shadow-2xl flex flex-col">
      {/* Header */}
      <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400">
            <Sparkles className="w-4 h-4 text-cyan-400 animate-pulse" />
          </div>
          <div>
            <h3 className="text-xs font-mono font-bold text-slate-100 flex items-center gap-1.5">
              <span>SentinelAI Copilot</span>
              {incidentId && <span className="text-cyan-400">[{incidentId}]</span>}
            </h3>
            <p className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              Autonomous SOC Reasoning Active
            </p>
          </div>
        </div>

        <button 
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Messages Feed */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
        {messages.map((m, idx) => (
          <div 
            key={idx}
            className={`flex items-start gap-2.5 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {m.sender === 'ai' && (
              <div className="p-1.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 mt-0.5 flex-shrink-0">
                <Bot className="w-3.5 h-3.5" />
              </div>
            )}
            
            <div className={`p-3 rounded-xl max-w-[85%] leading-relaxed ${
              m.sender === 'user' 
                ? 'bg-cyan-600 text-white rounded-tr-none' 
                : 'bg-slate-950 border border-slate-800 text-slate-200 rounded-tl-none whitespace-pre-wrap'
            }`}>
              {m.text}
            </div>

            {m.sender === 'user' && (
              <div className="p-1.5 rounded bg-slate-800 text-slate-300 mt-0.5 flex-shrink-0">
                <User className="w-3.5 h-3.5" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-slate-400 text-xs py-2">
            <Cpu className="w-4 h-4 text-cyan-400 animate-spin" />
            <span>Analyzing security context...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Suggestions */}
      <div className="p-2.5 bg-slate-950 border-t border-slate-800/80 flex flex-wrap gap-1.5">
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(p)}
            className="text-[10px] font-mono px-2 py-1 rounded bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-300 hover:text-cyan-300 transition-colors truncate max-w-full"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <form onSubmit={(e) => { e.preventDefault(); handleSend(); }} className="p-3 bg-slate-950 border-t border-slate-800 flex items-center gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask AI SOC Assistant..."
          className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50 transition-colors"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
}
