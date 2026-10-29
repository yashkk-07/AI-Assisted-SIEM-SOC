import React, { useState, useEffect } from 'react';
import { FileText, Copy, Printer, Check, X, Download, Code } from 'lucide-react';
import { fetchIncidentReport } from '../services/api';

export default function ReportModal({ incidentId, onClose }) {
  const [format, setFormat] = useState('html');
  const [reportContent, setReportContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (incidentId) {
      loadReport(format);
    }
  }, [incidentId, format]);

  const loadReport = async (fmt) => {
    try {
      setLoading(true);
      const text = await fetchIncidentReport(incidentId, fmt);
      setReportContent(text);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(reportContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

  const handlePrint = () => {
    const printWindow = window.open('', '_blank');
    printWindow.document.write(reportContent);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 250);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-4xl w-full h-[88vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header Bar */}
        <div className="px-6 py-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/40">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-mono font-bold text-slate-100">
                Incident Response Investigation Report: {incidentId}
              </h3>
              <p className="text-[11px] font-mono text-slate-400">
                NIST SP 800-61 Computer Security Incident Handling Guide Standard
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Format Switcher */}
            <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-mono">
              <button
                onClick={() => setFormat('html')}
                className={`px-3 py-1 rounded transition-colors ${
                  format === 'html' ? 'bg-cyan-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                HTML / Printable
              </button>
              <button
                onClick={() => setFormat('markdown')}
                className={`px-3 py-1 rounded transition-colors ${
                  format === 'markdown' ? 'bg-cyan-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Markdown
              </button>
            </div>

            <button
              onClick={handleCopy}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            {format === 'html' && (
              <button
                onClick={handlePrint}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors shadow-lg shadow-emerald-600/20"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print / Save as PDF</span>
              </button>
            )}

            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Viewer */}
        <div className="flex-1 overflow-y-auto p-6 bg-slate-950 font-mono text-xs">
          {loading ? (
            <div className="h-full flex items-center justify-center text-slate-400">
              Generating forensic report...
            </div>
          ) : format === 'html' ? (
            <div className="bg-white text-slate-900 rounded-xl p-6 shadow-inner h-full overflow-y-auto">
              <iframe
                title="Report Preview"
                srcDoc={reportContent}
                className="w-full h-full min-h-[600px] border-none"
              />
            </div>
          ) : (
            <pre className="text-slate-300 whitespace-pre-wrap leading-relaxed bg-slate-900 p-5 rounded-xl border border-slate-800">
              {reportContent}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
