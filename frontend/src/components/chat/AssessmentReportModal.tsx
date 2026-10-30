import React, { useState } from 'react';
import {
  X,
  FileDown,
  Download,
  Copy,
  Check,
} from 'lucide-react';
import type { AssessmentReport } from '../../types/assistant';
import { downloadReportPdf, downloadReportJson } from '../../services/api';
import { MarkdownRenderer } from './MarkdownRenderer';

interface AssessmentReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: AssessmentReport | null;
}

export const AssessmentReportModal: React.FC<AssessmentReportModalProps> = ({
  isOpen,
  onClose,
  report,
}) => {
  if (!isOpen || !report) return null;

  const [copied, setCopied] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [downloadingJson, setDownloadingJson] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(report.markdownContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadMarkdown = () => {
    const blob = new Blob([report.markdownContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `API-Security-Assessment-${report.specTitle.replace(/\s+/g, '-')}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJSON = async () => {
    if (report.backendReportId && report.sessionId) {
      try {
        setDownloadingJson(true);
        const blob = await downloadReportJson(report.sessionId, report.backendReportId);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${report.backendReportId}.json`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      } catch (err) {
        console.warn('Backend JSON export failed, falling back to client JSON:', err);
      } finally {
        setDownloadingJson(false);
      }
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `API-Security-Assessment-${report.specTitle.replace(/\s+/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPDF = async () => {
    if (report.backendReportId && report.sessionId) {
      try {
        setDownloadingPdf(true);
        const blob = await downloadReportPdf(report.sessionId, report.backendReportId);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${report.backendReportId}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      } catch (err) {
        console.warn('Backend PDF export failed, falling back to window.print():', err);
      } finally {
        setDownloadingPdf(false);
      }
    }
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200 text-slate-800">
        
        {/* Header */}
        <div className="h-16 px-6 border-b border-slate-100 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-purple-100 border border-purple-200 flex items-center justify-center text-purple-600 shadow-xs">
              <FileDown className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 font-display">
                Automated Security Assessment Report
              </h3>
              <p className="text-xs font-mono text-slate-500">
                {report.specTitle} • Generated {report.generatedAt}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Executive Summary Metrics Strip in Soft Pastel */}
        <div className="px-6 py-4 bg-slate-50/70 border-b border-slate-100 grid grid-cols-2 sm:grid-cols-4 gap-4 shrink-0 font-mono text-xs">
          <div className="p-3 rounded-xl bg-white border border-slate-200 shadow-xs">
            <div className="text-slate-500 text-[10px] uppercase font-semibold">Cataloged Endpoints</div>
            <div className="text-lg font-bold text-slate-800 mt-0.5">{report.summary.totalEndpoints}</div>
          </div>

          <div className="p-3 rounded-xl bg-white border border-slate-200 shadow-xs">
            <div className="text-slate-500 text-[10px] uppercase font-semibold">Approved Tests</div>
            <div className="text-lg font-bold text-sky-700 mt-0.5">{report.summary.testsExecuted}</div>
          </div>

          <div className="p-3 rounded-xl bg-rose-50/80 border border-rose-200 shadow-xs">
            <div className="text-rose-700 text-[10px] uppercase font-semibold">Confirmed Vulns</div>
            <div className="text-lg font-bold text-rose-700 mt-0.5">{report.summary.confirmedVulnerabilities}</div>
          </div>

          <div className="p-3 rounded-xl bg-white border border-slate-200 shadow-xs">
            <div className="text-slate-500 text-[10px] uppercase font-semibold">Risk Tiers</div>
            <div className="text-xs font-bold text-slate-700 mt-1">
              P1: {report.summary.p1Count} • P2: {report.summary.p2Count} • P3: {report.summary.p3Count}
            </div>
          </div>
        </div>

        {/* Markdown Content Viewer */}
        <div className="flex-1 overflow-y-auto p-6 bg-slate-50/40 select-text">
          <div className="max-w-3xl mx-auto bg-white p-6 rounded-2xl border border-slate-200 shadow-xs">
            <MarkdownRenderer content={report.markdownContent} />
          </div>
        </div>

        {/* Footer Actions */}
        <div className="h-16 px-6 border-t border-slate-100 bg-white flex items-center justify-between shrink-0 shadow-xs">
          <button
            onClick={handleCopy}
            className="px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Markdown'}</span>
          </button>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleDownloadPDF}
              disabled={downloadingPdf}
              className="px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-mono flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <FileDown className="w-3.5 h-3.5 text-rose-600" />
              <span>{downloadingPdf ? 'Exporting PDF...' : 'Download PDF'}</span>
            </button>

            <button
              onClick={handleDownloadJSON}
              disabled={downloadingJson}
              className="px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-mono flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5 text-sky-600" />
              <span>{downloadingJson ? 'Exporting JSON...' : 'Download JSON'}</span>
            </button>

            <button
              onClick={handleDownloadMarkdown}
              className="px-4 py-1.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-bold text-xs font-mono uppercase tracking-wider flex items-center gap-1.5 transition-all shadow-sm"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span>Download Markdown (.md)</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
